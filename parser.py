"""
Log and packet-capture parsing module.

Normalizes Apache, Nginx, Syslog, and PCAP/PCAPNG inputs into a unified
pandas DataFrame for downstream analysis.
"""

from __future__ import annotations

import io
import re
from datetime import datetime
from typing import BinaryIO, TextIO

import pandas as pd

# Scapy is optional at import time; we validate PCAP support lazily.
try:
    from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Regex patterns for common log formats
# ---------------------------------------------------------------------------

# Apache / Nginx combined log format (most common).
COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>[\d.]+|[\da-fA-F:]+)\s+'           # client IP
    r'\S+\s+\S+\s+'                               # ident / authuser
    r'\[(?P<timestamp>[^\]]+)\]\s+'               # [timestamp]
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]*)\s+[^"]*"\s+'  # request line
    r'(?P<status>\d{3})\s+'                       # status code
    r'(?P<size>\S+)',                              # response size
    re.MULTILINE,
)

# Fallback: extract any HTTP status near a quoted request line.
HTTP_FALLBACK_RE = re.compile(
    r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<path>[^\s"]+)[^"]*"\s+'
    r'(?P<status>\d{3})'
)

# Syslog: capture timestamp prefix + source IP when present.
SYSLOG_IP_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<message>.+)$'
)
# RFC5424 structured syslog (basic header extraction).
RFC5424_RE = re.compile(
    r'^<\d+>(?P<version>\d)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>\S+)\s+'
    r'(?P<pid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<structured>[^\s]+|-)\s+'
    r'(?P<message>.*)$'
)

# Strip leading PRI facility/severity prefix: <34> or <34>1
SYSLOG_PRI_RE = re.compile(r'^<\d+>(?:\d\s*)?')

SYSLOG_FROM_IP_RE = re.compile(
    r'from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE,
)

TIMESTAMP_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # Nginx / Apache with timezone
    "%d/%b/%Y:%H:%M:%S",      # Without timezone
    "%b %d %H:%M:%S",         # Syslog (year injected at parse time)
]


def _parse_timestamp(raw: str, default_year: int | None = None) -> datetime | None:
    """Best-effort timestamp parsing across supported formats."""
    if not raw:
        return None

    cleaned = raw.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            if default_year and dt.year == 1900:
                dt = dt.replace(year=default_year)
            # Normalize to naive datetime for consistent downstream handling.
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    return None


def _empty_record() -> dict:
    return {
        "timestamp": None,
        "source_ip": None,
        "dest_ip": None,
        "dest_port": None,
        "status_code": None,
        "request_path": None,
        "method": None,
        "log_type": None,
        "raw_line": None,
    }


def _records_to_dataframe(records: list[dict]) -> pd.DataFrame:
    """Convert parsed records to a normalized DataFrame."""
    if not records:
        return pd.DataFrame(columns=list(_empty_record().keys()))

    df = pd.DataFrame(records)
    # Force object dtype — pandas auto-casts datetime → datetime64 which can
    # segfault on boolean indexing in some Windows/pandas builds.
    if "timestamp" in df.columns:
        df["timestamp"] = pd.Series(
            [r.get("timestamp") for r in records],
            dtype=object,
        )
    return df


# ---------------------------------------------------------------------------
# Text log parsers
# ---------------------------------------------------------------------------

def parse_combined_access_log(content: str, log_type: str) -> pd.DataFrame:
    """
    Parse Apache or Nginx combined-format access logs.

    Returns a DataFrame with unified columns used by the analyzer.
    """
    records: list[dict] = []
    current_year = datetime.now().year

    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            match = COMBINED_LOG_RE.match(line)
            if match:
                groups = match.groupdict()
                record = _empty_record()
                record.update({
                    "timestamp": _parse_timestamp(groups["timestamp"], current_year),
                    "source_ip": groups["ip"],
                    "status_code": int(groups["status"]),
                    "request_path": groups["path"],
                    "method": groups["method"],
                    "log_type": log_type,
                    "raw_line": line,
                })
                records.append(record)
                continue

            # Lenient fallback for slightly malformed lines.
            fb = HTTP_FALLBACK_RE.search(line)
            if fb:
                ip_match = re.match(r'^([\d.]+|[\da-fA-F:]+)', line)
                record = _empty_record()
                record.update({
                    "source_ip": ip_match.group(1) if ip_match else None,
                    "status_code": int(fb.group("status")),
                    "request_path": fb.group("path"),
                    "log_type": log_type,
                    "raw_line": line,
                })
                records.append(record)
        except (ValueError, AttributeError):
            # Skip corrupt lines — analyzer should never crash on bad input.
            continue

    return _records_to_dataframe(records)


def parse_syslog(content: str) -> pd.DataFrame:
    """Parse Linux syslog-style text logs."""
    records: list[dict] = []
    current_year = datetime.now().year

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            match = SYSLOG_IP_RE.match(line)
            if not match:
                continue

            groups = match.groupdict()
            ip_match = SYSLOG_FROM_IP_RE.search(groups["message"])

            record = _empty_record()
            record.update({
                "timestamp": _parse_timestamp(groups["ts"], current_year),
                "source_ip": ip_match.group("ip") if ip_match else None,
                "request_path": groups["message"][:200],
                "log_type": "syslog",
                "raw_line": line,
            })
            records.append(record)
        except (ValueError, AttributeError):
            continue

    return _records_to_dataframe(records)


def parse_live_syslog_datagram(
    message: str,
    sender_ip: str | None = None,
    received_at: datetime | None = None,
) -> dict | None:
    """
    Parse a single live syslog datagram into a normalized record.

    Supports RFC3164 (traditional), RFC5424 (structured), embedded Apache
    combined logs, and a raw fallback. The UDP sender IP is used when no
    client IP can be extracted from the message body.
    """
    line = message.strip()
    if not line:
        return None

    current_year = datetime.now().year
    received_at = received_at or datetime.now()

    try:
        # Strip PRI prefix for downstream pattern matching.
        stripped = SYSLOG_PRI_RE.sub("", line, count=1).strip() or line

        # Embedded Apache/Nginx combined log forwarded via syslog.
        if COMBINED_LOG_RE.match(stripped):
            df = parse_combined_access_log(stripped, "apache")
            if not df.empty:
                rec = df.iloc[0].to_dict()
                rec["log_type"] = "syslog"
                rec["raw_line"] = line
                if rec.get("timestamp") is None:
                    rec["timestamp"] = received_at
                return rec

        # RFC5424 structured syslog.
        rfc5424 = RFC5424_RE.match(line)
        if rfc5424:
            groups = rfc5424.groupdict()
            body = groups["message"]
            ip_match = SYSLOG_FROM_IP_RE.search(body)
            ts_raw = groups["timestamp"]
            ts = None
            if ts_raw and ts_raw != "-":
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if ts.tzinfo:
                        ts = ts.replace(tzinfo=None)
                except ValueError:
                    ts = received_at
            record = _empty_record()
            record.update({
                "timestamp": ts or received_at,
                "source_ip": (
                    ip_match.group("ip") if ip_match
                    else (sender_ip or groups.get("host"))
                ),
                "request_path": body[:200],
                "method": groups.get("app"),
                "log_type": "syslog",
                "raw_line": line,
            })
            return record

        # RFC3164 traditional syslog.
        match = SYSLOG_IP_RE.match(stripped)
        if match:
            groups = match.groupdict()
            ip_match = SYSLOG_FROM_IP_RE.search(groups["message"])
            record = _empty_record()
            record.update({
                "timestamp": _parse_timestamp(groups["ts"], current_year) or received_at,
                "source_ip": (
                    ip_match.group("ip") if ip_match else (sender_ip or None)
                ),
                "request_path": groups["message"][:200],
                "log_type": "syslog",
                "raw_line": line,
            })
            return record

        # Raw fallback — preserve the message for keyword/Sigma rules.
        record = _empty_record()
        record.update({
            "timestamp": received_at,
            "source_ip": sender_ip,
            "request_path": stripped[:200],
            "log_type": "syslog",
            "raw_line": line,
        })
        return record

    except (ValueError, AttributeError):
        return None


def records_to_dataframe(records: list[dict]) -> pd.DataFrame:
    """Public wrapper for converting record dicts to a DataFrame."""
    return _records_to_dataframe(records)


def detect_log_type(filename: str, sample: str) -> str:
    """
    Infer log type from filename and content heuristics.

    Returns one of: apache, nginx, syslog, unknown_text
    """
    name = filename.lower()
    if "apache" in name or "access.log" in name:
        return "apache"
    if "nginx" in name:
        return "nginx"
    if "syslog" in name or "auth.log" in name or "messages" in name:
        return "syslog"

    # Content-based hints.
    if SYSLOG_IP_RE.match(sample.splitlines()[0] if sample else ""):
        return "syslog"
    if COMBINED_LOG_RE.match(sample.splitlines()[0] if sample else ""):
        return "apache"  # Apache and Nginx share combined format.

    return "unknown_text"


def parse_text_log(file_obj: TextIO | BinaryIO, filename: str) -> pd.DataFrame:
    """
    Entry point for text-based log files.

    Reads content safely and routes to the appropriate parser.
    """
    try:
        raw = file_obj.read()
        if isinstance(raw, bytes):
            content = raw.decode("utf-8", errors="replace")
        else:
            content = raw
    except Exception as exc:
        raise ValueError(f"Unable to read log file '{filename}': {exc}") from exc

    if not content.strip():
        raise ValueError(f"Log file '{filename}' is empty.")

    log_type = detect_log_type(filename, content[:2000])

    if log_type in ("apache", "nginx", "unknown_text"):
        # Combined format works for Apache/Nginx and many generic web logs.
        resolved_type = log_type if log_type != "unknown_text" else "apache"
        return parse_combined_access_log(content, resolved_type)

    return parse_syslog(content)


# ---------------------------------------------------------------------------
# PCAP parser
# ---------------------------------------------------------------------------

def parse_pcap(file_obj: BinaryIO, filename: str) -> pd.DataFrame:
    """
    Parse PCAP/PCAPNG captures into connection-oriented records.

    Each row represents one IP packet with L3/L4 metadata.
    """
    if not SCAPY_AVAILABLE:
        raise ImportError(
            "scapy is not installed. Run: pip install scapy"
        )

    try:
        raw_bytes = file_obj.read()
        if not raw_bytes:
            raise ValueError(f"PCAP file '{filename}' is empty.")

        # rdpcap accepts a file-like object or bytes via BytesIO.
        packets = rdpcap(io.BytesIO(raw_bytes))
    except Exception as exc:
        raise ValueError(
            f"Failed to parse PCAP '{filename}'. "
            f"The file may be corrupt or unsupported: {exc}"
        ) from exc

    records: list[dict] = []
    for pkt in packets:
        try:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            ts = datetime.fromtimestamp(float(pkt.time))
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            dst_port = None
            method = None

            if pkt.haslayer(TCP):
                dst_port = int(pkt[TCP].dport)
                # Map common TCP flags to a pseudo-status for display.
                flags = pkt[TCP].flags
                method = str(flags)
            elif pkt.haslayer(UDP):
                dst_port = int(pkt[UDP].dport)
                method = "UDP"

            record = _empty_record()
            record.update({
                "timestamp": ts,
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "request_path": f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                "method": method,
                "log_type": "pcap",
                "raw_line": pkt.summary(),
            })
            records.append(record)
        except Exception:
            # Skip individual malformed packets.
            continue

    if not records:
        raise ValueError(
            f"No parseable IP packets found in '{filename}'."
        )

    return _records_to_dataframe(records)


def parse_uploaded_file(
    file_bytes: bytes,
    filename: str,
) -> tuple[pd.DataFrame, str]:
    """
    Unified upload handler.

    Returns (DataFrame, detected_format_label).
    """
    name_lower = filename.lower()
    buffer = io.BytesIO(file_bytes)

    if name_lower.endswith((".pcap", ".pcapng")):
        df = parse_pcap(buffer, filename)
        return df, "pcap"

    # Text logs — decode as UTF-8 with replacement for invalid bytes.
    text_buffer = io.StringIO(file_bytes.decode("utf-8", errors="replace"))
    df = parse_text_log(text_buffer, filename)
    log_type = df["log_type"].iloc[0] if not df.empty else "text"
    return df, str(log_type)
