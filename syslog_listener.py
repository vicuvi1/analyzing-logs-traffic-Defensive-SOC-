"""
Live Syslog UDP Listener — SIEM log forwarding integration.

Listens on a configurable UDP port (default 514) for incoming syslog
datagrams from remote servers, parses them in a background thread, and
buffers normalized records for the Streamlit dashboard to consume.

Usage:
    listener = get_syslog_listener()
    listener.start()
    records = listener.get_records_snapshot()
"""

from __future__ import annotations

import socket
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from config import (
    SYSLOG_BUFFER_MAX,
    SYSLOG_LISTEN_HOST,
    SYSLOG_LISTEN_PORT,
    SYSLOG_SOCKET_TIMEOUT,
)
from parser import parse_live_syslog_datagram


@dataclass
class SyslogStats:
    """Runtime statistics for the live listener."""

    datagrams_received: int = 0
    records_parsed: int = 0
    parse_errors: int = 0
    started_at: datetime | None = None
    last_received_at: datetime | None = None
    bind_error: str | None = None
    unique_senders: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "datagrams_received": self.datagrams_received,
            "records_parsed": self.records_parsed,
            "parse_errors": self.parse_errors,
            "unique_senders": len(self.unique_senders),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "last_received_at": (
                self.last_received_at.isoformat() if self.last_received_at else None
            ),
            "bind_error": self.bind_error,
        }


class SyslogListener:
    """
    Thread-safe UDP syslog receiver.

    Binds to SYSLOG_LISTEN_HOST:SYSLOG_LISTEN_PORT and stores parsed
    records in a bounded deque (oldest entries drop when full).
    """

    MAX_DATAGRAM_BYTES = 65_535

    def __init__(
        self,
        host: str = SYSLOG_LISTEN_HOST,
        port: int = SYSLOG_LISTEN_PORT,
        max_buffer: int = SYSLOG_BUFFER_MAX,
    ) -> None:
        self.host = host
        self.port = port
        self.max_buffer = max_buffer

        self._records: deque[dict] = deque(maxlen=max_buffer)
        self._raw_feed: deque[dict] = deque(maxlen=200)  # live tail for UI
        self._lock = threading.Lock()
        self._stats = SyslogStats()

        self._running = False
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None
        self._bind_event = threading.Event()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> SyslogStats:
        with self._lock:
            return self._stats

    def start(self, host: str | None = None, port: int | None = None) -> str | None:
        """
        Start the background listener thread.

        Returns an error message if the socket cannot bind, else None.
        """
        if self._running:
            return None

        if host is not None:
            self.host = host
        if port is not None:
            self.port = port

        self._stats = SyslogStats()
        self._bind_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._listen_loop,
            name=f"syslog-udp-{self.port}",
            daemon=True,
        )
        self._thread.start()

        if not self._bind_event.wait(timeout=3.0):
            self.stop()
            return "Listener failed to start within 3 seconds."
        return self._stats.bind_error

    def stop(self) -> None:
        """Stop the listener and release the socket."""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

    def clear(self) -> None:
        """Flush buffered records (e.g. when analyst resets the live session)."""
        with self._lock:
            self._records.clear()
            self._raw_feed.clear()
            self._stats = SyslogStats(
                bind_error=self._stats.bind_error,
            )

    def get_records_snapshot(self) -> list[dict]:
        """Return a copy of all buffered parsed records."""
        with self._lock:
            return list(self._records)

    def get_raw_feed(self, limit: int = 50) -> list[dict]:
        """Return the most recent raw datagrams for the live tail widget."""
        with self._lock:
            items = list(self._raw_feed)
        return items[-limit:]

    def record_count(self) -> int:
        with self._lock:
            return len(self._records)

    def _listen_loop(self) -> None:
        """Background thread: bind UDP socket and process datagrams."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket = sock

        try:
            sock.bind((self.host, self.port))
        except OSError as exc:
            with self._lock:
                self._stats.bind_error = (
                    f"Cannot bind {self.host}:{self.port} — {exc}. "
                    f"Port 514 requires administrator/root privileges. "
                    f"Try port 5514 in the sidebar or set SYSLOG_LISTEN_PORT=5514 in .env."
                )
            self._running = False
            self._bind_event.set()
            return

        sock.settimeout(SYSLOG_SOCKET_TIMEOUT)

        with self._lock:
            self._stats.started_at = datetime.now(timezone.utc)
            self._stats.bind_error = None
        self._bind_event.set()

        while self._running:
            try:
                data, addr = sock.recvfrom(self.MAX_DATAGRAM_BYTES)
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    break
                continue

            self._handle_datagram(data, addr[0])

    def _handle_datagram(self, data: bytes, sender_ip: str) -> None:
        """Decode, parse, and buffer a single syslog datagram."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        try:
            message = data.decode("utf-8", errors="replace").strip()
        except Exception:
            with self._lock:
                self._stats.parse_errors += 1
            return

        if not message:
            return

        record = parse_live_syslog_datagram(message, sender_ip=sender_ip, received_at=now)

        with self._lock:
            self._stats.datagrams_received += 1
            self._stats.last_received_at = now
            self._stats.unique_senders.add(sender_ip)

            self._raw_feed.append({
                "received_at": now.isoformat(),
                "sender_ip": sender_ip,
                "message": message[:500],
            })

            if record:
                self._records.append(record)
                self._stats.records_parsed += 1
            else:
                self._stats.parse_errors += 1


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_listener: SyslogListener | None = None


def get_syslog_listener() -> SyslogListener:
    """Return the shared SyslogListener instance."""
    global _listener
    if _listener is None:
        _listener = SyslogListener()
    return _listener
