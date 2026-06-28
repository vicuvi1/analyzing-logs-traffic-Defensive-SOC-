"""
Sigma Rule Engine — YAML-based detection signature evaluator.

Sigma is the industry-standard format for portable log detection rules
(similar to YARA, but for logs). This module loads .yml rule files from
the /rules directory and evaluates them against normalized log DataFrames.

Supported Sigma features (subset):
  - logsource filtering (category, product, service)
  - field modifiers: contains, re, startswith, endswith, equals
  - keyword selections (plain string lists)
  - conditions: single selection, AND, OR, 1 of selection*, all of selection*

Field names in rules are mapped to our normalized schema (request_path,
source_ip, status_code, raw_line, etc.).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from config import SIGMA_RULES_DIR

# ---------------------------------------------------------------------------
# Sigma field → normalized DataFrame column mapping
# ---------------------------------------------------------------------------

FIELD_MAP: dict[str, str] = {
    # HTTP / web server fields
    "request_path": "request_path",
    "uri": "request_path",
    "cs-uri": "request_path",
    "url": "request_path",
    "c-uri": "request_path",
    "cs-uri-stem": "request_path",
    "cs-uri-query": "request_path",
    # Client / source
    "source_ip": "source_ip",
    "src_ip": "source_ip",
    "c-ip": "source_ip",
    "clientip": "source_ip",
    "client_ip": "source_ip",
    # HTTP status
    "status_code": "status_code",
    "sc-status": "status_code",
    "status": "status_code",
    "http_status": "status_code",
    # Network / PCAP
    "dest_ip": "dest_ip",
    "dest_port": "dest_port",
    "dport": "dest_port",
    "destinationport": "dest_port",
    # Syslog / generic
    "message": "request_path",
    "msg": "request_path",
    "raw_line": "raw_line",
    "method": "method",
    "log_type": "log_type",
}

# Text columns searched for keyword-only selections.
_KEYWORD_SEARCH_COLUMNS = ("request_path", "raw_line", "method", "source_ip")

# Sigma level → alert severity
_LEVEL_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "LOW",
}

# logsource product/service → our log_type values
_LOGSOURCE_MAP: dict[str, set[str]] = {
    "apache": {"apache"},
    "nginx": {"nginx"},
    "webserver": {"apache", "nginx"},
    "syslog": {"syslog"},
    "linux": {"syslog"},
    "pcap": {"pcap"},
}


@dataclass
class ThresholdRule:
    """YAML threshold rule for sliding-window aggregations."""

    title: str
    rule_id: str
    level: str
    description: str
    logsource: dict[str, Any]
    threshold: dict[str, Any]
    filepath: Path
    tags: list[str] = field(default_factory=list)

    @property
    def slug(self) -> str:
        return self.filepath.stem

    @property
    def severity(self) -> str:
        return _LEVEL_MAP.get(self.level.lower(), "MEDIUM")


@dataclass
class SigmaRule:
    """Parsed Sigma rule ready for evaluation."""

    title: str
    rule_id: str
    level: str
    description: str
    logsource: dict[str, Any]
    detection: dict[str, Any]
    condition: str
    filepath: Path
    tags: list[str] = field(default_factory=list)

    @property
    def slug(self) -> str:
        return self.filepath.stem

    @property
    def severity(self) -> str:
        return _LEVEL_MAP.get(self.level.lower(), "MEDIUM")


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def _parse_sigma_rule(path: Path, raw: dict) -> SigmaRule | None:
    """Parse a Sigma-style signature rule."""
    detection = raw.get("detection")
    if not isinstance(detection, dict):
        return None
    condition = detection.get("condition", "")
    if not condition:
        return None

    return SigmaRule(
        title=raw.get("title", path.stem),
        rule_id=raw.get("id", path.stem),
        level=raw.get("level", "medium"),
        description=raw.get("description", ""),
        logsource=raw.get("logsource", {}),
        detection=detection,
        condition=str(condition),
        filepath=path,
        tags=raw.get("tags", []) or [],
    )


def _parse_threshold_rule(path: Path, raw: dict) -> ThresholdRule | None:
    """Parse a threshold aggregation rule."""
    threshold = raw.get("threshold")
    if not isinstance(threshold, dict):
        return None
    if not threshold.get("group_by"):
        return None
    return ThresholdRule(
        title=raw.get("title", path.stem),
        rule_id=raw.get("id", path.stem),
        level=raw.get("level", "medium"),
        description=raw.get("description", ""),
        logsource=raw.get("logsource", {}),
        threshold=threshold,
        filepath=path,
        tags=raw.get("tags", []) or [],
    )


def _parse_rule_file(path: Path) -> SigmaRule | ThresholdRule | None:
    """Load and validate a single YAML rule file."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        print(f"[rules] Skipping {path.name}: {exc}")
        return None

    if not isinstance(raw, dict):
        return None

    if raw.get("type") == "threshold":
        return _parse_threshold_rule(path, raw)

    if "detection" not in raw:
        print(f"[rules] Skipping {path.name}: missing 'detection' block")
        return None

    return _parse_sigma_rule(path, raw)


def load_rules(rules_dir: Path | None = None) -> tuple[list[SigmaRule], list[ThresholdRule]]:
    """Load all YAML rules from the rules directory."""
    if rules_dir is None:
        rules_dir = SIGMA_RULES_DIR

    sigma_rules: list[SigmaRule] = []
    threshold_rules: list[ThresholdRule] = []

    if not rules_dir.is_dir():
        return sigma_rules, threshold_rules

    for pattern in ("*.yml", "*.yaml"):
        for path in sorted(rules_dir.glob(pattern)):
            parsed = _parse_rule_file(path)
            if isinstance(parsed, SigmaRule):
                sigma_rules.append(parsed)
            elif isinstance(parsed, ThresholdRule):
                threshold_rules.append(parsed)
    return sigma_rules, threshold_rules


def load_sigma_rules(rules_dir: Path | None = None) -> list[SigmaRule]:
    """Backward-compatible loader returning Sigma rules only."""
    sigma, _ = load_rules(rules_dir)
    return sigma


# ---------------------------------------------------------------------------
# Logsource matching
# ---------------------------------------------------------------------------

def _matches_logsource_dict(logsource: dict[str, Any], log_type: str | None) -> bool:
    """Return True if logsource constraints match the record log_type."""
    if not logsource:
        return True
    if log_type is None:
        return True

    product = logsource.get("product")
    category = logsource.get("category")
    service = logsource.get("service")
    allowed: set[str] = set()

    for key in (product, category, service):
        if key is None:
            continue
        if isinstance(key, list):
            for item in key:
                allowed.update(_LOGSOURCE_MAP.get(str(item).lower(), {str(item).lower()}))
        else:
            allowed.update(_LOGSOURCE_MAP.get(str(key).lower(), {str(key).lower()}))

    if not allowed:
        return True
    return log_type.lower() in allowed


def _matches_logsource(rule: SigmaRule, log_type: str | None) -> bool:
    return _matches_logsource_dict(rule.logsource, log_type)


def _matches_threshold_logsource(rule: ThresholdRule, df: pd.DataFrame) -> bool:
    if df.empty:
        return False
    if not rule.logsource:
        return True
    log_types = df["log_type"].dropna().unique() if "log_type" in df.columns else []
    return any(_matches_logsource_dict(rule.logsource, str(lt)) for lt in log_types)


# ---------------------------------------------------------------------------
# Selection evaluation
# ---------------------------------------------------------------------------

def _resolve_column(sigma_field: str) -> str | None:
    """Map a Sigma field name to a DataFrame column."""
    return FIELD_MAP.get(sigma_field.lower(), sigma_field.lower())


def _row_field_value(row: pd.Series, sigma_field: str) -> str:
    """Extract a field value from a DataFrame row."""
    col = _resolve_column(sigma_field)
    if col and col in row.index and pd.notna(row[col]):
        return str(row[col])
    return ""


def _keyword_text(row: pd.Series) -> str:
    """Concatenate searchable text fields for keyword matching."""
    parts = []
    for col in _KEYWORD_SEARCH_COLUMNS:
        if col in row.index and pd.notna(row[col]):
            parts.append(str(row[col]))
    return " ".join(parts).lower()


def _match_modifier(value: str, modifier: str, pattern: Any) -> bool:
    """Apply a Sigma field modifier to a single value."""
    if value is None:
        value = ""
    value_lower = value.lower()

    if modifier == "contains":
        targets = pattern if isinstance(pattern, list) else [pattern]
        return any(str(t).lower() in value_lower for t in targets)

    if modifier == "re":
        patterns = pattern if isinstance(pattern, list) else [pattern]
        return any(re.search(str(p), value, re.IGNORECASE) for p in patterns)

    if modifier == "startswith":
        targets = pattern if isinstance(pattern, list) else [pattern]
        return any(value_lower.startswith(str(t).lower()) for t in targets)

    if modifier == "endswith":
        targets = pattern if isinstance(pattern, list) else [pattern]
        return any(value_lower.endswith(str(t).lower()) for t in targets)

    # Plain equality (no modifier or |equals)
    targets = pattern if isinstance(pattern, list) else [pattern]
    try:
        # Numeric comparison for status codes.
        return any(value == str(t) or (str(value).isdigit() and int(value) == int(t))
                   for t in targets)
    except (ValueError, TypeError):
        return any(value_lower == str(t).lower() for t in targets)


def _parse_field_key(key: str) -> tuple[str, str]:
    """Split 'field|modifier' into (field, modifier)."""
    if "|" in key:
        fld, mod = key.split("|", 1)
        return fld.strip(), mod.strip().lower()
    return key.strip(), "equals"


def _evaluate_selection(selection: Any, row: pd.Series) -> bool:
    """
    Evaluate a single named selection against one log row.

    Selections can be:
      - A dict of field|modifier → value(s)
      - A plain list of keywords (search all text fields)
    """
    if selection is None:
        return False

    # Keyword list selection: ['term1', 'term2', ...]
    if isinstance(selection, list):
        text = _keyword_text(row)
        return any(str(kw).lower() in text for kw in selection)

    if not isinstance(selection, dict):
        return False

    # All field conditions in a selection must match (AND within selection).
    for key, pattern in selection.items():
        fld, modifier = _parse_field_key(key)
        value = _row_field_value(row, fld)
        if not _match_modifier(value, modifier, pattern):
            return False

    return True


def _get_selection_names(detection: dict[str, Any]) -> list[str]:
    """Return all named selections (everything except 'condition')."""
    return [k for k in detection if k != "condition"]


def _evaluate_condition(condition: str, detection: dict[str, Any], results: dict[str, bool]) -> bool:
    """
    Evaluate a Sigma condition expression against selection results.

    Supports:
      - 'selection_name'
      - 'sel_a and sel_b'
      - 'sel_a or sel_b'
      - '1 of selection*'
      - 'all of selection*'
    """
    cond = condition.strip()

    # Wildcard patterns: "1 of selection*" / "all of filter*"
    wildcard = re.match(r"^(1|all)\s+of\s+(\w+)\*$", cond, re.IGNORECASE)
    if wildcard:
        quantifier, prefix = wildcard.group(1).lower(), wildcard.group(2)
        matched_keys = [k for k in results if k.lower().startswith(prefix.lower())]
        if not matched_keys:
            return False
        hits = [results[k] for k in matched_keys]
        return any(hits) if quantifier == "1" else all(hits)

    # Boolean operators (simple left-to-right, no nesting beyond one level).
    if " or " in cond.lower():
        parts = re.split(r"\s+or\s+", cond, flags=re.IGNORECASE)
        return any(results.get(p.strip(), False) for p in parts)

    if " and " in cond.lower():
        parts = re.split(r"\s+and\s+", cond, flags=re.IGNORECASE)
        return all(results.get(p.strip(), False) for p in parts)

    # Single selection reference.
    return results.get(cond, False)


def _evaluate_rule_on_row(rule: SigmaRule, row: pd.Series) -> tuple[bool, list[str]]:
    """
    Test one rule against one row.

    Returns (matched, list_of_matched_selection_names).
    """
    if not _matches_logsource(rule, str(row.get("log_type") or "")):
        return False, []

    results: dict[str, bool] = {}
    matched_names: list[str] = []

    for name in _get_selection_names(rule.detection):
        hit = _evaluate_selection(rule.detection[name], row)
        results[name] = hit
        if hit:
            matched_names.append(name)

    condition_met = _evaluate_condition(rule.condition, rule.detection, results)
    return condition_met, matched_names if condition_met else []


def _evaluate_threshold_rule(rule: ThresholdRule, df: pd.DataFrame) -> list:
    """Evaluate a YAML threshold rule (sliding-window aggregation)."""
    from models import Alert  # noqa: PLC0415

    alerts: list[Alert] = []
    if df.empty or not _matches_threshold_logsource(rule, df):
        return alerts

    th = rule.threshold
    group_by = _resolve_column(str(th.get("group_by", "source_ip"))) or "source_ip"
    window_seconds = int(th.get("window_seconds", 300))
    min_count = int(th.get("min_count", 5))
    count_mode = str(th.get("count_mode", "events"))
    count_field = th.get("count_field")
    filter_field = th.get("filter_field")
    filter_values = th.get("filter_values", [])

    work_df = df.copy()
    if filter_field and filter_values:
        col = _resolve_column(str(filter_field)) or str(filter_field)
        if col in work_df.columns:
            allowed = {str(v) for v in filter_values}
            filtered = [
                row.to_dict() for _, row in work_df.iterrows()
                if str(row.get(col)) in allowed
            ]
            work_df = pd.DataFrame(filtered) if filtered else pd.DataFrame(columns=work_df.columns)

    if work_df.empty or group_by not in work_df.columns:
        return alerts

    timed_df = work_df.dropna(subset=[group_by, "timestamp"])
    if timed_df.empty:
        counts = work_df.dropna(subset=[group_by]).groupby(group_by).size()
        for key, count in counts.items():
            if count >= min_count:
                alerts.append(Alert(
                    severity=rule.severity,
                    rule=f"rule:{rule.slug}",
                    source_ip=str(key),
                    message=f"[{rule.title}] {count} events from {key} (threshold: {min_count})",
                    evidence_count=int(count),
                    extra={"rule_type": "threshold", "tags": rule.tags},
                ))
        return alerts

    timed_df = timed_df.sort_values("timestamp")
    for group_key, group in timed_df.groupby(group_by):
        timestamps = group["timestamp"].tolist()
        values = (
            group[count_field].tolist()
            if count_field and count_field in group.columns
            else [1] * len(timestamps)
        )

        max_metric = 0
        window_start = 0
        for window_end in range(len(timestamps)):
            while (
                (timestamps[window_end] - timestamps[window_start]).total_seconds()
                > window_seconds
            ):
                window_start += 1
            window_vals = values[window_start: window_end + 1]
            metric = (
                len(set(window_vals))
                if count_mode == "unique"
                else len(window_vals)
            )
            max_metric = max(max_metric, metric)

        if max_metric >= min_count:
            alerts.append(Alert(
                severity=rule.severity,
                rule=f"rule:{rule.slug}",
                source_ip=str(group_key),
                message=(
                    f"[{rule.title}] {group_key}: {max_metric} "
                    f"within {window_seconds}s (threshold: {min_count})"
                ),
                evidence_count=max_metric,
                timestamp=str(group["timestamp"].iloc[-1]),
                extra={"rule_type": "threshold", "tags": rule.tags},
            ))

    return alerts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Unified YAML rule engine — Sigma signatures + threshold aggregations.

    All detection logic is driven by files in the /rules directory.
    """

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or SIGMA_RULES_DIR
        self.sigma_rules: list[SigmaRule] = []
        self.threshold_rules: list[ThresholdRule] = []
        self.reload()

    def reload(self) -> int:
        self.sigma_rules, self.threshold_rules = load_rules(self.rules_dir)
        return self.rule_count

    @property
    def rule_count(self) -> int:
        return len(self.sigma_rules) + len(self.threshold_rules)

    @property
    def rules(self) -> list[SigmaRule]:
        """Backward-compatible alias."""
        return self.sigma_rules

    def list_rules(self) -> list[dict[str, str]]:
        items: list[dict[str, str]] = []
        for r in self.sigma_rules:
            items.append({
                "title": r.title,
                "id": r.rule_id,
                "level": r.level,
                "file": r.filepath.name,
                "type": "sigma",
                "tags": ", ".join(r.tags),
            })
        for r in self.threshold_rules:
            items.append({
                "title": r.title,
                "id": r.rule_id,
                "level": r.level,
                "file": r.filepath.name,
                "type": "threshold",
                "tags": ", ".join(r.tags),
            })
        return items

    def run(self, df: pd.DataFrame) -> list:
        from models import Alert  # noqa: PLC0415

        alerts: list[Alert] = []

        # Sigma row-matching rules.
        for rule in self.sigma_rules:
            for _, row in df.iterrows():
                try:
                    matched, selections = _evaluate_rule_on_row(rule, row)
                except Exception:
                    continue
                if not matched:
                    continue

                path = str(row.get("request_path") or "")
                src_ip = str(row.get("source_ip") or "unknown")
                ts = row.get("timestamp")
                ts_str = str(ts) if ts is not None and pd.notna(ts) else None

                alerts.append(Alert(
                    severity=rule.severity,
                    rule=f"sigma:{rule.slug}",
                    source_ip=src_ip,
                    message=(
                        f"[{rule.title}] "
                        f"{path[:100] if path else row.get('raw_line', '')[:100]}"
                    ),
                    evidence_count=len(selections),
                    timestamp=ts_str,
                    extra={
                        "sigma_id": rule.rule_id,
                        "sigma_title": rule.title,
                        "matched_selections": selections,
                        "path": path,
                        "raw_line": str(row.get("raw_line") or ""),
                        "tags": rule.tags,
                    },
                ))

        # Threshold / window aggregation rules.
        for rule in self.threshold_rules:
            try:
                alerts.extend(_evaluate_threshold_rule(rule, df))
            except Exception as exc:
                print(f"[rules] Threshold error in {rule.slug}: {exc}")

        return alerts


# Backward-compatible alias.
SigmaEngine = RuleEngine

_engine: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine


def get_sigma_engine() -> RuleEngine:
    """Backward-compatible alias."""
    return get_rule_engine()
