"""
Shared data models for the SOC Triage Platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Alert:
    """Normalized security alert returned to the UI and database layer."""

    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    rule: str              # Rule identifier
    source_ip: str
    message: str
    evidence_count: int = 1
    timestamp: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    db_id: int | None = None  # Populated after persistence

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "source_ip": self.source_ip,
            "message": self.message,
            "evidence_count": self.evidence_count,
            "timestamp": self.timestamp,
            "db_id": self.db_id,
            **self.extra,
        }

    @property
    def is_high_risk(self) -> bool:
        return self.severity.upper() in ("HIGH", "CRITICAL")

    @property
    def log_line(self) -> str:
        """Best-effort raw log line for AI triage."""
        return str(
            self.extra.get("raw_line")
            or self.extra.get("path")
            or self.message
        )
