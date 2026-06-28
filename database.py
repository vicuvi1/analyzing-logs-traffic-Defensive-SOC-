"""
SQLite persistence layer — case management and alert history.

Stores ingestions, metrics, and analyst alerts so the dashboard retains
state across application restarts.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from config import DATABASE_PATH
from models import Alert

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    source_type TEXT NOT NULL DEFAULT 'upload',
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingestions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    filename TEXT,
    log_count INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    high_risk_count INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    metrics_json TEXT,
    ingested_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    ingestion_id INTEGER,
    severity TEXT NOT NULL,
    rule TEXT NOT NULL,
    source_ip TEXT,
    message TEXT NOT NULL,
    evidence_count INTEGER DEFAULT 1,
    event_timestamp TEXT,
    extra_json TEXT,
    analyst_status TEXT NOT NULL DEFAULT 'new',
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id),
    FOREIGN KEY (ingestion_id) REFERENCES ingestions(id)
);

CREATE TABLE IF NOT EXISTS ai_triage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL UNIQUE,
    what_happened TEXT NOT NULL,
    next_steps TEXT NOT NULL,
    provider TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_case ON alerts(case_id);
CREATE INDEX IF NOT EXISTS idx_ingestions_case ON ingestions(case_id);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with row factory enabled."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they do not exist."""
    with get_connection() as conn:
        conn.executescript(_SCHEMA)


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def create_case(
    title: str,
    source_type: str = "upload",
    notes: str | None = None,
) -> int:
    """Create a new investigation case and return its ID."""
    now = _utcnow()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO cases (title, status, source_type, notes, created_at, updated_at)
            VALUES (?, 'open', ?, ?, ?, ?)
            """,
            (title, source_type, notes, now, now),
        )
        return int(cur.lastrowid)


def list_cases(limit: int = 50) -> list[dict[str, Any]]:
    """Return recent cases with aggregated alert counts."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT c.*,
                   COUNT(DISTINCT a.id) AS alert_total,
                   SUM(CASE WHEN a.severity IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS high_risk_total,
                   COUNT(DISTINCT i.id) AS ingestion_count
            FROM cases c
            LEFT JOIN alerts a ON a.case_id = c.id
            LEFT JOIN ingestions i ON i.case_id = c.id
            GROUP BY c.id
            ORDER BY c.updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_case(case_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return dict(row) if row else None


def update_case_status(case_id: int, status: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
            (status, _utcnow(), case_id),
        )


# ---------------------------------------------------------------------------
# Ingestions & alerts
# ---------------------------------------------------------------------------

def save_ingestion(
    case_id: int,
    filename: str | None,
    summary: dict[str, Any],
    alerts: list[Alert],
) -> tuple[int, list[Alert]]:
    """
    Persist an ingestion event and its alerts.

    Returns (ingestion_id, alerts with db_id populated).
    """
    now = _utcnow()
    metrics = {
        "total_logs": summary.get("total_logs", 0),
        "high_risk_alert_count": summary.get("high_risk_alert_count", 0),
        "total_alert_count": summary.get("total_alert_count", 0),
        "unique_source_ips": summary.get("unique_source_ips", 0),
    }

    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO ingestions
                (case_id, filename, log_count, alert_count, high_risk_count,
                 unique_ips, metrics_json, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                filename,
                metrics["total_logs"],
                metrics["total_alert_count"],
                metrics["high_risk_alert_count"],
                metrics["unique_source_ips"],
                json.dumps(metrics),
                now,
            ),
        )
        ingestion_id = int(cur.lastrowid)

        persisted: list[Alert] = []
        for alert in alerts:
            extra = {k: v for k, v in alert.extra.items()}
            acur = conn.execute(
                """
                INSERT INTO alerts
                    (case_id, ingestion_id, severity, rule, source_ip, message,
                     evidence_count, event_timestamp, extra_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    ingestion_id,
                    alert.severity,
                    alert.rule,
                    alert.source_ip,
                    alert.message,
                    alert.evidence_count,
                    alert.timestamp,
                    json.dumps(extra),
                    now,
                ),
            )
            alert.db_id = int(acur.lastrowid)
            persisted.append(alert)

        conn.execute(
            "UPDATE cases SET updated_at = ? WHERE id = ?",
            (now, case_id),
        )

    return ingestion_id, persisted


def get_case_alerts(case_id: int) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT a.*, t.what_happened, t.next_steps, t.provider AS ai_provider
            FROM alerts a
            LEFT JOIN ai_triage t ON t.alert_id = a.id
            WHERE a.case_id = ?
            ORDER BY a.created_at DESC
            """,
            (case_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_case_ingestions(case_id: int) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM ingestions WHERE case_id = ? ORDER BY ingested_at DESC",
            (case_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def update_alert_status(alert_id: int, status: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE alerts SET analyst_status = ? WHERE id = ?",
            (status, alert_id),
        )


def get_platform_stats() -> dict[str, Any]:
    """Aggregate KPIs across all persisted cases."""
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(DISTINCT c.id) AS total_cases,
                COUNT(DISTINCT a.id) AS total_alerts,
                SUM(CASE WHEN a.severity IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS high_risk_alerts,
                COUNT(DISTINCT i.id) AS total_ingestions
            FROM cases c
            LEFT JOIN alerts a ON a.case_id = c.id
            LEFT JOIN ingestions i ON i.case_id = c.id
            """
        ).fetchone()
    return dict(row) if row else {}


# ---------------------------------------------------------------------------
# AI triage cache
# ---------------------------------------------------------------------------

def save_ai_triage(
    alert_id: int,
    what_happened: str,
    next_steps: str,
    provider: str,
) -> None:
    now = _utcnow()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO ai_triage (alert_id, what_happened, next_steps, provider, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                what_happened = excluded.what_happened,
                next_steps = excluded.next_steps,
                provider = excluded.provider,
                created_at = excluded.created_at
            """,
            (alert_id, what_happened, next_steps, provider, now),
        )


def get_ai_triage(alert_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM ai_triage WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
    return dict(row) if row else None


# Initialize schema on import.
init_db()
