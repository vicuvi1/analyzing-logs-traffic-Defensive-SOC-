"""
Threat intelligence and anomaly detection engine.

Detection is fully driven by YAML rules in /rules (sigma_engine.py).
This module handles AbuseIPDB enrichment and dashboard aggregation.
"""

from __future__ import annotations

import time
from typing import Any

import pandas as pd
import requests

from config import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_BASE_URL,
    ABUSEIPDB_MAX_AGE_DAYS,
    ABUSEIPDB_SCORE_THRESHOLD,
    PRIVATE_IP_PREFIXES,
)
from models import Alert
from sigma_engine import get_rule_engine


def _is_private_ip(ip: str) -> bool:
    if not ip or ip == "unknown":
        return True
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def _severity_for_abuse_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def check_abuseipdb(ip: str, cache: dict[str, dict]) -> dict[str, Any] | None:
    """Query AbuseIPDB for a single IP address."""
    if _is_private_ip(ip):
        return None

    if ip in cache:
        return cache[ip]

    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_api_key_here":
        cache[ip] = {
            "ip": ip,
            "abuse_score": None,
            "is_malicious": False,
            "country": None,
            "total_reports": 0,
            "skipped": True,
            "reason": "ABUSEIPDB_API_KEY not configured",
        }
        return cache[ip]

    try:
        response = requests.get(
            ABUSEIPDB_BASE_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))

        result = {
            "ip": ip,
            "abuse_score": score,
            "is_malicious": score >= ABUSEIPDB_SCORE_THRESHOLD,
            "country": data.get("countryCode"),
            "total_reports": data.get("totalReports", 0),
            "skipped": False,
            "reason": None,
        }
        cache[ip] = result
        time.sleep(1.05)
        return result

    except requests.RequestException as exc:
        cache[ip] = {
            "ip": ip,
            "abuse_score": None,
            "is_malicious": False,
            "country": None,
            "total_reports": 0,
            "skipped": True,
            "reason": f"API error: {exc}",
        }
        return cache[ip]


def enrich_with_threat_intel(
    df: pd.DataFrame,
    max_lookups: int = 25,
) -> tuple[pd.DataFrame, list[Alert], dict[str, dict]]:
    """Cross-reference unique external IPs with AbuseIPDB."""
    cache: dict[str, dict] = {}
    alerts: list[Alert] = []

    if df.empty or "source_ip" not in df.columns:
        return df, alerts, cache

    unique_ips = df["source_ip"].dropna().astype(str).unique().tolist()
    external_ips = [ip for ip in unique_ips if not _is_private_ip(ip)]

    for ip in external_ips[:max_lookups]:
        result = check_abuseipdb(ip, cache)
        if result and result.get("is_malicious"):
            alerts.append(Alert(
                severity=_severity_for_abuse_score(result["abuse_score"] or 0),
                rule="threat_intel_abuseipdb",
                source_ip=ip,
                message=(
                    f"AbuseIPDB flagged {ip} "
                    f"(score: {result['abuse_score']}, "
                    f"reports: {result['total_reports']})"
                ),
                evidence_count=result["total_reports"],
                extra={
                    "abuse_score": result["abuse_score"],
                    "country": result["country"],
                },
            ))

    ti_rows = []
    for ip in df["source_ip"].fillna("unknown"):
        ti = cache.get(str(ip), {})
        ti_rows.append({
            "abuse_score": ti.get("abuse_score"),
            "is_malicious": ti.get("is_malicious", False),
            "ti_country": ti.get("country"),
        })

    enriched = df.copy()
    ti_df = pd.DataFrame(ti_rows, index=df.index)
    return pd.concat([enriched, ti_df], axis=1), alerts, cache


def run_all_detections(df: pd.DataFrame) -> list[Alert]:
    """Execute all YAML rules from /rules via the unified rule engine."""
    try:
        return get_rule_engine().run(df)
    except Exception as exc:
        print(f"[rules] Engine error: {exc}")
        return []


def build_analysis_summary(
    df: pd.DataFrame,
    alerts: list[Alert],
    ti_cache: dict[str, dict],
) -> dict[str, Any]:
    """Compute top-level KPIs consumed by the Streamlit dashboard."""
    high_risk = [
        a for a in alerts
        if a.is_high_risk
        and (
            a.rule.startswith("sigma:")
            or a.rule.startswith("rule:")
            or a.rule in ("threat_intel_abuseipdb",)
        )
    ]

    malicious_ips: list[dict[str, Any]] = []
    for ip, data in ti_cache.items():
        if data.get("is_malicious"):
            malicious_ips.append({
                "ip": ip,
                "abuse_score": data.get("abuse_score"),
                "country": data.get("country"),
                "reports": data.get("total_reports", 0),
            })
    malicious_ips.sort(key=lambda x: x.get("abuse_score") or 0, reverse=True)

    attack_timeline = pd.DataFrame()
    if alerts:
        hour_buckets: dict[str, int] = {}
        for alert in alerts:
            if not alert.timestamp:
                continue
            try:
                # Use string hour key — avoids pandas .floor() segfault on some Windows builds.
                raw = str(alert.timestamp).replace("T", " ")
                key = raw[:13] if len(raw) >= 13 else raw  # YYYY-MM-DD HH
                hour_buckets[key] = hour_buckets.get(key, 0) + 1
            except (ValueError, TypeError):
                continue
        if hour_buckets:
            attack_timeline = pd.DataFrame([
                {"timestamp": k, "alert_count": v}
                for k, v in sorted(hour_buckets.items())
            ])

    top_endpoints = pd.DataFrame()
    if not df.empty and "request_path" in df.columns and "status_code" in df.columns:
        error_records = [
            row for _, row in df.iterrows()
            if str(row.get("status_code")) in ("401", "403", "404", "500")
        ]
        if error_records:
            err_df = pd.DataFrame(error_records)
            top_endpoints = (
                err_df.groupby("request_path")
                .size()
                .reset_index(name="hits")
                .sort_values("hits", ascending=False)
                .head(10)
            )

    return {
        "total_logs": len(df),
        "unique_source_ips": df["source_ip"].nunique() if "source_ip" in df.columns else 0,
        "high_risk_alert_count": len(high_risk),
        "total_alert_count": len(alerts),
        "malicious_ips": malicious_ips[:10],
        "attack_timeline": attack_timeline,
        "top_endpoints": top_endpoints,
        "ti_configured": bool(
            ABUSEIPDB_API_KEY and ABUSEIPDB_API_KEY != "your_api_key_here"
        ),
    }
