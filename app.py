"""
SOC Log & Traffic Analyzer — Streamlit dashboard.

Run locally:
    streamlit run app.py
"""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ai_triage import is_ai_configured, triage_alert
from analyzer import (
    build_analysis_summary,
    enrich_with_threat_intel,
    run_all_detections,
)
from config import (
    ABUSEIPDB_API_KEY,
    LIVE_REFRESH_INTERVAL_MS,
    MAX_LOG_SIZE_BYTES,
    MAX_PCAP_SIZE_BYTES,
    SYSLOG_LISTEN_HOST,
    SYSLOG_LISTEN_PORT,
)
import database as db
from mitigation import (
    build_soar_actions_for_alert,
    extract_mitigation_targets,
    generate_bulk_playbook,
    generate_iptables_block,
    generate_iptables_unblock,
    generate_windows_firewall_block,
    generate_windows_firewall_unblock,
)
from models import Alert
from parser import parse_uploaded_file, records_to_dataframe
from sigma_engine import get_rule_engine
from syslog_listener import get_syslog_listener

try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:
    st_autorefresh = None  # type: ignore

# ---------------------------------------------------------------------------
# Page config & SOC dark theme
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SOC Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

SOC_CSS = """
<style>
    /* Dark SOC-style background */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    [data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    [data-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
    }
    [data-testid="stMetricLabel"] {
        color: #8b949e !important;
    }
    [data-testid="stMetricValue"] {
        color: #58a6ff !important;
    }
    h1, h2, h3 {
        color: #f0f6fc !important;
    }
    .alert-critical { color: #ff7b72; font-weight: bold; }
    .alert-high     { color: #ffa657; font-weight: bold; }
    .alert-medium   { color: #d2a8ff; }
    .alert-low      { color: #8b949e; }
    .soc-header {
        background: linear-gradient(90deg, #161b22 0%, #1f2937 100%);
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px 28px;
        margin-bottom: 24px;
    }
    .soc-subtitle { color: #8b949e; font-size: 0.95rem; margin-top: 4px; }
</style>
"""
st.markdown(SOC_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#ff7b72",
    "HIGH": "#ffa657",
    "MEDIUM": "#d2a8ff",
    "LOW": "#8b949e",
}


def _severity_badge(severity: str) -> str:
    css = f"alert-{severity.lower()}"
    return f'<span class="{css}">{severity}</span>'


def _render_header() -> None:
    st.markdown(
        """
        <div class="soc-header">
            <h1 style="margin:0;">🛡️ SOC Log &amp; Traffic Analyzer</h1>
            <p class="soc-subtitle">
                Defensive security prototype — parse logs, enrich with threat intel,
                and surface anomalies in real time.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _process_upload(uploaded_file) -> tuple[pd.DataFrame, list[Alert], dict]:
    """Parse, detect, and enrich a single uploaded file."""
    file_bytes = uploaded_file.getvalue()
    filename = uploaded_file.name

    # Size guardrails.
    is_pcap = filename.lower().endswith((".pcap", ".pcapng"))
    max_size = MAX_PCAP_SIZE_BYTES if is_pcap else MAX_LOG_SIZE_BYTES
    if len(file_bytes) > max_size:
        raise ValueError(
            f"File too large ({len(file_bytes) // 1024} KB). "
            f"Max allowed: {max_size // 1024} KB."
        )

    df, fmt = parse_uploaded_file(file_bytes, filename)
    rule_alerts = run_all_detections(df)
    df, ti_alerts, ti_cache = enrich_with_threat_intel(df)
    all_alerts = rule_alerts + ti_alerts
    return df, all_alerts, ti_cache


def _analyze_dataframe(
    df: pd.DataFrame,
    ti_cache: dict | None = None,
) -> tuple[pd.DataFrame, list[Alert], dict]:
    """Run detections and threat intel on a normalized DataFrame."""
    if df.empty:
        return df, [], ti_cache or {}

    rule_alerts = run_all_detections(df)
    enriched, ti_alerts, new_cache = enrich_with_threat_intel(df)
    merged_cache = {**(ti_cache or {}), **new_cache}
    return enriched, rule_alerts + ti_alerts, merged_cache


def _persist_analysis(
    case_title: str,
    source_type: str,
    filename: str | None,
    summary: dict,
    alerts: list[Alert],
) -> int:
    """Save ingestion + alerts to SQLite and return case_id."""
    case_id = db.create_case(case_title, source_type=source_type)
    db.save_ingestion(case_id, filename, summary, alerts)
    return case_id


def _render_full_dashboard(
    combined_df: pd.DataFrame,
    all_alerts: list[Alert],
    merged_ti_cache: dict,
    persist: bool = False,
    case_title: str | None = None,
    filename: str | None = None,
    source_type: str = "upload",
) -> int | None:
    """Shared dashboard panels; optionally persists to SQLite."""
    summary = build_analysis_summary(combined_df, all_alerts, merged_ti_cache)
    case_id = None

    if persist and case_title:
        case_id = _persist_analysis(case_title, source_type, filename, summary, all_alerts)
        st.success(f"Case #{case_id} saved to database — history retained across restarts.")

    st.markdown("---")
    _render_metrics(summary)
    st.markdown("---")
    _render_charts(summary)
    st.markdown("---")
    _render_malicious_ips(summary)
    st.markdown("---")
    _render_ip_distribution(combined_df)
    st.markdown("---")
    _render_alerts_with_actions(all_alerts)
    st.markdown("---")
    _render_mitigation_panel(all_alerts)
    _render_log_preview(combined_df)
    return case_id


def _render_live_syslog_tab() -> None:
    """Live SIEM integration — UDP syslog listener with auto-refreshing dashboard."""
    st.subheader("Live Syslog Stream")
    st.caption(
        "Receive syslog datagrams in real time over UDP. Point remote servers at "
        f"`<this-host>:{SYSLOG_LISTEN_PORT}` — the dashboard refreshes automatically."
    )

    listener = get_syslog_listener()

    if "live_ti_cache" not in st.session_state:
        st.session_state.live_ti_cache = {}

    # Listener controls.
    ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([1, 1, 1, 2])
    with ctrl1:
        listen_port = st.number_input(
            "UDP Port",
            min_value=1,
            max_value=65535,
            value=SYSLOG_LISTEN_PORT,
            help="Standard syslog is UDP/514 (requires admin/root). Use 5514 for local dev.",
        )
    with ctrl2:
        if st.button("Start Listener", type="primary", disabled=listener.is_running):
            err = listener.start(host=SYSLOG_LISTEN_HOST, port=int(listen_port))
            if err:
                st.error(err)
            else:
                st.session_state.live_listener_port = int(listen_port)
                st.success(f"Listening on UDP {SYSLOG_LISTEN_HOST}:{int(listen_port)}")
    with ctrl3:
        if st.button("Stop Listener", disabled=not listener.is_running):
            listener.stop()
            st.info("Listener stopped.")
    with ctrl4:
        if st.button("Clear Live Buffer"):
            listener.clear()
            st.session_state.live_ti_cache = {}
            st.toast("Live buffer cleared.")

    # Auto-refresh while listener is active.
    if listener.is_running:
        if st_autorefresh:
            st_autorefresh(
                interval=LIVE_REFRESH_INTERVAL_MS,
                limit=None,
                key="syslog_live_refresh",
            )
        else:
            st.warning(
                "Install `streamlit-autorefresh` for automatic updates: "
                "`pip install streamlit-autorefresh`"
            )

    stats = listener.stats
    stat_cols = st.columns(5)
    stat_cols[0].metric("Listener", "ACTIVE" if listener.is_running else "STOPPED")
    stat_cols[1].metric("Datagrams", stats.datagrams_received)
    stat_cols[2].metric("Parsed", stats.records_parsed)
    stat_cols[3].metric("Senders", len(stats.unique_senders))
    stat_cols[4].metric("Buffered", listener.record_count())

    if stats.bind_error and not listener.is_running:
        st.error(stats.bind_error)

    # Live tail — most recent raw messages.
    with st.expander("Live Syslog Tail (last 50 datagrams)", expanded=listener.is_running):
        feed = listener.get_raw_feed(50)
        if feed:
            st.dataframe(pd.DataFrame(feed), use_container_width=True, hide_index=True)
        else:
            st.info("Waiting for syslog datagrams…")

    records = listener.get_records_snapshot()
    if not records:
        st.markdown("---")
        st.info(
            "No syslog messages received yet. "
            "Start the listener, then forward logs from a remote host.\n\n"
            "**Linux (rsyslog):** `*.* @<analyzer-ip>:514`\n\n"
            "**Test locally:** `python tools/send_test_syslog.py --host 127.0.0.1 --port 5514`"
        )
        return

    combined_df = records_to_dataframe(records)
    enriched_df, all_alerts, ti_cache = _analyze_dataframe(
        combined_df,
        ti_cache=st.session_state.live_ti_cache,
    )
    st.session_state.live_ti_cache = ti_cache

    if listener.is_running:
        st.caption(
            f"Auto-refreshing every {LIVE_REFRESH_INTERVAL_MS / 1000:.0f}s · "
            f"Last message: {stats.last_received_at or '—'}"
        )
        if st.button("Save live snapshot to case", key="save_live_case"):
            summary = build_analysis_summary(enriched_df, all_alerts, ti_cache)
            case_id = _persist_analysis(
                f"Live syslog {datetime.now():%Y-%m-%d %H:%M}",
                "live",
                None,
                summary,
                all_alerts,
            )
            st.success(f"Saved as case #{case_id}")

    _render_full_dashboard(enriched_df, all_alerts, ti_cache, persist=False)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _render_sidebar() -> None:
    st.sidebar.title("⚙️ Configuration")

    ti_configured = bool(ABUSEIPDB_API_KEY and ABUSEIPDB_API_KEY != "your_api_key_here")
    if ti_configured:
        st.sidebar.success("AbuseIPDB API key loaded")
    else:
        st.sidebar.warning(
            "AbuseIPDB key not set.\n\n"
            "Copy `.env.example` → `.env` and add your free API key."
        )

    st.sidebar.markdown("---")
    st.sidebar.markdown("**Supported formats**")
    st.sidebar.markdown(
        "- Apache / Nginx access logs\n"
        "- Linux Syslog\n"
        "- PCAP / PCAPNG captures\n"
        "- **Live UDP Syslog** (port 514)"
    )
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Detection rules**")
    st.sidebar.markdown(
        "- Brute-force (401/403 bursts)\n"
        "- Port scan (PCAP)\n"
        "- AbuseIPDB threat intel\n"
        "- **Sigma YAML rules** (dynamic)\n"
        "- **SOAR mitigation** playbooks"
    )

    engine = get_rule_engine()
    st.sidebar.markdown(f"**YAML rules loaded:** {engine.rule_count}")
    if engine.list_rules():
        with st.sidebar.expander("View detection rules"):
            for rule in engine.list_rules():
                st.sidebar.markdown(
                    f"**{rule['title']}**  \n"
                    f"`{rule['file']}` · {rule['type']} · {rule['level']}"
                )

    st.sidebar.markdown("---")
    if is_ai_configured():
        st.sidebar.success("AI Triage Assistant: configured")
    else:
        st.sidebar.info("AI Triage: template mode (set Ollama/OpenAI in `.env`)")

    stats = db.get_platform_stats()
    st.sidebar.markdown("**Platform history**")
    st.sidebar.markdown(
        f"- Cases: {stats.get('total_cases', 0)}\n"
        f"- Alerts: {stats.get('total_alerts', 0)}\n"
        f"- High-risk: {stats.get('high_risk_alerts', 0)}"
    )


# ---------------------------------------------------------------------------
# Main dashboard panels
# ---------------------------------------------------------------------------

def _render_metrics(summary: dict) -> None:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Logs Processed", f"{summary['total_logs']:,}")
    col2.metric("High-Risk Alerts", summary["high_risk_alert_count"])
    col3.metric("Total Alerts", summary["total_alert_count"])
    col4.metric("Unique Source IPs", summary["unique_source_ips"])


def _render_charts(summary: dict) -> None:
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Attacks Over Time")
        timeline = summary.get("attack_timeline")
        if timeline is not None and not timeline.empty:
            fig = px.bar(
                timeline,
                x="timestamp",
                y="alert_count",
                labels={"timestamp": "Time", "alert_count": "Alerts"},
                color_discrete_sequence=["#58a6ff"],
            )
            fig.update_layout(
                plot_bgcolor="#161b22",
                paper_bgcolor="#0d1117",
                font_color="#c9d1d9",
                xaxis=dict(gridcolor="#30363d"),
                yaxis=dict(gridcolor="#30363d"),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No time-series alert data available for this upload.")

    with col_right:
        st.subheader("Top Attacked Endpoints")
        endpoints = summary.get("top_endpoints")
        if endpoints is not None and not endpoints.empty:
            fig = px.bar(
                endpoints,
                x="hits",
                y="request_path",
                orientation="h",
                labels={"hits": "Error Hits", "request_path": "Endpoint"},
                color_discrete_sequence=["#ffa657"],
            )
            fig.update_layout(
                plot_bgcolor="#161b22",
                paper_bgcolor="#0d1117",
                font_color="#c9d1d9",
                yaxis=dict(categoryorder="total ascending"),
                xaxis=dict(gridcolor="#30363d"),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No HTTP error endpoints found (PCAP or syslog uploads).")


def _render_malicious_ips(summary: dict) -> None:
    st.subheader("Most Active Malicious IPs (Threat Intel)")
    malicious = summary.get("malicious_ips", [])
    if malicious:
        mal_df = pd.DataFrame(malicious)
        st.dataframe(mal_df, use_container_width=True, hide_index=True)
    elif summary.get("ti_configured"):
        st.success("No IPs exceeded the AbuseIPDB abuse score threshold.")
    else:
        st.info(
            "Threat intel lookups skipped — configure `ABUSEIPDB_API_KEY` in `.env`."
        )


def _render_alert_actions(alert: Alert, key_prefix: str) -> None:
    """Per-alert SOAR actions and AI triage for enterprise triage workflow."""
    ip = alert.source_ip
    if ip and ip != "unknown":
        actions = build_soar_actions_for_alert(alert)
        if actions:
            st.markdown("**Actions**")
            cols = st.columns(min(len(actions), 4))
            for idx, (action_key, meta) in enumerate(actions.items()):
                with cols[idx % len(cols)]:
                    st.download_button(
                        label=meta["label"],
                        data=meta["content"],
                        file_name=meta["filename"],
                        mime=meta["mime"],
                        key=f"{key_prefix}_soar_{action_key}_{alert.rule}_{ip}",
                        use_container_width=True,
                    )

    if alert.is_high_risk or alert.severity.upper() in ("HIGH", "CRITICAL", "MEDIUM"):
        st.markdown("**AI Triage Assistant**")
        triage_key = f"{key_prefix}_ai_{alert.db_id or alert.rule}_{ip}"
        if st.button("Generate triage summary", key=triage_key):
            with st.spinner("Analyzing with AI assistant…"):
                if alert.db_id:
                    cached = db.get_ai_triage(alert.db_id)
                    if cached:
                        result = cached
                    else:
                        result = triage_alert(alert)
                        db.save_ai_triage(
                            alert.db_id,
                            result["what_happened"],
                            result["next_steps"],
                            result.get("provider", "unknown"),
                        )
                else:
                    result = triage_alert(alert)

                st.info(f"**What happened:** {result['what_happened']}")
                st.success(f"**Recommended next steps:** {result['next_steps']}")
                st.caption(f"Provider: {result.get('provider', 'template')}")


def _render_alerts_with_actions(alerts: list[Alert]) -> None:
    """Security alerts with per-alert SOAR actions and AI triage."""
    st.subheader("Security Alerts & Analyst Actions")
    if not alerts:
        st.success("No anomalies detected.")
        return

    sorted_alerts = sorted(
        alerts,
        key=lambda a: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(a.severity.upper(), 0),
        reverse=True,
    )

    for idx, alert in enumerate(sorted_alerts[:25]):
        color = SEVERITY_COLORS.get(alert.severity.upper(), "#c9d1d9")
        with st.expander(
            f"**{alert.severity}** · `{alert.rule}` · "
            f"{alert.source_ip} — {alert.message[:90]}",
            expanded=idx == 0 and alert.is_high_risk,
        ):
            st.markdown(
                f"<span style='color:{color};font-weight:600'>{alert.severity}</span> · "
                f"Rule: `{alert.rule}` · Evidence: {alert.evidence_count}",
                unsafe_allow_html=True,
            )
            st.markdown(alert.message)
            _render_alert_actions(alert, key_prefix=f"alert_{idx}")


def _render_log_preview(df: pd.DataFrame) -> None:
    with st.expander("Parsed Log Preview (first 100 rows)", expanded=False):
        preview_cols = [
            c for c in [
                "timestamp", "source_ip", "dest_ip", "dest_port",
                "status_code", "method", "request_path", "log_type",
                "is_malicious", "abuse_score",
            ]
            if c in df.columns
        ]
        st.dataframe(df[preview_cols].head(100), use_container_width=True)


def _render_ip_distribution(df: pd.DataFrame) -> None:
    if df.empty or "source_ip" not in df.columns:
        return

    st.subheader("Top Source IPs by Event Volume")
    ip_counts = (
        df["source_ip"]
        .value_counts()
        .head(15)
        .reset_index()
    )
    ip_counts.columns = ["source_ip", "events"]

    fig = go.Figure(go.Bar(
        x=ip_counts["events"],
        y=ip_counts["source_ip"],
        orientation="h",
        marker_color="#3fb950",
    ))
    fig.update_layout(
        plot_bgcolor="#161b22",
        paper_bgcolor="#0d1117",
        font_color="#c9d1d9",
        yaxis=dict(categoryorder="total ascending"),
        xaxis=dict(gridcolor="#30363d"),
        height=400,
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_mitigation_panel(alerts: list[Alert]) -> None:
    """
    SOAR-style incident response panel.

    Surfaces high-risk IPs and offers one-click download of firewall
    containment scripts for Linux (iptables) and Windows (PowerShell).
    """
    st.subheader("Incident Response — Automated Mitigation (SOAR)")
    st.caption(
        "High-risk source IPs are listed below. Download a containment script, "
        "review it, then execute manually on the target host. "
        "**Scripts are never auto-executed by this tool.**"
    )

    targets = extract_mitigation_targets(alerts)
    if not targets:
        st.info("No high-risk IPs require mitigation playbooks for this upload.")
        return

    private_targets = [t for t in targets if t.is_private]
    if private_targets:
        st.warning(
            f"{len(private_targets)} target(s) are **private/internal IPs**. "
            "Blocking internal addresses can disrupt legitimate services — "
            "verify before deploying."
        )

    # Bulk download — block all high-risk IPs in one script.
    st.markdown("#### Bulk Containment")
    bulk_col1, bulk_col2 = st.columns(2)
    with bulk_col1:
        st.download_button(
            label="Download Linux playbook (all IPs)",
            data=generate_bulk_playbook(targets, platform="linux"),
            file_name="soc_block_all_linux.sh",
            mime="text/x-shellscript",
            use_container_width=True,
        )
    with bulk_col2:
        st.download_button(
            label="Download Windows playbook (all IPs)",
            data=generate_bulk_playbook(targets, platform="windows"),
            file_name="soc_block_all_windows.ps1",
            mime="text/plain",
            use_container_width=True,
        )

    st.markdown("#### Per-IP Containment")
    for target in targets:
        badge = "INTERNAL" if target.is_private else "EXTERNAL"
        with st.expander(
            f"{target.ip}  ·  {target.max_severity}  ·  "
            f"{target.alert_count} alert(s)  ·  {badge}",
            expanded=len(targets) == 1,
        ):
            st.markdown(f"**Triggered rules:** `{'`, `'.join(target.rules)}`")
            for msg in target.sample_messages:
                st.markdown(f"- {msg}")

            col_linux, col_win, col_undo = st.columns(3)

            with col_linux:
                st.download_button(
                    label="Linux iptables block",
                    data=generate_iptables_block(target.ip, target),
                    file_name=f"block_{target.ip.replace(':', '-')}_linux.sh",
                    mime="text/x-shellscript",
                    key=f"linux_block_{target.ip}",
                    use_container_width=True,
                )
            with col_win:
                st.download_button(
                    label="Windows Firewall block",
                    data=generate_windows_firewall_block(target.ip, target),
                    file_name=f"block_{target.ip.replace(':', '-')}_windows.ps1",
                    mime="text/plain",
                    key=f"win_block_{target.ip}",
                    use_container_width=True,
                )
            with col_undo:
                undo_col_a, undo_col_b = st.columns(2)
                with undo_col_a:
                    st.download_button(
                        label="Unblock (Linux)",
                        data=generate_iptables_unblock(target.ip),
                        file_name=f"unblock_{target.ip.replace(':', '-')}_linux.sh",
                        mime="text/x-shellscript",
                        key=f"linux_unblock_{target.ip}",
                        use_container_width=True,
                    )
                with undo_col_b:
                    st.download_button(
                        label="Unblock (Win)",
                        data=generate_windows_firewall_unblock(target.ip),
                        file_name=f"unblock_{target.ip.replace(':', '-')}_windows.ps1",
                        mime="text/plain",
                        key=f"win_unblock_{target.ip}",
                        use_container_width=True,
                    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _render_case_management_tab() -> None:
    """Historical cases and persisted alert triage."""
    st.subheader("Case Management")
    st.caption("Investigation cases and alerts persist in SQLite across restarts.")

    cases = db.list_cases()
    if not cases:
        st.info("No cases yet. Upload logs or start a live stream to create one.")
        return

    case_df = pd.DataFrame(cases)
    display_cols = [
        c for c in [
            "id", "title", "status", "source_type", "alert_total",
            "high_risk_total", "ingestion_count", "created_at", "updated_at",
        ]
        if c in case_df.columns
    ]
    st.dataframe(case_df[display_cols], use_container_width=True, hide_index=True)

    case_ids = [int(c["id"]) for c in cases]
    selected = st.selectbox(
        "Open case",
        case_ids,
        format_func=lambda cid: next(
            (f"#{c['id']} — {c['title']} ({c['status']})" for c in cases if c["id"] == cid),
            str(cid),
        ),
    )

    if selected:
        case = db.get_case(selected)
        if case:
            st.markdown(f"### {case['title']}")
            status_col, notes_col = st.columns([1, 3])
            with status_col:
                statuses = ["open", "investigating", "closed"]
                current = case.get("status", "open")
                new_status = st.selectbox(
                    "Case status",
                    statuses,
                    index=statuses.index(current) if current in statuses else 0,
                    key=f"case_status_{selected}",
                )
                if st.button("Update status", key=f"update_case_{selected}"):
                    db.update_case_status(selected, new_status)
                    st.rerun()
            with notes_col:
                st.markdown(f"**Notes:** {case.get('notes') or '—'}")

        ingestions = db.get_case_ingestions(selected)
        if ingestions:
            st.markdown("#### Ingestions")
            st.dataframe(pd.DataFrame(ingestions), use_container_width=True, hide_index=True)

        alerts = db.get_case_alerts(selected)
        if alerts:
            st.markdown("#### Persisted alerts")
            for row in alerts[:20]:
                with st.expander(
                    f"{row['severity']} · {row['rule']} · {row['source_ip']}",
                    expanded=False,
                ):
                    st.markdown(row["message"])
                    if row.get("what_happened"):
                        st.info(f"**What happened:** {row['what_happened']}")
                        st.success(f"**Next steps:** {row['next_steps']}")
                    status = st.selectbox(
                        "Analyst status",
                        ["new", "acknowledged", "closed"],
                        index=["new", "acknowledged", "closed"].index(row.get("analyst_status", "new")),
                        key=f"ast_{row['id']}",
                    )
                    if st.button("Save", key=f"save_ast_{row['id']}"):
                        db.update_alert_status(row["id"], status)
                        st.rerun()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    _render_header()
    _render_sidebar()

    tab_upload, tab_live, tab_cases = st.tabs([
        "File Upload",
        "Live Syslog Stream",
        "Case Management",
    ])

    with tab_upload:
        case_title = st.text_input(
            "Case title",
            value=f"Upload {datetime.now():%Y-%m-%d %H:%M}",
            help="Saved to SQLite for cross-session history.",
        )
        uploaded_files = st.file_uploader(
            "Upload log or PCAP files",
            type=["log", "txt", "pcap", "pcapng"],
            accept_multiple_files=True,
            help="Drop Apache/Nginx access logs, syslog files, or small PCAP captures.",
        )

        if not uploaded_files:
            st.markdown("---")
            st.markdown(
                "### Getting started\n"
                "1. Upload logs or switch to **Live Syslog Stream**.\n"
                "2. Review alerts — each has **SOAR Actions** and **AI Triage**.\n"
                "3. Cases persist in **Case Management** across restarts.\n\n"
                "Try `samples/apache_sample.log` to see detections immediately."
            )
        else:
            all_dfs: list[pd.DataFrame] = []
            all_alerts: list[Alert] = []
            merged_ti_cache: dict = {}
            filenames: list[str] = []

            for uploaded in uploaded_files:
                with st.spinner(f"Analyzing `{uploaded.name}`…"):
                    try:
                        df, alerts, ti_cache = _process_upload(uploaded)
                        all_dfs.append(df)
                        all_alerts.extend(alerts)
                        merged_ti_cache.update(ti_cache)
                        filenames.append(uploaded.name)
                        st.success(
                            f"`{uploaded.name}` — {len(df):,} records, {len(alerts)} alerts"
                        )
                    except Exception as exc:
                        st.error(f"Failed to process `{uploaded.name}`: {exc}")

            if all_dfs:
                combined_df = pd.concat(all_dfs, ignore_index=True)
                _render_full_dashboard(
                    combined_df,
                    all_alerts,
                    merged_ti_cache,
                    persist=True,
                    case_title=case_title,
                    filename=", ".join(filenames),
                    source_type="upload",
                )

    with tab_live:
        _render_live_syslog_tab()

    with tab_cases:
        _render_case_management_tab()


if __name__ == "__main__":
    main()
