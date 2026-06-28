"""
Central configuration for the SOC Log & Traffic Analyzer.
Adjust thresholds here without touching core logic.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root (if present).
load_dotenv(Path(__file__).parent / ".env")

# --- AbuseIPDB ---
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS: int = 90
ABUSEIPDB_SCORE_THRESHOLD: int = 50  # Flag IPs with abuse score >= this value.

# --- Anomaly detection thresholds ---
BRUTE_FORCE_STATUS_CODES: set[int] = {401, 403}
BRUTE_FORCE_MIN_EVENTS: int = 5
BRUTE_FORCE_WINDOW_SECONDS: int = 300  # 5 minutes

PORT_SCAN_MIN_PORTS: int = 10
PORT_SCAN_WINDOW_SECONDS: int = 60

# Sigma rules directory (YAML detection signatures).
SIGMA_RULES_DIR: Path = Path(__file__).parent / "rules"

# Private/reserved ranges — skip TI lookups for internal traffic.
PRIVATE_IP_PREFIXES: tuple[str, ...] = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "0.",
)

# Upload limits (bytes).
MAX_LOG_SIZE_BYTES: int = 10 * 1024 * 1024   # 10 MB
MAX_PCAP_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB

# --- Live Syslog Listener (SIEM forwarding) ---
SYSLOG_LISTEN_HOST: str = os.getenv("SYSLOG_LISTEN_HOST", "0.0.0.0")
SYSLOG_LISTEN_PORT: int = int(os.getenv("SYSLOG_LISTEN_PORT", "514"))
SYSLOG_BUFFER_MAX: int = int(os.getenv("SYSLOG_BUFFER_MAX", "10000"))
SYSLOG_SOCKET_TIMEOUT: float = float(os.getenv("SYSLOG_SOCKET_TIMEOUT", "1.0"))
LIVE_REFRESH_INTERVAL_MS: int = int(os.getenv("LIVE_REFRESH_INTERVAL_MS", "2000"))

# --- SQLite case management ---
DATABASE_PATH: Path = Path(__file__).parent / "data" / "soc_platform.db"

# --- AI Triage Assistant ---
AI_PROVIDER: str = os.getenv("AI_PROVIDER", "ollama")  # ollama | openai
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2")
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
