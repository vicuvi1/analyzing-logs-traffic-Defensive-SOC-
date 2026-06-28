"""
AI Triage Assistant — optional LLM-powered alert summarization.

Supports Ollama (local) and OpenAI-compatible APIs. Falls back to a
rule-based template when no provider is configured.
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from config import (
    AI_PROVIDER,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
)
from models import Alert

_SYSTEM_PROMPT = (
    "You are a senior SOC analyst mentoring a junior analyst. "
    "Respond ONLY with valid JSON containing exactly two string fields: "
    '"what_happened" (one sentence) and "next_steps" (one sentence with '
    "concrete defensive actions). No markdown, no extra keys."
)


def _provider_configured() -> tuple[str | None, str]:
    """Return (provider_name, model) if configured."""
    if AI_PROVIDER == "openai" and OPENAI_API_KEY and OPENAI_API_KEY != "your_openai_key_here":
        return "openai", OPENAI_MODEL
    if AI_PROVIDER in ("ollama", "openai") and OLLAMA_BASE_URL:
        return "ollama", OLLAMA_MODEL
    if OPENAI_API_KEY and OPENAI_API_KEY != "your_openai_key_here":
        return "openai", OPENAI_MODEL
    if OLLAMA_BASE_URL:
        return "ollama", OLLAMA_MODEL
    return None, ""


def _parse_llm_json(text: str) -> dict[str, str] | None:
    """Extract JSON object from LLM response."""
    text = text.strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "what_happened" in data and "next_steps" in data:
            return {
                "what_happened": str(data["what_happened"]).strip(),
                "next_steps": str(data["next_steps"]).strip(),
            }
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group())
            if "what_happened" in data and "next_steps" in data:
                return {
                    "what_happened": str(data["what_happened"]).strip(),
                    "next_steps": str(data["next_steps"]).strip(),
                }
        except json.JSONDecodeError:
            pass
    return None


def _call_ollama(prompt: str) -> str:
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": "json",
    }
    response = requests.post(url, json=payload, timeout=60)
    response.raise_for_status()
    return response.json()["message"]["content"]


def _call_openai(prompt: str) -> str:
    url = f"{OPENAI_BASE_URL.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    response = requests.post(url, headers=headers, json=payload, timeout=60)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def _fallback_triage(alert: Alert, log_line: str) -> dict[str, Any]:
    """Template-based summary when LLM is unavailable."""
    rule = alert.rule.replace("sigma:", "Sigma rule ")
    what = (
        f"A {alert.severity} alert ({rule}) was triggered by source IP "
        f"{alert.source_ip}: {alert.message[:160]}"
    )
    steps_map = {
        "brute_force": "Isolate the source IP at the perimeter, review auth logs for successful logins, and enforce MFA on targeted accounts.",
        "port_scan": "Verify the target host's exposure, block the scanner IP, and inspect internal hosts for unauthorized services.",
        "threat_intel_abuseipdb": "Block the IP at the firewall, correlate with other SIEM events from this address, and document in the incident ticket.",
    }
    next_steps = steps_map.get(
        alert.rule,
        "Validate the indicator in raw logs, block the source IP if malicious intent is confirmed, and escalate per your IR playbook.",
    )
    return {
        "what_happened": what,
        "next_steps": next_steps,
        "provider": "template",
    }


def triage_alert(alert: Alert, log_line: str | None = None) -> dict[str, Any]:
    """
    Generate a 2-sentence triage summary for a suspicious alert.

    Returns dict with: what_happened, next_steps, provider.
    """
    line = (log_line or alert.log_line)[:2000]
    prompt = (
        f"Alert severity: {alert.severity}\n"
        f"Rule: {alert.rule}\n"
        f"Source IP: {alert.source_ip}\n"
        f"Message: {alert.message}\n"
        f"Log line: {line}\n"
    )

    provider, model = _provider_configured()
    if not provider:
        return _fallback_triage(alert, line)

    try:
        raw = _call_openai(prompt) if provider == "openai" else _call_ollama(prompt)
        parsed = _parse_llm_json(raw)
        if parsed:
            return {**parsed, "provider": f"{provider}:{model}"}
    except requests.RequestException as exc:
        result = _fallback_triage(alert, line)
        result["provider"] = f"template (LLM error: {exc})"
        return result

    return _fallback_triage(alert, line)


def is_ai_configured() -> bool:
    return _provider_configured()[0] is not None
