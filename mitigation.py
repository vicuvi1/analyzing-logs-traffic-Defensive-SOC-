"""
SOAR-style Mitigation Module — automated incident response playbooks.

When an IP triggers a high-risk alert, this module generates ready-to-run
firewall containment scripts for Linux (iptables) and Windows (PowerShell).

Scripts are generated for analyst review and one-click download — they are
NEVER executed automatically by this application.
"""

from __future__ import annotations

import json
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from config import PRIVATE_IP_PREFIXES
from models import Alert

# Severity ordering for ranking multiple alerts on the same IP.
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Rules that qualify for automated containment playbooks.
_HIGH_RISK_RULES = frozenset({"threat_intel_abuseipdb"})

# IPv4/IPv6 validation pattern (defence-in-depth before script injection).
_IP_SAFE_RE = re.compile(r"^[0-9a-fA-F:.\-]+$")


@dataclass
class MitigationTarget:
    """An IP address eligible for firewall containment."""

    ip: str
    max_severity: str
    rules: list[str] = field(default_factory=list)
    alert_count: int = 0
    sample_messages: list[str] = field(default_factory=list)
    is_private: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "max_severity": self.max_severity,
            "rules": self.rules,
            "alert_count": self.alert_count,
            "is_private": self.is_private,
        }


# ---------------------------------------------------------------------------
# IP validation & target extraction
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def validate_ip(ip: str) -> str | None:
    """
    Validate and normalize an IP address for safe inclusion in scripts.

    Returns the stringified IP if valid, or None if invalid/unsafe.
    """
    if not ip or ip == "unknown":
        return None
    cleaned = ip.strip()
    if not _IP_SAFE_RE.match(cleaned):
        return None
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return None
    # Reject multicast and unspecified addresses.
    if addr.is_multicast or addr.is_unspecified:
        return None
    return str(addr)


def is_high_risk_alert(alert: Alert) -> bool:
    """Return True if an alert warrants automated containment playbooks."""
    if not alert.is_high_risk:
        return False
    rule = str(alert.rule)
    if rule.startswith("sigma:") or rule.startswith("rule:"):
        return True
    return rule in _HIGH_RISK_RULES


def extract_mitigation_targets(alerts: list[Alert]) -> list[MitigationTarget]:
    """
    Aggregate high-risk alerts by source IP into mitigation targets.

    Returns targets sorted by severity (CRITICAL first), then alert count.
    """
    buckets: dict[str, dict[str, Any]] = {}

    for alert in alerts:
        if not is_high_risk_alert(alert):
            continue

        ip = validate_ip(str(alert.source_ip))
        if not ip:
            continue

        if ip not in buckets:
            buckets[ip] = {
                "max_severity": "LOW",
                "rules": set(),
                "alert_count": 0,
                "sample_messages": [],
                "is_private": _is_private_ip(ip),
            }

        bucket = buckets[ip]
        bucket["alert_count"] += 1
        bucket["rules"].add(str(alert.rule))

        sev = str(alert.severity).upper()
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(bucket["max_severity"], 0):
            bucket["max_severity"] = sev

        if len(bucket["sample_messages"]) < 3:
            bucket["sample_messages"].append(str(alert.message)[:120])

    targets = [
        MitigationTarget(
            ip=ip,
            max_severity=data["max_severity"],
            rules=sorted(data["rules"]),
            alert_count=data["alert_count"],
            sample_messages=data["sample_messages"],
            is_private=data["is_private"],
        )
        for ip, data in buckets.items()
    ]

    targets.sort(
        key=lambda t: (_SEVERITY_RANK.get(t.max_severity, 0), t.alert_count),
        reverse=True,
    )
    return targets


# ---------------------------------------------------------------------------
# Script generators
# ---------------------------------------------------------------------------

def _header_comment(ip: str, target: MitigationTarget | None, platform: str) -> str:
    """Standard playbook header with audit metadata."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# {'=' * 60}",
        f"# SOC Log Analyzer — {platform} Mitigation Playbook",
        f"# {'=' * 60}",
        f"# Generated : {ts}",
        f"# Target IP : {ip}",
    ]
    if target:
        lines.append(f"# Severity  : {target.max_severity}")
        lines.append(f"# Alerts    : {target.alert_count}")
        lines.append(f"# Rules     : {', '.join(target.rules)}")
    lines += [
        "#",
        "# WARNING: Review before executing on production systems.",
        "#          Incorrect blocks can cause service outages.",
        "#          This script was NOT auto-executed by the analyzer.",
        "#",
    ]
    return "\n".join(lines)


def generate_iptables_block(ip: str, target: MitigationTarget | None = None) -> str:
    """
    Generate a Linux iptables containment script.

    Blocks inbound, outbound, and forwarded traffic for the target IP.
    Requires root/sudo to execute.
    """
    safe_ip = validate_ip(ip)
    if not safe_ip:
        raise ValueError(f"Invalid IP address for mitigation: {ip!r}")

    header = _header_comment(safe_ip, target, "Linux iptables")
    return f"""{header}
#!/bin/bash
set -euo pipefail

IP="{safe_ip}"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)." >&2
    exit 1
fi

echo "[*] Applying iptables DROP rules for $IP ..."

# Inbound: block traffic originating from the attacker
iptables -C INPUT -s "$IP" -j DROP 2>/dev/null || \\
    iptables -I INPUT 1 -s "$IP" -j DROP

# Outbound: block traffic destined to the attacker (exfil / C2 containment)
iptables -C OUTPUT -d "$IP" -j DROP 2>/dev/null || \\
    iptables -I OUTPUT 1 -d "$IP" -j DROP

# Forward: block routed traffic through this host
iptables -C FORWARD -s "$IP" -j DROP 2>/dev/null || \\
    iptables -I FORWARD 1 -s "$IP" -j DROP
iptables -C FORWARD -d "$IP" -j DROP 2>/dev/null || \\
    iptables -I FORWARD 1 -d "$IP" -j DROP

echo "[+] Block applied for $IP"
echo "[*] Verify with: iptables -L INPUT -n -v | grep $IP"
"""


def generate_iptables_unblock(ip: str) -> str:
    """Generate a Linux script to remove iptables rules for an IP."""
    safe_ip = validate_ip(ip)
    if not safe_ip:
        raise ValueError(f"Invalid IP address: {ip!r}")

    return f"""#!/bin/bash
# SOC Log Analyzer — Remove iptables block for {safe_ip}
set -euo pipefail

IP="{safe_ip}"

iptables -D INPUT  -s "$IP" -j DROP 2>/dev/null || true
iptables -D OUTPUT -d "$IP" -j DROP 2>/dev/null || true
iptables -D FORWARD -s "$IP" -j DROP 2>/dev/null || true
iptables -D FORWARD -d "$IP" -j DROP 2>/dev/null || true

echo "[+] Removed iptables rules for $IP"
"""


def generate_windows_firewall_block(ip: str, target: MitigationTarget | None = None) -> str:
    """
    Generate a Windows PowerShell script using New-NetFirewallRule.

    Must be run in an elevated (Administrator) PowerShell session.
    """
    safe_ip = validate_ip(ip)
    if not safe_ip:
        raise ValueError(f"Invalid IP address for mitigation: {ip!r}")

    # Safe rule name suffix (no dots or colons).
    rule_suffix = safe_ip.replace(".", "-").replace(":", "-")
    header = _header_comment(safe_ip, target, "Windows Firewall")

    return f"""{header}
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$TargetIP   = "{safe_ip}"
$RuleBase   = "SOC-Block-{rule_suffix}"
$Timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "[*] SOC Mitigation Playbook — $Timestamp" -ForegroundColor Cyan
Write-Host "[*] Target IP: $TargetIP"

# Remove stale rules with the same name before re-creating
foreach ($dir in @("Inbound", "Outbound")) {{
    $name = "$RuleBase-$dir"
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {{
        Remove-NetFirewallRule -DisplayName $name
        Write-Host "[-] Removed existing rule: $name"
    }}
}}

# Inbound block — drop all traffic from the attacker
New-NetFirewallRule `
    -DisplayName "$RuleBase-Inbound" `
    -Description "SOC auto-generated block for $TargetIP (inbound)" `
    -Direction Inbound `
    -RemoteAddress $TargetIP `
    -Action Block `
    -Enabled True `
    -Profile Any

# Outbound block — prevent connections to the attacker
New-NetFirewallRule `
    -DisplayName "$RuleBase-Outbound" `
    -Description "SOC auto-generated block for $TargetIP (outbound)" `
    -Direction Outbound `
    -RemoteAddress $TargetIP `
    -Action Block `
    -Enabled True `
    -Profile Any

Write-Host "[+] Firewall rules created for $TargetIP" -ForegroundColor Green
Write-Host "[*] Verify with: Get-NetFirewallRule -DisplayName '$RuleBase-*'"
"""


def generate_windows_firewall_unblock(ip: str) -> str:
    """Generate a PowerShell script to remove Windows Firewall block rules."""
    safe_ip = validate_ip(ip)
    if not safe_ip:
        raise ValueError(f"Invalid IP address: {ip!r}")

    rule_suffix = safe_ip.replace(".", "-").replace(":", "-")

    return f"""#Requires -RunAsAdministrator
# SOC Log Analyzer — Remove firewall block for {safe_ip}

$RuleBase = "SOC-Block-{rule_suffix}"

foreach ($dir in @("Inbound", "Outbound")) {{
    $name = "$RuleBase-$dir"
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {{
        Remove-NetFirewallRule -DisplayName $name
        Write-Host "[+] Removed rule: $name"
    }} else {{
        Write-Host "[-] Rule not found: $name"
    }}
}}
"""


def generate_bulk_playbook(
    targets: list[MitigationTarget],
    platform: str = "linux",
) -> str:
    """
    Generate a single script that blocks all high-risk IPs.

    platform: 'linux' | 'windows'
    """
    if not targets:
        return "# No high-risk IPs to block.\n"

    sections: list[str] = []
    for target in targets:
        try:
            if platform == "windows":
                sections.append(generate_windows_firewall_block(target.ip, target))
            else:
                sections.append(generate_iptables_block(target.ip, target))
        except ValueError:
            continue

    separator = "\n\n# " + "-" * 60 + "\n\n"
    return separator.join(sections)


def generate_aws_security_group_rule(
    ip: str,
    alert: Alert | None = None,
    sg_id: str = "sg-XXXXXXXX",
) -> str:
    """
    Generate an AWS EC2 Security Group ingress deny rule as JSON.

    Suitable for import into IaC pipelines or AWS CLI review.
    """
    safe_ip = validate_ip(ip)
    if not safe_ip:
        raise ValueError(f"Invalid IP address for mitigation: {ip!r}")

    cidr = f"{safe_ip}/32" if ":" not in safe_ip else f"{safe_ip}/128"
    description = (
        f"SOC block — {alert.rule} — {alert.message[:80]}"
        if alert else f"SOC auto-block for {safe_ip}"
    )

    rule = {
        "SecurityGroupRules": [
            {
                "Description": description,
                "GroupId": sg_id,
                "IpProtocol": "-1",
                "FromPort": -1,
                "ToPort": -1,
                "CidrIpv4": cidr if ":" not in safe_ip else None,
                "CidrIpv6": cidr if ":" in safe_ip else None,
                "RuleAction": "deny",
            }
        ],
        "Tags": [
            {"Key": "soc-platform", "Value": "auto-generated"},
            {"Key": "blocked-ip", "Value": safe_ip},
        ],
    }
    # Remove null CIDR keys for clean JSON.
    entry = rule["SecurityGroupRules"][0]
    if entry["CidrIpv4"] is None:
        del entry["CidrIpv4"]
    if entry["CidrIpv6"] is None:
        del entry["CidrIpv6"]

    return json.dumps(rule, indent=2)


def generate_iptables_oneliner(ip: str) -> str:
    """Single-line iptables command for quick copy-paste."""
    safe_ip = validate_ip(ip)
    if not safe_ip:
        raise ValueError(f"Invalid IP: {ip!r}")
    return f"iptables -A INPUT -s {safe_ip} -j DROP"


def build_soar_actions_for_alert(alert: Alert) -> dict[str, dict[str, str]]:
    """
    Build downloadable SOAR action artifacts for a single alert.

    Returns dict of action_name -> {filename, content, mime}.
    """
    ip = validate_ip(str(alert.source_ip))
    if not ip:
        return {}

    slug = ip.replace(":", "-")
    target = MitigationTarget(
        ip=ip,
        max_severity=alert.severity,
        rules=[alert.rule],
        alert_count=1,
        sample_messages=[alert.message],
    )

    actions: dict[str, dict[str, str]] = {
        "iptables_oneliner": {
            "filename": f"block_{slug}_oneliner.txt",
            "content": generate_iptables_oneliner(ip),
            "mime": "text/plain",
            "label": "iptables one-liner",
        },
        "iptables_script": {
            "filename": f"block_{slug}_linux.sh",
            "content": generate_iptables_block(ip, target),
            "mime": "text/x-shellscript",
            "label": "Linux iptables script",
        },
        "windows_firewall": {
            "filename": f"block_{slug}_windows.ps1",
            "content": generate_windows_firewall_block(ip, target),
            "mime": "text/plain",
            "label": "Windows Firewall",
        },
        "aws_sg_rule": {
            "filename": f"block_{slug}_aws_sg.json",
            "content": generate_aws_security_group_rule(ip, alert),
            "mime": "application/json",
            "label": "AWS Security Group JSON",
        },
    }
    return actions
