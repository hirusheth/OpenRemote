"""Windows firewall helper for mDNS discovery.

Discovery normally works on domestic networks after clicking "Allow" on the
Windows popup. If that popup was cancelled (Windows never asks again) or never
appeared, `openremote fix-firewall` adds a narrowly scoped inbound rule -
UDP port 5353 only - through a UAC-elevated PowerShell. Control traffic
(outbound TCP to the TV) never needs any of this.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

RULE_NAME = "OpenRemote mDNS (UDP 5353)"


def _powershell(command: str, timeout: float = 60.0) -> str:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


def rule_exists() -> bool:
    """Whether the mDNS allow rule is already present (True on non-Windows)."""
    if os.name != "nt":
        return True
    output = _powershell(
        f"(Get-NetFirewallRule -DisplayName '{RULE_NAME}' "
        f"-ErrorAction SilentlyContinue) -ne $null"
    )
    return output.strip().lower().endswith("true")


def create_rule_elevated() -> tuple[bool, str]:
    """Add the inbound UDP 5353 allow rule via a UAC-elevated PowerShell."""
    if os.name != "nt":
        return False, "not required on this platform"
    script = Path(tempfile.gettempdir()) / "openremote_mdns_rule.ps1"
    script.write_text(
        f"New-NetFirewallRule -DisplayName '{RULE_NAME}' -Direction Inbound "
        f"-Protocol UDP -LocalPort 5353 -Action Allow -Profile Any | Out-Null\n"
        f"Write-Host 'Rule created: {RULE_NAME}'\n"
        f"Read-Host 'Press Enter to close this window'\n",
        encoding="utf-8",
    )
    try:
        subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Start-Process powershell -Verb RunAs -Wait -ArgumentList "
                f"'-NoProfile','-ExecutionPolicy','Bypass','-File','{script}'",
            ],
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "could not launch the elevated PowerShell window"
    if rule_exists():
        return True, "firewall rule created"
    return False, (
        "rule not found afterwards - you may have declined the UAC prompt, or "
        "policy blocks local firewall rules"
    )
