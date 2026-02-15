from __future__ import annotations

import subprocess

from src.models import ScanResult, Severity, VulnerableApp


def send_scan_summary(result: ScanResult) -> None:
    if not result.vulnerable_apps:
        _notify(
            title="CVE Watch - Scan Complete",
            message=f"Scanned {result.apps_scanned} apps. No known vulnerabilities found!",
        )
        return

    critical = result.critical_count
    total_cves = result.total_cves
    vuln_count = len(result.vulnerable_apps)

    if critical > 0:
        message = (
            f"⚠️ {critical} CRITICAL vulnerabilities found! "
            f"{total_cves} total CVEs across {vuln_count} apps."
        )
    else:
        message = (
            f"Found {total_cves} CVEs across {vuln_count} apps. "
            f"Run 'cve-watch' for details."
        )

    _notify(
        title="CVE Watch - Vulnerabilities Detected",
        message=message,
        sound=critical > 0,
    )


def send_new_cve_alert(app: VulnerableApp) -> None:
    severity = app.max_severity
    cve_ids = ", ".join(c.cve_id for c in app.cves[:3])
    extra = f" (+{len(app.cves) - 3} more)" if len(app.cves) > 3 else ""

    _notify(
        title=f"CVE Alert: {app.app.display_name}",
        message=f"[{severity.value}] {cve_ids}{extra}",
        sound=severity in (Severity.CRITICAL, Severity.HIGH),
    )


def _notify(title: str, message: str, sound: bool = False) -> None:
    sound_clause = 'sound name "Basso"' if sound else ""
    script = (
        f'display notification "{_escape(message)}" '
        f'with title "{_escape(title)}" {sound_clause}'
    )
    try:
        subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')
