from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.models import ScanResult, Severity, VulnerableApp

console = Console()


def display_scan_results(result: ScanResult) -> None:
    console.clear()
    _display_header(result)
    _display_summary(result)

    if result.vulnerable_apps:
        _display_vulnerable_apps_table(result.vulnerable_apps)
        _display_cve_details(result.vulnerable_apps)
    else:
        console.print()
        console.print(
            Panel(
                "[bold green]No known vulnerabilities found![/bold green]\n"
                "All scanned applications appear to be safe.",
                title="Results",
                border_style="green",
            )
        )

    if result.errors:
        _display_errors(result.errors)

    console.print()


def display_scanning_progress(app_name: str, current: int, total: int) -> None:
    console.print(
        f"  [{current}/{total}] Checking [cyan]{app_name}[/cyan]...",
        end="\r",
    )


def _display_header(result: ScanResult) -> None:
    console.print()
    console.print(
        Panel(
            "[bold cyan]CVE Watch[/bold cyan] - macOS Vulnerability Monitor\n"
            f"Scan completed: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            border_style="cyan",
        )
    )


def _display_summary(result: ScanResult) -> None:
    total_cves = result.total_cves
    critical = result.critical_count
    vuln_count = len(result.vulnerable_apps)

    if critical > 0:
        status = f"[bold red]⚠ {critical} CRITICAL[/bold red]"
    elif total_cves > 0:
        status = f"[yellow]⚡ {total_cves} CVEs found[/yellow]"
    else:
        status = "[green]✓ No vulnerabilities[/green]"

    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column("Key", style="bold")
    summary.add_column("Value")
    summary.add_row("Apps Discovered", str(result.total_apps))
    summary.add_row("Apps Scanned", str(result.apps_scanned))
    summary.add_row("Vulnerable Apps", str(vuln_count))
    summary.add_row("Total CVEs", str(total_cves))
    summary.add_row("Status", status)

    console.print(Panel(summary, title="Scan Summary", border_style="blue"))


def _display_vulnerable_apps_table(apps: list[VulnerableApp]) -> None:
    sorted_apps = sorted(
        apps, key=lambda a: a.max_severity.sort_order, reverse=True
    )

    table = Table(title="Vulnerable Applications", show_lines=True)
    table.add_column("Application", style="cyan", no_wrap=True)
    table.add_column("Version", style="dim")
    table.add_column("Source", style="dim")
    table.add_column("CVEs", justify="center")
    table.add_column("Max Severity", justify="center")
    table.add_column("Max Score", justify="center")

    for vuln_app in sorted_apps:
        severity = vuln_app.max_severity
        severity_text = Text(severity.value, style=severity.color)
        score = vuln_app.max_score
        score_text = Text(
            f"{score:.1f}" if score else "N/A",
            style=severity.color,
        )

        table.add_row(
            vuln_app.app.name,
            vuln_app.app.version,
            vuln_app.app.source,
            str(vuln_app.cve_count),
            severity_text,
            score_text,
        )

    console.print()
    console.print(table)


def _display_cve_details(apps: list[VulnerableApp]) -> None:
    console.print()
    console.print("[bold]CVE Details[/bold]")
    console.print("─" * 80)

    sorted_apps = sorted(
        apps, key=lambda a: a.max_severity.sort_order, reverse=True
    )

    for vuln_app in sorted_apps:
        console.print()
        console.print(
            f"[bold cyan]{vuln_app.app.name}[/bold cyan] "
            f"[dim]{vuln_app.app.version}[/dim]"
        )

        sorted_cves = sorted(
            vuln_app.cves,
            key=lambda c: c.severity.sort_order,
            reverse=True,
        )

        for cve in sorted_cves:
            severity_text = Text(
                f"[{cve.severity.value}]", style=cve.severity.color
            )
            score_text = f"Score: {cve.display_score}"
            date_text = (
                f"Published: {cve.published.strftime('%Y-%m-%d')}"
                if cve.published
                else ""
            )

            console.print(f"  [bold]{cve.cve_id}[/bold] ", end="")
            console.print(severity_text, end=" ")
            console.print(f"{score_text}  {date_text}")

            desc = cve.description
            if len(desc) > 200:
                desc = desc[:200] + "..."
            console.print(f"    {desc}", style="dim")

            if cve.references:
                console.print(
                    f"    [link]{cve.references[0]}[/link]", style="dim blue"
                )


def _display_errors(errors: list[str]) -> None:
    console.print()
    error_panel = "\n".join(f"• {e}" for e in errors)
    console.print(
        Panel(error_panel, title="Errors", border_style="red", style="red")
    )
