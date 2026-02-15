from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from src.dashboard import display_scan_results
from src.database import Database
from src.models import ScanResult, VulnerableApp
from src.notifier import send_scan_summary, send_new_cve_alert
from src.nvd_client import NVDClient
from src.scanner import scan_all_apps

console = Console()
logger = logging.getLogger("cve_watch")

WATCH_INTERVAL_HOURS = 6


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CVE Watch - macOS Application Vulnerability Monitor"
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run scan only (no dashboard)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Run in watch mode (periodic checks)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the native macOS GUI",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output scan results as JSON (for GUI bridge)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=os.environ.get("NVD_API_KEY"),
        help="NVD API key (or set NVD_API_KEY env var)",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Disable macOS notifications",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.gui:
        _launch_gui()
        return

    if args.json:
        result, all_apps = asyncio.run(_run_scan(args, quiet=True))
        _output_json(result, all_apps)
        return

    if args.watch:
        _run_watch_mode(args)
    else:
        result, _all_apps = asyncio.run(_run_scan(args))
        if not args.scan:
            display_scan_results(result)
        if not args.no_notify:
            send_scan_summary(result)


def _launch_gui() -> None:
    project_root = Path(__file__).resolve().parent.parent
    gui_binary = project_root / "gui" / ".build" / "release" / "CVEWatchGUI"

    if not gui_binary.exists():
        console.print("[bold]Building GUI...[/bold]")
        try:
            subprocess.run(
                ["swift", "build", "-c", "release"],
                cwd=str(project_root / "gui"),
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            console.print(f"[red]Failed to build GUI: {e}[/red]")
            console.print("Make sure Xcode and Swift are installed.")
            sys.exit(1)

    try:
        subprocess.Popen(
            [str(gui_binary)],
            cwd=str(project_root),
        )
        console.print("[green]GUI launched.[/green]")
    except OSError as e:
        console.print(f"[red]Failed to launch GUI: {e}[/red]")
        sys.exit(1)


def _run_watch_mode(args: argparse.Namespace) -> None:
    console.print(
        f"[bold cyan]CVE Watch[/bold cyan] - Watch mode "
        f"(checking every {WATCH_INTERVAL_HOURS} hours)"
    )
    console.print("Press Ctrl+C to stop.\n")

    try:
        while True:
            result, _all = asyncio.run(_run_scan(args))
            display_scan_results(result)
            if not args.no_notify:
                send_scan_summary(result)

            console.print(
                f"\n[dim]Next scan in {WATCH_INTERVAL_HOURS} hours...[/dim]"
            )
            time.sleep(WATCH_INTERVAL_HOURS * 3600)
    except KeyboardInterrupt:
        console.print("\n[dim]Watch mode stopped.[/dim]")


async def _run_scan(
    args: argparse.Namespace, quiet: bool = False
) -> tuple[ScanResult, list]:
    db = Database()
    nvd = NVDClient(api_key=args.api_key)
    errors: list[str] = []

    if not quiet:
        console.print("[bold]Discovering installed applications...[/bold]")
    apps = scan_all_apps()
    if not quiet:
        console.print(f"  Found [cyan]{len(apps)}[/cyan] installed applications.\n")

    if not apps:
        await nvd.close()
        return ScanResult(
            timestamp=datetime.now(),
            total_apps=0,
            apps_scanned=0,
            errors=["No installed applications found."],
        ), []

    vulnerable_apps: list[VulnerableApp] = []
    cached_apps: list[tuple[InstalledApp, list]] = []
    to_query: list[InstalledApp] = []

    for app in apps:
        cached = db.get_cached_cves(app.name, app.version)
        if cached is not None:
            cached_apps.append((app, cached))
        elif nvd.has_known_cpe(app):
            to_query.append(app)
        else:
            db.cache_cves(app.name, app.version, [])
            cached_apps.append((app, []))

    for app, cves in cached_apps:
        if cves:
            vulnerable_apps.append(VulnerableApp(app=app, cves=cves))

    scanned = len(cached_apps)
    total_to_scan = len(cached_apps) + len(to_query)

    if not quiet:
        console.print(
            f"  [dim]{len(cached_apps)} cached, "
            f"{len(to_query)} to query NVD "
            f"({len(apps) - len(cached_apps) - len(to_query)} skipped)[/dim]\n"
        )

    if to_query:
        if quiet:
            def _progress_quiet(current: int, total: int, name: str) -> None:
                idx = len(cached_apps) + current
                print(
                    f"PROGRESS:{idx}:{total_to_scan}:{name}",
                    file=sys.stderr, flush=True,
                )

            batch_results = await nvd.search_cves_batch(to_query, _progress_quiet)
            for app in to_query:
                key = f"{app.name}:{app.version}"
                cves = batch_results.get(key, [])
                db.cache_cves(app.name, app.version, cves)
                if cves:
                    vulnerable_apps.append(VulnerableApp(app=app, cves=cves))
                scanned += 1
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "Querying NVD...", total=len(to_query)
                )

                def _progress_rich(current: int, total: int, name: str) -> None:
                    progress.update(
                        task,
                        completed=current,
                        description=f"Checking [cyan]{name}[/cyan]...",
                    )

                batch_results = await nvd.search_cves_batch(
                    to_query, _progress_rich
                )
                for app in to_query:
                    key = f"{app.name}:{app.version}"
                    cves = batch_results.get(key, [])
                    db.cache_cves(app.name, app.version, cves)
                    if cves:
                        vulnerable_apps.append(
                            VulnerableApp(app=app, cves=cves)
                        )
                    scanned += 1
    elif quiet:
        print(
            f"PROGRESS:{total_to_scan}:{total_to_scan}:done",
            file=sys.stderr, flush=True,
        )

    result = ScanResult(
        timestamp=datetime.now(),
        total_apps=len(apps),
        apps_scanned=scanned,
        vulnerable_apps=vulnerable_apps,
        errors=errors,
    )

    db.save_scan_result(
        total_apps=result.total_apps,
        apps_scanned=result.apps_scanned,
        total_cves=result.total_cves,
        critical_count=result.critical_count,
        vulnerable_apps_summary=[
            {
                "name": v.app.name,
                "version": v.app.version,
                "cve_count": v.cve_count,
                "max_severity": v.max_severity.value,
            }
            for v in vulnerable_apps
        ],
    )

    db.close()
    await nvd.close()
    return result, apps


def _output_json(result: ScanResult, all_apps: list) -> None:
    data = {
        "timestamp": result.timestamp.isoformat(),
        "total_apps": result.total_apps,
        "apps_scanned": result.apps_scanned,
        "all_apps": [
            {
                "name": app.name,
                "version": app.version,
                "source": app.source,
                "bundle_id": app.bundle_id,
                "path": app.path,
            }
            for app in all_apps
        ],
        "vulnerable_apps": [
            {
                "name": v.app.name,
                "version": v.app.version,
                "source": v.app.source,
                "cves": [
                    {
                        "cve_id": c.cve_id,
                        "description": c.description,
                        "severity": c.severity.value,
                        "score": c.score,
                        "published": c.published.isoformat() if c.published else None,
                        "last_modified": c.last_modified.isoformat() if c.last_modified else None,
                        "references": c.references,
                    }
                    for c in v.cves
                ],
            }
            for v in result.vulnerable_apps
        ],
        "errors": result.errors,
    }
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
