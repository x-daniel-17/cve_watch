from __future__ import annotations

import os
import plistlib
import re
import subprocess
from pathlib import Path

from src.models import InstalledApp


def scan_all_apps() -> list[InstalledApp]:
    apps: list[InstalledApp] = []
    apps.extend(scan_homebrew_formulae())
    apps.extend(scan_homebrew_casks())
    apps.extend(scan_applications_folder())

    seen: dict[str, InstalledApp] = {}
    for app in apps:
        key = app.name.lower()
        if key not in seen or app.source.startswith("homebrew"):
            seen[key] = app
    return sorted(seen.values(), key=lambda a: a.name.lower())


def scan_homebrew_formulae() -> list[InstalledApp]:
    apps: list[InstalledApp] = []
    try:
        result = subprocess.run(
            ["brew", "list", "--formula", "--versions"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return apps

        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[-1]  # Use the latest version listed
                apps.append(InstalledApp(
                    name=name,
                    version=version,
                    source="homebrew",
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return apps


def scan_homebrew_casks() -> list[InstalledApp]:
    apps: list[InstalledApp] = []
    try:
        result = subprocess.run(
            ["brew", "list", "--cask", "--versions"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return apps

        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[-1]
                apps.append(InstalledApp(
                    name=name,
                    version=version,
                    source="homebrew-cask",
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return apps


def scan_applications_folder() -> list[InstalledApp]:
    apps: list[InstalledApp] = []
    app_dirs = [
        Path("/Applications"),
        Path.home() / "Applications",
    ]

    for app_dir in app_dirs:
        if not app_dir.exists():
            continue
        for entry in app_dir.iterdir():
            if entry.suffix == ".app" and entry.is_dir():
                app = _parse_app_bundle(entry)
                if app:
                    apps.append(app)
    return apps


def _parse_app_bundle(app_path: Path) -> InstalledApp | None:
    plist_path = app_path / "Contents" / "Info.plist"
    if not plist_path.exists():
        return None

    try:
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)

        name = plist.get("CFBundleName") or app_path.stem
        version = (
            plist.get("CFBundleShortVersionString")
            or plist.get("CFBundleVersion")
            or "unknown"
        )
        bundle_id = plist.get("CFBundleIdentifier")

        name = _normalize_app_name(name)

        return InstalledApp(
            name=name,
            version=version,
            source="applications",
            bundle_id=bundle_id,
            path=str(app_path),
        )
    except Exception:
        return None


def _normalize_app_name(name: str) -> str:
    name = re.sub(r"\.app$", "", name, flags=re.IGNORECASE)
    name = re.sub(r"\s+(Helper|Agent|Updater)$", "", name)
    return name.strip()
