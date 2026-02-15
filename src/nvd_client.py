from __future__ import annotations

import asyncio
import logging
import re
import typing
from datetime import datetime, timedelta, timezone

import httpx

from src.models import CVERecord, InstalledApp, Severity

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RATE_LIMIT_DELAY = 6.5
RATE_LIMIT_DELAY_WITH_KEY = 0.6
BATCH_SIZE_NO_KEY = 5
BATCH_SIZE_WITH_KEY = 40
BATCH_WINDOW = 31
BATCH_WINDOW_WITH_KEY = 31
CVE_MAX_AGE_YEARS = 4

# App name → CPE vendor:product
APP_NAME_MAP: dict[str, tuple[str, str]] = {
    "firefox": ("mozilla", "firefox"),
    "google chrome": ("google", "chrome"),
    "chrome": ("google", "chrome"),
    "safari": ("apple", "safari"),
    "visual studio code": ("microsoft", "visual_studio_code"),
    "vscode": ("microsoft", "visual_studio_code"),
    "slack": ("slack", "slack"),
    "zoom": ("zoom", "zoom"),
    "docker": ("docker", "docker_desktop"),
    "docker desktop": ("docker", "docker_desktop"),
    "vlc": ("videolan", "vlc_media_player"),
    "iterm2": ("iterm2", "iterm2"),
    "iterm": ("iterm2", "iterm2"),
    "python": ("python", "python"),
    "node": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "git": ("git-scm", "git"),
    "curl": ("haxx", "curl"),
    "wget": ("gnu", "wget"),
    "openssl": ("openssl", "openssl"),
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "postgresql": ("postgresql", "postgresql"),
    "mysql": ("oracle", "mysql"),
    "redis": ("redis", "redis"),
    "sqlite": ("sqlite", "sqlite"),
    "ffmpeg": ("ffmpeg", "ffmpeg"),
    "imagemagick": ("imagemagick", "imagemagick"),
    "7-zip": ("7-zip", "7-zip"),
    "the unarchiver": ("macpaw", "the_unarchiver"),
    "wireshark": ("wireshark", "wireshark"),
    "gimp": ("gimp", "gimp"),
    "libreoffice": ("libreoffice", "libreoffice"),
    "thunderbird": ("mozilla", "thunderbird"),
    "telegram": ("telegram", "telegram_desktop"),
    "signal": ("signal", "signal-desktop"),
    "1password": ("1password", "1password"),
    "keepassxc": ("keepassxc", "keepassxc"),
}


class NVDClient:

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self.delay = RATE_LIMIT_DELAY_WITH_KEY if api_key else RATE_LIMIT_DELAY
        self.batch_size = BATCH_SIZE_WITH_KEY if api_key else BATCH_SIZE_NO_KEY
        self.batch_window = BATCH_WINDOW_WITH_KEY if api_key else BATCH_WINDOW
        self._last_request_time: float = 0
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def has_known_cpe(self, app: InstalledApp) -> bool:
        return app.name.lower() in APP_NAME_MAP

    async def search_cves_for_app(self, app: InstalledApp) -> list[CVERecord]:
        cpe_results = await self._search_by_cpe(app)
        if cpe_results is not None:
            return cpe_results
        return []

    async def search_cves_batch(
        self, apps: list[InstalledApp],
        progress_callback: typing.Callable[[int, int, str], None] | None = None,
    ) -> dict[str, list[CVERecord]]:
        results: dict[str, list[CVERecord]] = {}
        total = len(apps)

        for batch_start in range(0, total, self.batch_size):
            batch = apps[batch_start:batch_start + self.batch_size]
            tasks = [
                self._search_single(app)
                for app in batch
            ]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for app, result in zip(batch, batch_results):
                key = f"{app.name}:{app.version}"
                if isinstance(result, Exception):
                    logger.warning("Error scanning %s: %s", app.name, result)
                    results[key] = []
                else:
                    results[key] = result

                if progress_callback:
                    idx = batch_start + batch.index(app) + 1
                    progress_callback(idx, total, app.name)

            if batch_start + self.batch_size < total:
                logger.debug("Waiting %ds for rate limit window...", self.batch_window)
                await asyncio.sleep(self.batch_window)

        return results

    async def _search_single(self, app: InstalledApp) -> list[CVERecord]:
        return await self.search_cves_for_app(app)

    async def _search_by_cpe(self, app: InstalledApp) -> list[CVERecord] | None:
        name_lower = app.name.lower()
        mapping = APP_NAME_MAP.get(name_lower)
        if mapping is None:
            return None

        vendor, product = mapping
        cpe_name = f"cpe:2.3:a:{vendor}:{product}:{app.version}:*:*:*:*:*:*:*"

        params = {
            "cpeName": cpe_name,
            "resultsPerPage": "50",
        }
        raw_vulns = await self._fetch_raw(params)

        validated: list[dict] = []
        for vuln in raw_vulns:
            cve_data = vuln.get("cve", {})
            if self._cve_affects_version(cve_data, vendor, product, app.version):
                validated.append(vuln)
            else:
                logger.debug(
                    "Filtered false-positive %s for %s %s",
                    cve_data.get("id", "?"), app.name, app.version,
                )

        return self._filter_old_cves(
            self._parse_response({"vulnerabilities": validated})
        )

    async def _fetch_raw(self, params: dict[str, str]) -> list[dict]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            client = await self._get_client()
            response = await client.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
            )

            if response.status_code == 403:
                logger.warning("NVD API rate limit exceeded, backing off...")
                await asyncio.sleep(30)
                return []

            if response.status_code != 200:
                logger.warning(
                    "NVD API returned status %d for params %s",
                    response.status_code,
                    params,
                )
                return []

            data = response.json()
            return data.get("vulnerabilities", [])

        except (httpx.TimeoutException, httpx.ConnectError) as e:
            logger.warning("NVD API request failed: %s", e)
            return []

    _DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    _SEMVER_RE = re.compile(r"^\d+\.\d+")

    def _cve_affects_version(
        self,
        cve_data: dict,
        vendor: str,
        product: str,
        installed_version: str,
    ) -> bool:
        configs = cve_data.get("configurations", [])
        if not configs:
            return True

        installed_is_semver = bool(self._SEMVER_RE.match(installed_version))

        found_vendor_product = False
        explicitly_not_vulnerable = False

        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    parts = match.get("criteria", "").split(":")
                    if len(parts) < 6:
                        continue
                    cpe_vendor, cpe_product, cpe_version = parts[3], parts[4], parts[5]
                    if cpe_vendor != vendor or cpe_product != product:
                        continue

                    found_vendor_product = True

                    if not match.get("vulnerable", False):
                        explicitly_not_vulnerable = True
                        continue

                    if cpe_version == installed_version:
                        return True

                    if cpe_version == "*":
                        boundaries = [
                            match.get("versionStartIncluding"),
                            match.get("versionStartExcluding"),
                            match.get("versionEndIncluding"),
                            match.get("versionEndExcluding"),
                        ]
                        has_boundaries = any(b is not None for b in boundaries)

                        if not has_boundaries:
                            return True

                        if installed_is_semver:
                            for b in boundaries:
                                if b and self._DATE_RE.match(b):
                                    logger.debug(
                                        "Skipping %s: date boundary %s vs semver %s",
                                        cve_data.get("id", "?"), b, installed_version,
                                    )
                                    return False

                        return True

        if found_vendor_product and explicitly_not_vulnerable:
            return False

        return True

    def _parse_response(self, data: dict) -> list[CVERecord]:
        cves: list[CVERecord] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            severity, score = self._extract_severity(cve_data.get("metrics", {}))
            published = self._parse_date(cve_data.get("published"))
            last_modified = self._parse_date(cve_data.get("lastModified"))

            references = [
                ref.get("url", "")
                for ref in cve_data.get("references", [])
                if ref.get("url")
            ][:5]  # Limit to 5 references

            cves.append(CVERecord(
                cve_id=cve_id,
                description=description[:500],  # Truncate long descriptions
                severity=severity,
                score=score,
                published=published,
                last_modified=last_modified,
                references=references,
            ))

        return cves

    def _filter_old_cves(self, cves: list[CVERecord]) -> list[CVERecord]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=CVE_MAX_AGE_YEARS * 365)
        filtered: list[CVERecord] = []
        for cve in cves:
            pub_date = cve.published
            if pub_date is None:
                filtered.append(cve)
                continue
            if pub_date.tzinfo is None:
                pub_date = pub_date.replace(tzinfo=timezone.utc)
            if pub_date >= cutoff:
                filtered.append(cve)
            else:
                logger.debug("Filtered out old CVE %s (published %s)", cve.cve_id, pub_date)
        return filtered

    def _extract_severity(
        self, metrics: dict
    ) -> tuple[Severity, float | None]:
        for metric in metrics.get("cvssMetricV31", []):
            cvss = metric.get("cvssData", {})
            score = cvss.get("baseScore")
            severity_str = cvss.get("baseSeverity", "UNKNOWN").upper()
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.UNKNOWN
            return severity, score

        for metric in metrics.get("cvssMetricV30", []):
            cvss = metric.get("cvssData", {})
            score = cvss.get("baseScore")
            severity_str = cvss.get("baseSeverity", "UNKNOWN").upper()
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.UNKNOWN
            return severity, score

        for metric in metrics.get("cvssMetricV2", []):
            cvss = metric.get("cvssData", {})
            score = cvss.get("baseScore")
            if score is not None:
                if score >= 9.0:
                    return Severity.CRITICAL, score
                elif score >= 7.0:
                    return Severity.HIGH, score
                elif score >= 4.0:
                    return Severity.MEDIUM, score
                elif score > 0:
                    return Severity.LOW, score
                else:
                    return Severity.NONE, score

        return Severity.UNKNOWN, None

    def _parse_date(self, date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            return None
