"""Tests for the models module."""

from __future__ import annotations

import unittest
from datetime import datetime

from src.models import (
    CVERecord,
    InstalledApp,
    ScanResult,
    Severity,
    VulnerableApp,
)


class TestSeverity(unittest.TestCase):
    def test_sort_order(self) -> None:
        assert Severity.CRITICAL.sort_order > Severity.HIGH.sort_order
        assert Severity.HIGH.sort_order > Severity.MEDIUM.sort_order
        assert Severity.MEDIUM.sort_order > Severity.LOW.sort_order

    def test_color_exists(self) -> None:
        for s in Severity:
            assert isinstance(s.color, str)


class TestVulnerableApp(unittest.TestCase):
    def test_max_severity(self) -> None:
        app = InstalledApp(name="test", version="1.0", source="homebrew")
        cves = [
            CVERecord(cve_id="CVE-1", description="", severity=Severity.LOW),
            CVERecord(cve_id="CVE-2", description="", severity=Severity.CRITICAL),
            CVERecord(cve_id="CVE-3", description="", severity=Severity.MEDIUM),
        ]
        va = VulnerableApp(app=app, cves=cves)
        assert va.max_severity == Severity.CRITICAL
        assert va.cve_count == 3

    def test_max_score(self) -> None:
        app = InstalledApp(name="test", version="1.0", source="homebrew")
        cves = [
            CVERecord(cve_id="CVE-1", description="", severity=Severity.LOW, score=3.0),
            CVERecord(cve_id="CVE-2", description="", severity=Severity.HIGH, score=9.1),
        ]
        va = VulnerableApp(app=app, cves=cves)
        assert va.max_score == 9.1


class TestScanResult(unittest.TestCase):
    def test_total_cves(self) -> None:
        app = InstalledApp(name="a", version="1.0", source="homebrew")
        va = VulnerableApp(
            app=app,
            cves=[
                CVERecord(cve_id="CVE-1", description="", severity=Severity.HIGH),
                CVERecord(cve_id="CVE-2", description="", severity=Severity.LOW),
            ],
        )
        result = ScanResult(
            timestamp=datetime.now(),
            total_apps=5,
            apps_scanned=5,
            vulnerable_apps=[va],
        )
        assert result.total_cves == 2


if __name__ == "__main__":
    unittest.main()
