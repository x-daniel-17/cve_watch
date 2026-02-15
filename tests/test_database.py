"""Tests for the database module."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from src.database import Database
from src.models import CVERecord, Severity


class TestDatabase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.tmp_dir) / "test_cache.db"
        self.db = Database(db_path=self.db_path)

    def tearDown(self) -> None:
        self.db.close()

    def test_cache_and_retrieve_cves(self) -> None:
        cves = [
            CVERecord(
                cve_id="CVE-2024-0001",
                description="Test vulnerability",
                severity=Severity.HIGH,
                score=8.5,
                published=datetime(2024, 1, 15),
            ),
        ]
        self.db.cache_cves("testapp", "1.0.0", cves)

        cached = self.db.get_cached_cves("testapp", "1.0.0")
        assert cached is not None
        assert len(cached) == 1
        assert cached[0].cve_id == "CVE-2024-0001"
        assert cached[0].severity == Severity.HIGH
        assert cached[0].score == 8.5

    def test_cache_miss(self) -> None:
        cached = self.db.get_cached_cves("nonexistent", "1.0.0")
        assert cached is None

    def test_empty_cves_still_cached(self) -> None:
        self.db.cache_cves("safeapp", "2.0.0", [])
        cached = self.db.get_cached_cves("safeapp", "2.0.0")
        assert cached is not None
        assert cached == []

    def test_save_scan_result(self) -> None:
        self.db.save_scan_result(
            total_apps=10,
            apps_scanned=8,
            total_cves=3,
            critical_count=1,
            vulnerable_apps_summary=[{"name": "test", "cve_count": 3}],
        )
        last_scan = self.db.get_last_scan_time()
        assert last_scan is not None


if __name__ == "__main__":
    unittest.main()
