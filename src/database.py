from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from src.models import CVERecord, Severity

DEFAULT_DB_PATH = Path.home() / ".cve_watch" / "cache.db"
CACHE_TTL_HOURS = 24 * 7


class Database:

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                app_name TEXT NOT NULL,
                app_version TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                score REAL,
                published TEXT,
                last_modified TEXT,
                affected_versions TEXT,
                cached_at TEXT NOT NULL,
                PRIMARY KEY (app_name, app_version, cve_id)
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_apps INTEGER,
                apps_scanned INTEGER,
                total_cves INTEGER,
                critical_count INTEGER,
                vulnerable_apps_json TEXT
            );

            CREATE TABLE IF NOT EXISTS lookup_cache (
                app_name TEXT NOT NULL,
                app_version TEXT NOT NULL,
                cached_at TEXT NOT NULL,
                PRIMARY KEY (app_name, app_version)
            );

            CREATE INDEX IF NOT EXISTS idx_cve_cache_app
                ON cve_cache(app_name, app_version);
            CREATE INDEX IF NOT EXISTS idx_lookup_cache_time
                ON lookup_cache(cached_at);
        """)
        self.conn.commit()

    def get_cached_cves(
        self, app_name: str, app_version: str
    ) -> list[CVERecord] | None:
        cursor = self.conn.execute(
            "SELECT cached_at FROM lookup_cache WHERE app_name = ? AND app_version = ?",
            (app_name.lower(), app_version),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        cached_at = datetime.fromisoformat(row["cached_at"])
        if datetime.now() - cached_at > timedelta(hours=CACHE_TTL_HOURS):
            return None

        cursor = self.conn.execute(
            "SELECT * FROM cve_cache WHERE app_name = ? AND app_version = ?",
            (app_name.lower(), app_version),
        )
        return [self._row_to_cve(r) for r in cursor.fetchall()]

    def cache_cves(
        self, app_name: str, app_version: str, cves: list[CVERecord]
    ) -> None:
        now = datetime.now().isoformat()
        app_key = app_name.lower()

        self.conn.execute(
            "DELETE FROM cve_cache WHERE app_name = ? AND app_version = ?",
            (app_key, app_version),
        )
        self.conn.execute(
            "DELETE FROM lookup_cache WHERE app_name = ? AND app_version = ?",
            (app_key, app_version),
        )

        for cve in cves:
            self.conn.execute(
                """INSERT OR REPLACE INTO cve_cache
                   (app_name, app_version, cve_id, description, severity,
                    score, published, last_modified, affected_versions, cached_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    app_key,
                    app_version,
                    cve.cve_id,
                    cve.description,
                    cve.severity.value,
                    cve.score,
                    cve.published.isoformat() if cve.published else None,
                    cve.last_modified.isoformat() if cve.last_modified else None,
                    json.dumps(cve.affected_versions),
                    now,
                ),
            )

        self.conn.execute(
            "INSERT OR REPLACE INTO lookup_cache (app_name, app_version, cached_at) VALUES (?, ?, ?)",
            (app_key, app_version, now),
        )
        self.conn.commit()

    def save_scan_result(
        self,
        total_apps: int,
        apps_scanned: int,
        total_cves: int,
        critical_count: int,
        vulnerable_apps_summary: list[dict],
    ) -> None:
        self.conn.execute(
            """INSERT INTO scan_history
               (timestamp, total_apps, apps_scanned, total_cves,
                critical_count, vulnerable_apps_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                total_apps,
                apps_scanned,
                total_cves,
                critical_count,
                json.dumps(vulnerable_apps_summary),
            ),
        )
        self.conn.commit()

    def get_last_scan_time(self) -> datetime | None:
        cursor = self.conn.execute(
            "SELECT timestamp FROM scan_history ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if row:
            return datetime.fromisoformat(row["timestamp"])
        return None

    def _row_to_cve(self, row: sqlite3.Row) -> CVERecord:
        return CVERecord(
            cve_id=row["cve_id"],
            description=row["description"] or "",
            severity=Severity(row["severity"]) if row["severity"] else Severity.UNKNOWN,
            score=row["score"],
            published=datetime.fromisoformat(row["published"]) if row["published"] else None,
            last_modified=datetime.fromisoformat(row["last_modified"]) if row["last_modified"] else None,
            affected_versions=json.loads(row["affected_versions"]) if row["affected_versions"] else [],
        )

    def close(self) -> None:
        self.conn.close()
