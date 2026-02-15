from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @property
    def color(self) -> str:
        return {
            Severity.NONE: "dim",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
            Severity.UNKNOWN: "dim",
        }[self]

    @property
    def sort_order(self) -> int:
        return {
            Severity.NONE: 0,
            Severity.UNKNOWN: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


@dataclass
class InstalledApp:
    name: str
    version: str
    source: str
    bundle_id: str | None = None
    path: str | None = None

    @property
    def display_name(self) -> str:
        return f"{self.name} {self.version}"


@dataclass
class CVERecord:
    cve_id: str
    description: str
    severity: Severity
    score: float | None = None
    published: datetime | None = None
    last_modified: datetime | None = None
    affected_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def display_score(self) -> str:
        if self.score is not None:
            return f"{self.score:.1f}"
        return "N/A"


@dataclass
class VulnerableApp:
    app: InstalledApp
    cves: list[CVERecord] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.cves:
            return Severity.NONE
        return max(self.cves, key=lambda c: c.severity.sort_order).severity

    @property
    def max_score(self) -> float | None:
        scores = [c.score for c in self.cves if c.score is not None]
        return max(scores) if scores else None

    @property
    def cve_count(self) -> int:
        return len(self.cves)


@dataclass
class ScanResult:
    timestamp: datetime
    total_apps: int
    apps_scanned: int
    vulnerable_apps: list[VulnerableApp] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_cves(self) -> int:
        return sum(v.cve_count for v in self.vulnerable_apps)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for v in self.vulnerable_apps
            for c in v.cves
            if c.severity == Severity.CRITICAL
        )
