"""Data models shared by the checks, the CLI and the API."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Status(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


# Severity order used to pick the "worst" status of several findings.
_SEVERITY = {Status.OK: 0, Status.INFO: 1, Status.WARN: 2, Status.FAIL: 3}


def worst(*statuses: Status) -> Status:
    return max(statuses, key=_SEVERITY.__getitem__, default=Status.OK)


@dataclass
class Check:
    name: str
    status: Status
    message: str
    record: str | None = None


@dataclass
class MXRecord:
    priority: int
    host: str


@dataclass
class DomainReport:
    domain: str
    provider: str
    provider_kind: str
    mx: list[MXRecord] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    score: int = 0

    @property
    def risk(self) -> str:
        if self.score >= 80:
            return "low"
        if self.score >= 50:
            return "medium"
        return "high"

    def get(self, name: str) -> Check | None:
        return next((c for c in self.checks if c.name == name), None)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["risk"] = self.risk
        for check in data["checks"]:
            check["status"] = check["status"].value
        return data
