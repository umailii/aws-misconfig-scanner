"""Shared data models for scanner findings."""

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"Unknown severity '{value}'. Choose from: {valid}") from exc


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: Severity
    resource: str
    region: str
    title: str
    remediation: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data
