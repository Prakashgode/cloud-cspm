from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class Finding:
    check_id: str
    check_name: str
    status: Status
    severity: Severity
    resource_id: str
    resource_type: str
    region: str
    description: str
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class BaseScanner:
    def __init__(self, session: Any):
        self.session = session
        self.findings: list[Finding] = []

    def scan(self) -> list[Finding]:
        raise NotImplementedError

    def add_finding(self, **kwargs: Any) -> Finding:
        finding = Finding(**kwargs)
        self.findings.append(finding)
        return finding
