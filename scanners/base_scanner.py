from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


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
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class BaseScanner:
    def __init__(self, session):
        self.session = session
        self.findings: list[Finding] = []

    def scan(self) -> list[Finding]:
        raise NotImplementedError

    def add_finding(self, **kwargs) -> Finding:
        finding = Finding(**kwargs)
        self.findings.append(finding)
        return finding
