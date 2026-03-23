import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from scanners.base_scanner import Finding, Severity, Status


class ReportGenerator:
    def __init__(self, findings: list[Finding], timestamp: str | None = None):
        self.findings = findings
        self.timestamp = timestamp or datetime.now(UTC).isoformat()

    def summary(self) -> dict[str, Any]:
        total = len(self.findings)
        by_status = Counter(f.status.value for f in self.findings)
        by_severity = Counter(f.severity.value for f in self.findings if f.status == Status.FAIL)

        return {
            "scan_timestamp": self.timestamp,
            "total_checks": total,
            "passed": by_status.get("PASS", 0),
            "failed": by_status.get("FAIL", 0),
            "errors": by_status.get("ERROR", 0),
            "score": round((by_status.get("PASS", 0) / total * 100) if total > 0 else 0, 1),
            "failures_by_severity": dict(by_severity),
        }

    def json_report(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "findings": [
                {
                    "check_id": f.check_id,
                    "check_name": f.check_name,
                    "status": f.status.value,
                    "severity": f.severity.value,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type,
                    "region": f.region,
                    "description": f.description,
                    "remediation": f.remediation,
                    "timestamp": f.timestamp,
                }
                for f in self.findings
            ],
        }

    def to_json(self, filepath: str):
        report = self.json_report()
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        return filepath

    def to_csv(self, filepath: str):
        import csv

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Check ID",
                    "Check Name",
                    "Status",
                    "Severity",
                    "Resource ID",
                    "Resource Type",
                    "Region",
                    "Description",
                    "Remediation",
                ]
            )
            for finding in self.findings:
                writer.writerow(
                    [
                        finding.check_id,
                        finding.check_name,
                        finding.status.value,
                        finding.severity.value,
                        finding.resource_id,
                        finding.resource_type,
                        finding.region,
                        finding.description,
                        finding.remediation,
                    ]
                )
        return filepath

    def to_sarif(self, filepath: str):
        summary = self.summary()
        rules = [self._sarif_rule(finding) for finding in self._unique_rules()]
        results = [
            self._sarif_result(finding)
            for finding in self.findings
            if finding.status in {Status.FAIL, Status.ERROR}
        ]

        sarif_report = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cloud-cspm",
                            "informationUri": "https://github.com/Prakashgode/cloud-cspm",
                            "rules": rules,
                        }
                    },
                    "automationDetails": {"id": "cloud-cspm/local-scan"},
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": self.timestamp,
                            "properties": {"summary": summary},
                        }
                    ],
                    "results": results,
                    "properties": {
                        "summary": summary,
                        "actionable_findings": len(results),
                    },
                }
            ],
        }

        with open(filepath, "w") as f:
            json.dump(sarif_report, f, indent=2)
        return filepath

    def _unique_rules(self) -> list[Finding]:
        rules_by_id: dict[str, Finding] = {}
        for finding in self.findings:
            rules_by_id.setdefault(finding.check_id, finding)
        return list(rules_by_id.values())

    def _sarif_rule(self, finding: Finding) -> dict[str, Any]:
        return {
            "id": finding.check_id,
            "name": finding.check_name,
            "shortDescription": {"text": finding.check_name},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.remediation or "Review the finding description and remediate."},
            "defaultConfiguration": {"level": self._sarif_level(finding)},
            "properties": {
                "tags": ["security", "cloud", "cloud-cspm"],
                "precision": "high",
                "security-severity": self._security_severity(finding.severity),
                "resource_type": finding.resource_type,
            },
        }

    def _sarif_result(self, finding: Finding) -> dict[str, Any]:
        return {
            "ruleId": finding.check_id,
            "level": self._sarif_level(finding),
            "kind": "review" if finding.status == Status.ERROR else "fail",
            "message": {
                "text": f"{finding.description} Resource: {finding.resource_id} ({finding.region})."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self._sarif_resource_uri(finding)},
                        "region": {"startLine": 1},
                    },
                    "message": {"text": f"{finding.resource_type} {finding.resource_id} in {finding.region}"},
                    "logicalLocations": [
                        {
                            "name": finding.resource_id,
                            "kind": "cloud-resource",
                            "fullyQualifiedName": (
                                f"{finding.region}:{finding.resource_type}:{finding.resource_id}"
                            ),
                        }
                    ],
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": self._sarif_fingerprint(finding)
            },
            "properties": {
                "status": finding.status.value,
                "severity": finding.severity.value,
                "resource_id": finding.resource_id,
                "resource_type": finding.resource_type,
                "region": finding.region,
                "timestamp": finding.timestamp,
                "remediation": finding.remediation,
            },
        }

    def _sarif_level(self, finding: Finding) -> str:
        if finding.status == Status.ERROR or finding.severity in {Severity.CRITICAL, Severity.HIGH}:
            return "error"
        if finding.severity == Severity.MEDIUM:
            return "warning"
        return "note"

    def _security_severity(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "9.0",
            Severity.HIGH: "8.0",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
        }
        return mapping[severity]

    def _sarif_resource_uri(self, finding: Finding) -> str:
        region = quote(finding.region, safe="")
        resource_type = quote(finding.resource_type, safe="")
        resource_id = quote(finding.resource_id, safe="")
        return f"aws-resource://{region}/{resource_type}/{resource_id}"

    def _sarif_fingerprint(self, finding: Finding) -> str:
        payload = "|".join(
            [
                finding.check_id,
                finding.resource_type,
                finding.resource_id,
                finding.region,
                finding.status.value,
            ]
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        return f"{digest}:1"
