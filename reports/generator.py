import json
from datetime import datetime
from collections import Counter
from scanners.base_scanner import Finding, Status, Severity


class ReportGenerator:
    def __init__(self, findings: list[Finding]):
        self.findings = findings
        self.timestamp = datetime.utcnow().isoformat()

    def summary(self) -> dict:
        total = len(self.findings)
        by_status = Counter(f.status.value for f in self.findings)
        by_severity = Counter(
            f.severity.value for f in self.findings if f.status == Status.FAIL
        )

        return {
            "scan_timestamp": self.timestamp,
            "total_checks": total,
            "passed": by_status.get("PASS", 0),
            "failed": by_status.get("FAIL", 0),
            "errors": by_status.get("ERROR", 0),
            "score": round(
                (by_status.get("PASS", 0) / total * 100) if total > 0 else 0, 1
            ),
            "failures_by_severity": dict(by_severity),
        }

    def to_json(self, filepath: str):
        report = {
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
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        return filepath

    def to_csv(self, filepath: str):
        import csv

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Check ID", "Check Name", "Status", "Severity",
                "Resource ID", "Resource Type", "Region", "Description", "Remediation",
            ])
            for finding in self.findings:
                writer.writerow([
                    finding.check_id, finding.check_name, finding.status.value,
                    finding.severity.value, finding.resource_id, finding.resource_type,
                    finding.region, finding.description, finding.remediation,
                ])
        return filepath
