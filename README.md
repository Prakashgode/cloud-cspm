# Cloud CSPM

Scans AWS accounts for security misconfigurations against CIS benchmark controls. Covers IAM, S3, EC2, RDS, and CloudTrail.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Security-orange?logo=amazon-web-services&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

## What It Scans

| Scanner | Checks |
|---------|--------|
| IAM | Root MFA, password policy, unused credentials, key rotation, console user MFA |
| S3 | Public access blocks, encryption, versioning, access logging, SSL enforcement |
| EC2 | Open SSH/RDP, dangerous ports, default security groups, EBS encryption, public instances |
| RDS | Encryption, public access, Multi-AZ, auto upgrades, backup retention, deletion protection |
| Logging | CloudTrail enabled, log validation, KMS encryption, VPC flow logs |

## Setup

```bash
git clone https://github.com/Prakashgode/cloud-cspm.git
cd cloud-cspm
pip install -r requirements.txt
```

Needs Python 3.8+ and AWS credentials configured (`aws configure`). The `SecurityAudit` managed policy is enough for read-only access.

## Usage

```bash
# run everything
python cspm.py

# specific profile
python cspm.py --profile production

# specific scanners
python cspm.py --scanner iam --scanner s3

# filter by severity
python cspm.py --severity CRITICAL

# export results
python cspm.py --output report.json
python cspm.py --output report.csv
```

## Sample Output

```
╭──────────────────────────────────╮
│          Cloud CSPM              │
│  AWS Security Posture Management │
╰──────────────────────────────────╯

Authenticated as: arn:aws:iam::123456789012:user/security-auditor
Account: 123456789012

Scanning: IAM Security...
  4 passed | 2 failed
Scanning: S3 Bucket Security...
  3 passed | 5 failed
Scanning: EC2 & Network Security...
  6 passed | 3 failed

┌──────────────────── Security Findings ────────────────────┐
│ ID       │ Check              │ Status │ Severity │ ...   │
├──────────┼────────────────────┼────────┼──────────┤       │
│ CIS-1.1  │ Root Account MFA   │  FAIL  │ CRITICAL │       │
│ CIS-3.1  │ S3 Public Access   │  FAIL  │ CRITICAL │       │
│ CIS-4.1  │ Open SSH Port      │  FAIL  │ CRITICAL │       │
└──────────────────────────────────────────────────────────┘

╭──────────── Scan Summary ─────────────╮
│ Total Checks: 24                      │
│ Passed: 14                            │
│ Failed: 10                            │
│ Security Score: 58.3%                 │
│                                       │
│ Failures by Severity:                 │
│   CRITICAL: 4                         │
│   HIGH: 3                             │
│   MEDIUM: 3                           │
╰───────────────────────────────────────╯
```

## Structure

```
cloud-cspm/
├── cspm.py                 # entry point
├── scanners/
│   ├── base_scanner.py     # base class and data models
│   ├── iam_scanner.py
│   ├── s3_scanner.py
│   ├── ec2_scanner.py
│   ├── rds_scanner.py
│   └── logging_scanner.py
├── reports/
│   └── generator.py        # JSON/CSV export
├── policies/
│   └── cis_aws.yaml        # CIS policy definitions
└── requirements.txt
```

## Adding a Scanner

Extend `BaseScanner` and call `self.add_finding(...)`:

```python
from scanners.base_scanner import BaseScanner, Severity, Status

class MyScanner(BaseScanner):
    def scan(self):
        self.add_finding(
            check_id="CUSTOM-1",
            check_name="My Check",
            status=Status.FAIL,
            severity=Severity.HIGH,
            resource_id="resource-123",
            resource_type="AWS::Service::Resource",
            region="us-east-1",
            description="Description of the finding",
            remediation="How to fix it",
        )
        return self.findings
```

CIS policy definitions live in `policies/cis_aws.yaml` if you want to tweak them.

## License

MIT
