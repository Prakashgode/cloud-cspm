# Cloud CSPM

![CI](https://github.com/Prakashgode/cloud-cspm/actions/workflows/ci.yml/badge.svg)

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
$ python cspm.py --profile default --region us-east-1

Scanning IAM...
[CRITICAL] Root account has active access keys (CIS 1.4)
[HIGH] 3 IAM users without MFA enabled (CIS 1.2)
[PASS] No inline policies on IAM users (CIS 1.16)

Scanning S3...
[HIGH] Bucket "dev-logs-2024" has public read access (CIS 2.1.1)
[MEDIUM] Bucket "backups" missing server-side encryption (CIS 2.1.2)
[PASS] All buckets have versioning enabled

Scanning EC2...
[HIGH] Security group sg-0a1b2c allows 0.0.0.0/0 on port 22 (CIS 5.2)
[PASS] No public instances found

Results: 4 critical/high, 1 medium, 3 passed | 3 services scanned
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

