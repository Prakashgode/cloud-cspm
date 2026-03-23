# Codex Handoff: cloud-cspm

## What This Project Is

AWS Cloud Security Posture Management (CSPM) tool that scans AWS accounts for security misconfigurations against CIS AWS Foundations Benchmark controls. Built in Python with boto3, Click CLI, and Rich terminal output.

**Repo:** https://github.com/Prakashgode/cloud-cspm
**Owner:** Prakash Gode (Cloud Security Engineer)
**License:** MIT

---

## Directory Structure

```
cloud-cspm/
|-- .github/workflows/
|   |-- ci.yml                      # GitHub Actions matrix: Ruff, mypy, pytest
|   |-- codeql.yml                  # CodeQL analysis
|   `-- dependency-review.yml       # PR dependency review
|-- assets/
|   `-- cloud-cspm-demo.svg         # README demo image
|-- scanners/
|   |-- __init__.py                 # Exports all scanner classes
|   |-- base_scanner.py             # BaseScanner, Finding dataclass, Severity/Status enums
|   |-- iam_scanner.py              # IAM checks (root MFA, password policy, key rotation, etc.)
|   |-- s3_scanner.py               # S3 checks (public access, encryption, versioning, logging, SSL)
|   |-- ec2_scanner.py              # EC2/network checks (open ports, default SGs, EBS encryption, public instances)
|   |-- rds_scanner.py              # RDS checks (encryption, public access, multi-AZ, backups, deletion protection)
|   |-- logging_scanner.py          # Logging checks (CloudTrail, VPC flow logs)
|   |-- lambda_scanner.py           # Lambda checks (public access, env KMS, VPC, tags, tracing)
|   `-- secretsmanager_scanner.py   # Secrets Manager checks (rotation, recent access, tags)
|-- reports/
|   |-- __init__.py
|   `-- generator.py                # ReportGenerator: JSON/CSV/SARIF export + summary
|-- policies/
|   |-- cis_aws.yaml
|   |-- lambda_best_practices.yaml
|   `-- secretsmanager_best_practices.yaml
|-- samples/
|   |-- demo-report.json
|   |-- demo-report.csv
|   `-- demo-report.sarif
|-- scripts/
|   `-- generate_sample_artifacts.py
|-- tests/
|   |-- test_scanners.py
|   |-- test_cspm.py
|   |-- test_secretsmanager_scanner.py
|   `-- test_integration_moto.py
|-- cspm.py                         # CLI entry point (Click-based)
|-- pyproject.toml                  # Project metadata and tool configuration
|-- uv.lock                         # Locked dependency graph
|-- requirements.txt                # Pip fallback install path
|-- README.md
`-- IDEAS.md                        # Roadmap ideas
```

---

## How It Works (End-to-End Flow)

```
python cspm.py [options]
  1. Parse CLI args (--profile, --region, --role-arn, --scanner, --output, --severity)
  2. Create boto3.Session
  3. Optionally assume a target role with STS AssumeRole
  4. Run selected scanners (each returns list[Finding])
  5. Filter by severity if specified
  6. Display Rich table (FAIL findings first, sorted by severity)
  7. Show summary panel (score = passed/total * 100)
  8. Export to JSON, CSV, or SARIF if --output specified
```

**Scanner registry** in cspm.py:
```python
SCANNERS = {
    "iam": ("IAM Security", IAMScanner),
    "s3": ("S3 Bucket Security", S3Scanner),
    "ec2": ("EC2 & Network Security", EC2Scanner),
    "rds": ("RDS Database Security", RDSScanner),
    "logging": ("Logging & Monitoring", LoggingScanner),
    "lambda": ("Lambda Security", LambdaScanner),
    "secrets": ("Secrets Manager Security", SecretsManagerScanner),
}
```

---

## CIS Benchmarks Covered (26 controls)

| ID | Check | Severity | Scanner |
|----|-------|----------|---------|
| CIS-1.1 | Root MFA | CRITICAL | IAM |
| CIS-1.2 | Password policy | HIGH | IAM |
| CIS-1.3 | Unused credentials (>90 days) | MEDIUM | IAM |
| CIS-1.4 | Access key rotation (>90 days) | HIGH | IAM |
| CIS-1.5 | Console user MFA | HIGH | IAM |
| CIS-2.1 | CloudTrail enabled + multi-region | CRITICAL | Logging |
| CIS-2.2 | CloudTrail log validation | HIGH | Logging |
| CIS-2.3 | CloudTrail KMS encryption | HIGH | Logging |
| CIS-2.4 | VPC flow logs | HIGH | Logging |
| CIS-3.1 | S3 public access block | CRITICAL | S3 |
| CIS-3.2 | S3 encryption | HIGH | S3 |
| CIS-3.3 | S3 versioning | MEDIUM | S3 |
| CIS-3.4 | S3 access logging | MEDIUM | S3 |
| CIS-3.5 | S3 SSL enforcement | HIGH | S3 |
| CIS-4.1 | Security group SSH open | CRITICAL | EC2 |
| CIS-4.2 | Security group RDP open | CRITICAL | EC2 |
| CIS-4.3 | Dangerous ports open | CRITICAL | EC2 |
| CIS-4.4 | Default security group rules | HIGH | EC2 |
| CIS-4.5 | Public EC2 instances | MEDIUM | EC2 |
| CIS-5.1 | RDS encryption at rest | HIGH | RDS |
| CIS-5.2 | RDS public access | CRITICAL | RDS |
| CIS-5.3 | RDS Multi-AZ | MEDIUM | RDS |
| CIS-5.4 | RDS auto minor upgrade | MEDIUM | RDS |
| CIS-5.5 | RDS backup retention >= 7 days | MEDIUM | RDS |
| CIS-5.6 | RDS deletion protection | MEDIUM | RDS |
| CIS-6.1 | EBS encryption | HIGH | EC2 |

---

## Key Architecture Patterns

- **BaseScanner** abstract class: all scanners inherit from it, implement `scan()`, use `add_finding()` factory method
- **Finding dataclass**: standardized result object with check_id, status, severity, resource_id, description, remediation
- **Multi-region scanning**: EC2, RDS, and Logging scanners iterate all AWS regions automatically
- **Mocking strategy**: tests inject MagicMock boto3 session/clients, no real AWS calls needed
- **CLI plugin system**: SCANNERS dict maps names to classes, easy to add new scanners

---

## Dependencies

```
boto3>=1.28.0       # AWS SDK
botocore>=1.31.0    # AWS SDK core (error handling)
rich>=13.0.0        # Terminal tables, panels, colors
click>=8.1.0        # CLI framework
pyyaml>=6.0         # YAML policy parsing
jinja2>=3.1.0       # Template engine (imported but not actively used yet)
```

---

## Tests

13 unit tests in `tests/test_scanners.py`:
- BaseScanner: finding creation, abstract method enforcement
- IAMScanner: root MFA pass/fail
- S3Scanner: public access pass, encryption fail
- EC2Scanner: open SSH detection
- ReportGenerator: summary math, JSON export, CSV export
- Imports: all scanners importable, enum values correct

**Run:** `pytest tests/ -v`

**CI:** GitHub Actions on push/PR to master, Python 3.11, syntax check + pytest

---

## Existing TODOs in Code

1. EC2Scanner: "TODO: add memcached 11211" to DANGEROUS_PORTS
2. RDSScanner: "TODO: add Aurora cluster checks"
3. Jinja2 imported but not used (intended for HTML reports)

---

## Suggested Improvements

### New Scanners
- **Lambda scanner**: overly permissive execution roles, public function URLs, environment variable secrets
- **CloudWatch scanner**: check for metric alarms on root login, unauthorized API calls, console sign-in without MFA
- **KMS scanner**: key rotation enabled, key policy permissions
- **SNS scanner**: topic encryption, public access policies
- **EKS scanner**: public API endpoint, secrets encryption, logging enabled
- **Secrets Manager scanner**: rotation enabled, unused secrets

### Enhancements to Existing Scanners
- S3: check for Object Lock, lifecycle policies, cross-region replication
- EC2: check for IMDSv2 enforcement, SSM agent, public AMIs
- IAM: check for overly permissive policies (iam:*, s3:*), inline vs managed policies
- RDS: Aurora cluster checks, enhanced monitoring, performance insights

### Features
- **HTML report** using Jinja2 (already imported, not wired up)
- **Multi-account support** via cross-account IAM AssumeRole
- **Remediation mode**: auto-fix findings (e.g., enable encryption, block public access)
- **Policy engine**: use policies/cis_aws.yaml to make checks configurable (enable/disable, override severity)
- **Diff mode**: compare scans over time, show new/resolved findings
- **Compliance mapping**: map checks to SOC2, PCI-DSS, HIPAA controls (not just CIS)
- **Parallel scanning**: use concurrent.futures for faster multi-region scans
- **Terraform integration**: scan Terraform plans for misconfigs before deployment

### Code Quality
- Add type hints to all functions
- Add docstrings to all public methods
- Increase test coverage (currently missing: RDS, Logging scanner tests, severity filtering, CLI arg parsing)
- Add integration test with moto (AWS mock library)
- Add --format flag (table, json, csv, html) instead of inferring from file extension

---

## Rules for Contributing

1. **No AI attribution** in commits - no Co-Authored-By, no AI badges
2. **No em dashes** anywhere in code, docs, or commit messages
3. **Commit messages** should be casual and natural (e.g., "add lambda checks" not "Implement AWS Lambda security scanner module")
4. **All new scanners** must: subclass BaseScanner, implement scan(), have corresponding unit tests with mocked boto3
5. **Tests must pass** before pushing: `pytest tests/ -v`
6. **Keep it simple** - no over-engineering, no unnecessary abstractions
7. **Branch from master**, PR into master
8. **Do not touch GitHub remote state without explicit user approval in this thread** - no push, pull, branch deletion, PR creation, or other remote changes unless the user clearly asks for that action

