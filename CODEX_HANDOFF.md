# Codex Handoff: cloud-cspm

## What This Project Is

`cloud-cspm` is a Python CLI for AWS cloud security posture checks. It scans AWS accounts for CIS-style misconfigurations across IAM, S3, EC2, RDS, and logging, plus extended best-practice checks for Lambda and Secrets Manager.

Current shape:
- 7 scanner families
- 36 main security checks
- JSON, CSV, and SARIF export
- cross-account scanning via STS AssumeRole
- modern Python packaging with `pyproject.toml` and `uv.lock`
- local sample artifacts and a README demo image for portfolio use

**Repo:** https://github.com/Prakashgode/cloud-cspm  
**Owner:** Prakash Gode  
**License:** MIT  
**Primary entrypoint:** `cloud-cspm` or `python cspm.py`

---

## Current Status

The repo is no longer just a basic local script set. It now includes:
- `pyproject.toml` packaging and a console script
- Ruff, mypy, pytest, CodeQL, Dependabot, and dependency review
- Lambda and Secrets Manager scanners
- sample JSON, CSV, and SARIF reports under `samples/`
- a moto-backed integration test layer
- SECURITY, LICENSE, and CONTRIBUTING docs

Important SARIF note:
- The SARIF export is for generic cloud-security pipelines and machine processing.
- It is not intended to be uploaded to GitHub code scanning as a source-code SARIF report.

---

## Directory Structure

```text
cloud-cspm/
|-- .github/workflows/
|   |-- ci.yml                      # CI matrix: Ruff, mypy, compileall, pytest
|   |-- codeql.yml                  # CodeQL analysis
|   `-- dependency-review.yml       # PR dependency review
|-- assets/
|   `-- cloud-cspm-demo.svg         # README demo image
|-- scanners/
|   |-- __init__.py                 # Scanner exports
|   |-- base_scanner.py             # BaseScanner, Finding, Severity, Status
|   |-- iam_scanner.py              # IAM checks
|   |-- s3_scanner.py               # S3 checks
|   |-- ec2_scanner.py              # EC2 and network checks
|   |-- rds_scanner.py              # RDS checks
|   |-- logging_scanner.py          # CloudTrail and VPC flow log checks
|   |-- lambda_scanner.py           # Lambda checks
|   `-- secretsmanager_scanner.py   # Secrets Manager checks
|-- reports/
|   |-- __init__.py
|   `-- generator.py                # Summary + JSON/CSV/SARIF export
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
|-- cspm.py
|-- pyproject.toml
|-- uv.lock
|-- requirements.txt                # pip fallback path
|-- README.md
|-- SECURITY.md
|-- LICENSE
|-- CONTRIBUTING.md
`-- IDEAS.md
```

---

## How It Works

```text
cloud-cspm [options]
  1. Parse CLI args (--profile, --region, --role-arn, --external-id, --scanner, --output, --severity)
  2. Build a base boto3 session
  3. Optionally call STS AssumeRole to scan a target account
  4. Run the selected scanners
  5. Collect normalized Finding objects
  6. Filter visible results by minimum severity if requested
  7. Render a Rich findings table and summary panel
  8. Export the results to JSON, CSV, or SARIF when --output is set
```

Scanner registry in `cspm.py`:

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

Core patterns:
- `BaseScanner` defines the scanner contract and finding creation helper.
- `Finding` is the normalized result object shared across all scanners.
- The CLI owns session setup, role assumption, orchestration, display, and export.
- Region-aware scanners call `describe_regions()` and iterate region clients.
- Reports are generated from findings only; scanners do not know about output formats.

---

## Scanner Inventory

The repo currently implements 36 main checks.

| Family | Checks | Notes |
|---|---:|---|
| IAM | 5 | Root MFA, password policy, unused credentials, key rotation, console MFA |
| Logging | 4 | CloudTrail enabled/logging, log validation, KMS encryption, VPC flow logs |
| S3 | 5 | Public access block, encryption, versioning, access logging, SSL enforcement |
| EC2 | 6 | SSH/RDP/dangerous ports, default SGs, public instances, EBS encryption |
| RDS | 6 | Encryption, public access, Multi-AZ, auto minor upgrades, backups, deletion protection |
| Lambda | 6 | Public access, env var KMS, VPC, multi-AZ subnets, tags, X-Ray |
| Secrets Manager | 4 | Rotation enabled, recent rotation, recent access, tags |

Notes:
- IAM, S3, EC2, RDS, and logging are the CIS-style core.
- Lambda and Secrets Manager are extended best-practice controls, not part of the original CIS-only footprint.
- `LAMBDA-0` and `SECRETS-0` are service-access error findings used when the scanner cannot enumerate resources.

---

## Dependencies And Tooling

Runtime dependencies from `pyproject.toml`:

```text
boto3>=1.42.0
botocore>=1.42.0
click>=8.3.0
Jinja2>=3.1.6
PyYAML>=6.0.1
rich>=14.0.0
```

Dev dependencies:

```text
moto[s3]>=5.1.22
mypy>=1.18.2
pytest>=9.0.0
ruff>=0.14.0
```

Tooling status:
- Python 3.11 to 3.14 supported
- `uv sync --locked --all-extras --dev` is the preferred setup flow
- `requirements.txt` still exists as a pip fallback
- `uv.lock` is the authoritative lockfile

---

## Reports And Demo Assets

Supported output paths:
- `.json`
- `.csv`
- `.sarif`
- `.sarif.json`

Sample committed artifacts:
- `samples/demo-report.json`
- `samples/demo-report.csv`
- `samples/demo-report.sarif`
- `assets/cloud-cspm-demo.svg`

Regenerate them with:

```bash
uv run python scripts/generate_sample_artifacts.py
```

---

## Tests

Current test count: 25 collected tests.

Coverage by file:
- `tests/test_scanners.py`: unit tests for base scanner behavior, IAM, S3, EC2, Lambda, report generation, and imports
- `tests/test_cspm.py`: CLI session-building and AssumeRole behavior
- `tests/test_secretsmanager_scanner.py`: Secrets Manager scanner behavior
- `tests/test_integration_moto.py`: moto-backed S3 integration path

Run locally:

```bash
uv run ruff check .
uv run mypy
uv run pytest -v
uv run python -m compileall cspm.py scanners reports tests scripts
```

CI status:
- matrix testing on Python 3.11, 3.12, 3.13, and 3.14
- Ruff
- mypy
- compile check
- pytest
- CodeQL
- dependency review on pull requests

---

## Current TODOs In Code

These are the actual in-code TODOs that still exist:

1. `scanners/ec2_scanner.py`: add memcached port `11211` to `DANGEROUS_PORTS`
2. `scanners/rds_scanner.py`: add Aurora cluster checks

Nearby reality:
- `Jinja2` is still installed but there is no HTML report implementation yet.
- The policy YAML files are present, but the scanners are still mostly hardcoded rather than policy-driven.

---

## Real Remaining Gaps

If someone picks this repo up and wants the highest-value next work, these are the real gaps now:

1. Add another high-signal AWS family such as KMS, EKS, or CloudWatch alarms
2. Make policy files drive scanner enablement and severity instead of leaving checks hardcoded
3. Add HTML output or remove the unused Jinja2 dependency
4. Add deeper integration coverage for RDS, logging, and any new scanners
5. Add organization-level or batch multi-account workflows on top of the existing AssumeRole support
6. Add execution-role analysis for Lambda to catch overly permissive IAM policies

---

## Repo Rules

1. No AI attribution in commits
2. No em dashes in code, docs, or commit messages
3. Keep commit messages natural and short
4. New scanners should subclass `BaseScanner` and ship with tests
5. Run tests before pushing
6. Keep the implementation simple and avoid unnecessary abstractions
7. Branch from `master` and PR into `master` unless the user says otherwise
8. Do not touch GitHub remote state without explicit user approval in the active thread

---

## Working Rule For This Repo

Hard rule from the user:
- No GitHub remote actions without explicit approval in-thread.
- That includes push, pull, branch deletion, PR creation, force-push, and any other remote mutations.
