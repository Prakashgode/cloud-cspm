# CSPM Roadmap

## Done
- IAM scanner: root MFA, password policy, credential age, access key rotation
- S3 scanner: public access, encryption, versioning, logging, SSL enforcement
- EC2 scanner: security groups, open ports, public instances, EBS encryption
- RDS scanner: encryption, public access, Multi-AZ, backup and deletion checks
- Logging checks: CloudTrail coverage, log validation, KMS encryption, VPC flow logs
- Lambda security checks: public access, environment encryption, VPC, tags, tracing
- Secrets Manager checks: rotation, recent access, tagging
- Cross-account scanning via STS AssumeRole
- JSON, CSV, and SARIF export
- Sample report artifacts for demos and documentation
- CI with Ruff, mypy, pytest, and moto-backed integration tests
- Repo hygiene: SECURITY.md, LICENSE, CONTRIBUTING.md

## Next Up
- Terraform plan scanning (pre-deploy checks)
- EKS cluster security checks
- AWS Config compliance checks
- Org-wide multi-account scanning via AWS Organizations
- SNS/SQS public access checks
- Slack or Teams alerting for critical findings
- Scheduled scan mode
- Policy-driven check configuration from YAML

## Maybe Later
- KMS key policy and rotation checks
- Dashboard UI
- Remediation automation for common issues
- Azure support
- GCP support
