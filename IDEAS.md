# CSPM Roadmap

## Done
- [x] IAM scanner (root keys, MFA, credential age)
- [x] S3 scanner (public access, encryption, versioning)
- [x] EC2 scanner (security groups, open ports)
- [x] RDS scanner (encryption, public access)
- [x] CloudTrail logging checks
- [x] Lambda function policy checks
- [x] Secrets Manager rotation checks
- [x] CIS benchmark mappings
- [x] HTML report generator
- [x] SARIF output for CI integration
- [x] Cross-account scanning via STS AssumeRole
- [x] CI pipeline with pytest and moto

## Next Up
- [ ] Multi-account support (scan org-wide)
- [ ] EKS cluster security checks
- [ ] VPC flow log validation
- [ ] SNS/SQS public access checks
- [ ] Config rule compliance checks
- [ ] Slack/Teams alerting on critical findings
- [ ] Scheduled scan mode (cron-based)
- [ ] Terraform plan scanning (pre-deploy checks)

## Maybe Later
- [ ] Azure support (Defender integration)
- [ ] GCP support (Security Command Center)
- [ ] Dashboard UI (flask or streamlit)
- [ ] Remediation automation (auto-fix common issues)
