import boto3
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, Finding, Severity, Status


class IAMScanner(BaseScanner):
    def scan(self) -> list[Finding]:
        iam = self.session.client("iam")
        self._check_root_mfa(iam)
        self._check_password_policy(iam)
        self._check_access_keys_rotation(iam)
        return self.findings

    def _check_root_mfa(self, iam):
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            root_mfa = summary.get("AccountMFAEnabled", 0)
            self.add_finding(
                check_id="CIS-1.1",
                check_name="Root Account MFA",
                status=Status.PASS if root_mfa == 1 else Status.FAIL,
                severity=Severity.CRITICAL,
                resource_id="root",
                resource_type="AWS::IAM::Root",
                region="global",
                description="Root account MFA is "
                + ("enabled" if root_mfa == 1 else "NOT enabled"),
                remediation="Enable MFA on the root account via IAM console > Security credentials",
            )
        except ClientError as e:
            self.add_finding(
                check_id="CIS-1.1",
                check_name="Root Account MFA",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                resource_id="root",
                resource_type="AWS::IAM::Root",
                region="global",
                description=f"Error checking root MFA: {e}",
            )

    def _check_password_policy(self, iam):
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            min_length = policy.get("MinimumPasswordLength", 0)
            requires_symbols = policy.get("RequireSymbols", False)
            requires_numbers = policy.get("RequireNumbers", False)
            requires_upper = policy.get("RequireUppercaseCharacters", False)
            requires_lower = policy.get("RequireLowercaseCharacters", False)

            is_strong = all([
                min_length >= 14,
                requires_symbols,
                requires_numbers,
                requires_upper,
                requires_lower,
            ])

            issues = []
            if min_length < 14:
                issues.append(f"min length is {min_length} (should be >= 14)")
            if not requires_symbols:
                issues.append("symbols not required")
            if not requires_numbers:
                issues.append("numbers not required")
            if not requires_upper:
                issues.append("uppercase not required")
            if not requires_lower:
                issues.append("lowercase not required")

            self.add_finding(
                check_id="CIS-1.2",
                check_name="IAM Password Policy",
                status=Status.PASS if is_strong else Status.FAIL,
                severity=Severity.HIGH,
                resource_id="password-policy",
                resource_type="AWS::IAM::PasswordPolicy",
                region="global",
                description="Password policy is strong"
                if is_strong
                else f"Weak password policy: {', '.join(issues)}",
                remediation="Update password policy: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters",
            )
        except iam.exceptions.NoSuchEntityException:
            self.add_finding(
                check_id="CIS-1.2",
                check_name="IAM Password Policy",
                status=Status.FAIL,
                severity=Severity.HIGH,
                resource_id="password-policy",
                resource_type="AWS::IAM::PasswordPolicy",
                region="global",
                description="No password policy configured",
                remediation="Create a password policy using aws iam update-account-password-policy",
            )

    def _check_access_keys_rotation(self, iam):
        try:
            users = iam.list_users()["Users"]
            from datetime import datetime, timedelta

            threshold = datetime.utcnow() - timedelta(days=90)

            for user in users:
                username = user["UserName"]
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

                for key in keys:
                    if key["Status"] == "Active":
                        created = key["CreateDate"].replace(tzinfo=None)
                        if created < threshold:
                            self.add_finding(
                                check_id="CIS-1.4",
                                check_name="Access Key Rotation",
                                status=Status.FAIL,
                                severity=Severity.HIGH,
                                resource_id=f"{username}/{key['AccessKeyId']}",
                                resource_type="AWS::IAM::AccessKey",
                                region="global",
                                description=f"Access key for user '{username}' has not been rotated in 90+ days",
                                remediation=f"Rotate access key for user '{username}': aws iam create-access-key && aws iam delete-access-key",
                            )
        except ClientError:
            pass
