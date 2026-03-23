from datetime import UTC, datetime, timedelta

from botocore.exceptions import ClientError

from .base_scanner import BaseScanner, Finding, Severity, Status


class SecretsManagerScanner(BaseScanner):
    ROTATION_THRESHOLD_DAYS = 90
    ACCESS_THRESHOLD_DAYS = 90

    def scan(self) -> list[Finding]:
        regions = self._get_regions()
        for region in regions:
            secrets_client = self.session.client("secretsmanager", region_name=region)
            for secret in self._list_secrets(secrets_client, region):
                secret_id = secret.get("ARN") or secret.get("Name")
                if not secret_id:
                    continue

                details = self._describe_secret(secrets_client, secret_id, region)
                if details is None or details.get("DeletedDate"):
                    continue

                self._check_rotation_enabled(details, region)
                self._check_recent_rotation(details, region)
                self._check_recent_access(details, region)
                self._check_tags(details, region)

        return self.findings

    def _get_regions(self) -> list[str]:
        ec2 = self.session.client("ec2")
        try:
            regions = ec2.describe_regions()["Regions"]
            return [region["RegionName"] for region in regions]
        except ClientError:
            return ["us-east-1"]

    def _list_secrets(self, secrets_client, region: str) -> list[dict]:
        try:
            paginator = secrets_client.get_paginator("list_secrets")
            secrets: list[dict] = []
            for page in paginator.paginate():
                secrets.extend(page.get("SecretList", []))
            return secrets
        except ClientError as error:
            self.add_finding(
                check_id="SECRETS-0",
                check_name="Secrets Manager Service Access",
                status=Status.ERROR,
                severity=Severity.HIGH,
                resource_id=f"secretsmanager:{region}",
                resource_type="AWS::SecretsManager::Service",
                region=region,
                description=f"Unable to list Secrets Manager secrets in {region}: {error}",
            )
            return []

    def _describe_secret(self, secrets_client, secret_id: str, region: str) -> dict | None:
        try:
            return secrets_client.describe_secret(SecretId=secret_id)
        except ClientError as error:
            self.add_finding(
                check_id="SECRETS-0",
                check_name="Secrets Manager Secret Access",
                status=Status.ERROR,
                severity=Severity.HIGH,
                resource_id=secret_id,
                resource_type="AWS::SecretsManager::Secret",
                region=region,
                description=f"Unable to read secret metadata for '{secret_id}': {error}",
            )
            return None

    def _check_rotation_enabled(self, secret: dict, region: str) -> None:
        name = secret["Name"]
        rotation_enabled = bool(secret.get("RotationEnabled"))

        self.add_finding(
            check_id="SECRETS-1",
            check_name="Secrets Manager Rotation Enabled",
            status=Status.PASS if rotation_enabled else Status.FAIL,
            severity=Severity.MEDIUM,
            resource_id=name,
            resource_type="AWS::SecretsManager::Secret",
            region=region,
            description=(
                f"Secret '{name}' has automatic rotation enabled"
                if rotation_enabled
                else f"Secret '{name}' does not have automatic rotation enabled"
            ),
            remediation="Enable automatic rotation for the secret and attach a rotation Lambda where needed",
        )

    def _check_recent_rotation(self, secret: dict, region: str) -> None:
        name = secret["Name"]
        rotation_enabled = bool(secret.get("RotationEnabled"))
        if rotation_enabled:
            reference_date = secret.get("LastRotatedDate") or secret.get("LastChangedDate")
            if reference_date is not None:
                age_days = self._age_in_days(reference_date)
                recent_rotation = age_days <= self.ROTATION_THRESHOLD_DAYS
                description = (
                    f"Secret '{name}' was rotated or changed {age_days} days ago"
                    if recent_rotation
                    else f"Secret '{name}' was last rotated or changed {age_days} days ago"
                )
            else:
                recent_rotation = False
                description = f"Secret '{name}' has no recorded successful rotation or recent change"
        else:
            recent_rotation = False
            description = f"Secret '{name}' cannot meet rotation age requirements because rotation is disabled"

        self.add_finding(
            check_id="SECRETS-2",
            check_name="Secrets Manager Recent Rotation",
            status=Status.PASS if recent_rotation else Status.FAIL,
            severity=Severity.MEDIUM,
            resource_id=name,
            resource_type="AWS::SecretsManager::Secret",
            region=region,
            description=description,
            remediation=f"Rotate the secret at least every {self.ROTATION_THRESHOLD_DAYS} days",
        )

    def _check_recent_access(self, secret: dict, region: str) -> None:
        name = secret["Name"]
        last_accessed = secret.get("LastAccessedDate")
        if last_accessed is not None:
            age_days = self._age_in_days(last_accessed)
            recently_used = age_days <= self.ACCESS_THRESHOLD_DAYS
            description = (
                f"Secret '{name}' was accessed {age_days} days ago in {region}"
                if recently_used
                else f"Secret '{name}' was last accessed {age_days} days ago in {region}"
            )
        else:
            created_date = secret.get("CreatedDate") or secret.get("LastChangedDate")
            access_age_days: int | None = (
                self._age_in_days(created_date) if created_date is not None else None
            )
            recently_used = (
                access_age_days is not None and access_age_days <= self.ACCESS_THRESHOLD_DAYS
            )
            if recently_used and access_age_days is not None:
                description = (
                    f"Secret '{name}' has not been accessed in {region} yet, but it was created or "
                    f"changed {access_age_days} days ago"
                )
            else:
                description = f"Secret '{name}' has not been accessed in {region} in the last 90 days"

        self.add_finding(
            check_id="SECRETS-3",
            check_name="Secrets Manager Recent Access",
            status=Status.PASS if recently_used else Status.FAIL,
            severity=Severity.MEDIUM,
            resource_id=name,
            resource_type="AWS::SecretsManager::Secret",
            region=region,
            description=description,
            remediation="Delete unused secrets or confirm they are still required and actively used",
        )

    def _check_tags(self, secret: dict, region: str) -> None:
        name = secret["Name"]
        tags = secret.get("Tags", [])
        user_tags = [tag for tag in tags if not tag["Key"].startswith("aws:")]

        self.add_finding(
            check_id="SECRETS-4",
            check_name="Secrets Manager Tags",
            status=Status.PASS if user_tags else Status.FAIL,
            severity=Severity.LOW,
            resource_id=name,
            resource_type="AWS::SecretsManager::Secret",
            region=region,
            description=(
                f"Secret '{name}' has user-defined tags"
                if user_tags
                else f"Secret '{name}' has no user-defined tags"
            ),
            remediation="Add owner, environment, and service tags to the secret",
        )

    def _age_in_days(self, value: datetime) -> int:
        normalized_value = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return int((datetime.now(UTC) - normalized_value) / timedelta(days=1))
