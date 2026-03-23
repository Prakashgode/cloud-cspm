from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from scanners.base_scanner import Severity, Status
from scanners.secretsmanager_scanner import SecretsManagerScanner


def make_session():
    return MagicMock()


class TestSecretsManagerScanner:
    def _make_session(self, secret_details):
        session = make_session()
        ec2_global = MagicMock()
        secrets_client = MagicMock()
        paginator = MagicMock()

        paginator.paginate.return_value = [
            {
                "SecretList": [
                    {
                        "Name": secret_details["Name"],
                        "ARN": secret_details["ARN"],
                    }
                ]
            }
        ]
        secrets_client.get_paginator.return_value = paginator
        secrets_client.describe_secret.return_value = secret_details
        ec2_global.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}

        def client(service_name, region_name=None):
            if service_name == "ec2" and region_name is None:
                return ec2_global
            if service_name == "secretsmanager":
                return secrets_client
            raise AssertionError(f"Unexpected service requested: {service_name}")

        session.client.side_effect = client
        return session

    def test_secret_with_rotation_recent_access_and_tags_passes(self):
        now = datetime.now(UTC)
        secret = {
            "Name": "db/password",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db/password",
            "RotationEnabled": True,
            "LastRotatedDate": now - timedelta(days=14),
            "LastChangedDate": now - timedelta(days=14),
            "LastAccessedDate": now - timedelta(days=7),
            "CreatedDate": now - timedelta(days=30),
            "Tags": [{"Key": "owner", "Value": "security"}],
        }

        findings = SecretsManagerScanner(self._make_session(secret)).scan()
        statuses = {finding.check_id: finding.status for finding in findings}

        assert statuses["SECRETS-1"] == Status.PASS
        assert statuses["SECRETS-2"] == Status.PASS
        assert statuses["SECRETS-3"] == Status.PASS
        assert statuses["SECRETS-4"] == Status.PASS

    def test_secret_without_rotation_fails_expected_controls(self):
        now = datetime.now(UTC)
        secret = {
            "Name": "legacy/api-key",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:legacy/api-key",
            "RotationEnabled": False,
            "LastChangedDate": now - timedelta(days=200),
            "CreatedDate": now - timedelta(days=200),
            "Tags": [],
        }

        findings = SecretsManagerScanner(self._make_session(secret)).scan()
        statuses = {finding.check_id: finding.status for finding in findings}

        assert statuses["SECRETS-1"] == Status.FAIL
        assert statuses["SECRETS-2"] == Status.FAIL
        assert statuses["SECRETS-3"] == Status.FAIL
        assert statuses["SECRETS-4"] == Status.FAIL

        rotation_enabled = next(finding for finding in findings if finding.check_id == "SECRETS-1")
        assert rotation_enabled.severity == Severity.MEDIUM

    def test_secret_created_recently_without_access_still_passes_access_check(self):
        now = datetime.now(UTC)
        secret = {
            "Name": "new/service-token",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:new/service-token",
            "RotationEnabled": True,
            "LastChangedDate": now - timedelta(days=5),
            "CreatedDate": now - timedelta(days=5),
            "Tags": [{"Key": "environment", "Value": "dev"}],
        }

        findings = SecretsManagerScanner(self._make_session(secret)).scan()
        access_finding = next(finding for finding in findings if finding.check_id == "SECRETS-3")

        assert access_finding.status == Status.PASS


def test_scanner_is_exported():
    from scanners import SecretsManagerScanner

    assert SecretsManagerScanner is not None
