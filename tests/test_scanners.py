import json
import os
import tempfile
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from reports.generator import ReportGenerator
from scanners.base_scanner import BaseScanner, Finding, Severity, Status
from scanners.ec2_scanner import EC2Scanner
from scanners.iam_scanner import IAMScanner
from scanners.lambda_scanner import LambdaScanner
from scanners.s3_scanner import S3Scanner


def make_session():
    """Create a mock boto3 session."""
    return MagicMock()


# ---------------------------------------------------------------------------
# base_scanner
# ---------------------------------------------------------------------------


class TestBaseScanner:
    def test_add_finding(self):
        scanner = BaseScanner(make_session())
        f = scanner.add_finding(
            check_id="TEST-1",
            check_name="Test Check",
            status=Status.PASS,
            severity=Severity.LOW,
            resource_id="res-1",
            resource_type="AWS::Test::Resource",
            region="us-east-1",
            description="All good",
        )
        assert isinstance(f, Finding)
        assert f.check_id == "TEST-1"
        assert f.status == Status.PASS
        assert len(scanner.findings) == 1

    def test_scan_not_implemented(self):
        scanner = BaseScanner(make_session())
        with pytest.raises(NotImplementedError):
            scanner.scan()


# ---------------------------------------------------------------------------
# iam_scanner
# ---------------------------------------------------------------------------


class TestIAMScanner:
    def test_root_mfa_enabled(self):
        session = make_session()
        iam_client = MagicMock()
        session.client.return_value = iam_client
        iam_client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam_client.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
            }
        }
        iam_client.generate_credential_report.return_value = {"State": "STARTED"}
        iam_client.list_users.return_value = {"Users": []}

        scanner = IAMScanner(session)
        findings = scanner.scan()

        root_finding = next(f for f in findings if f.check_id == "CIS-1.1")
        assert root_finding.status == Status.PASS

    def test_root_mfa_disabled(self):
        session = make_session()
        iam_client = MagicMock()
        session.client.return_value = iam_client
        iam_client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        iam_client.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
            }
        }
        iam_client.generate_credential_report.return_value = {"State": "STARTED"}
        iam_client.list_users.return_value = {"Users": []}

        scanner = IAMScanner(session)
        findings = scanner.scan()

        root_finding = next(f for f in findings if f.check_id == "CIS-1.1")
        assert root_finding.status == Status.FAIL
        assert root_finding.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# s3_scanner
# ---------------------------------------------------------------------------


class TestS3Scanner:
    def test_bucket_public_access_blocked(self):
        session = make_session()
        s3_client = MagicMock()
        session.client.return_value = s3_client
        s3_client.list_buckets.return_value = {"Buckets": [{"Name": "my-secure-bucket"}]}
        s3_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        s3_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        s3_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        s3_client.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "logs"}}
        s3_client.get_bucket_policy.return_value = {
            "Policy": '{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
        }

        scanner = S3Scanner(session)
        findings = scanner.scan()

        public_finding = next(f for f in findings if f.check_id == "CIS-3.1")
        assert public_finding.status == Status.PASS

    def test_bucket_no_encryption(self):
        from botocore.exceptions import ClientError

        session = make_session()
        s3_client = MagicMock()
        session.client.return_value = s3_client
        s3_client.list_buckets.return_value = {"Buckets": [{"Name": "unencrypted-bucket"}]}
        s3_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        s3_client.get_bucket_encryption.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ServerSideEncryptionConfigurationNotFoundError",
                    "Message": "not found",
                }
            },
            "GetBucketEncryption",
        )
        s3_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        s3_client.get_bucket_logging.return_value = {}
        s3_client.get_bucket_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "no policy"}},
            "GetBucketPolicy",
        )

        scanner = S3Scanner(session)
        findings = scanner.scan()

        enc_finding = next(f for f in findings if f.check_id == "CIS-3.2")
        assert enc_finding.status == Status.FAIL


# ---------------------------------------------------------------------------
# ec2_scanner
# ---------------------------------------------------------------------------


class TestEC2Scanner:
    def test_open_ssh_detected(self):
        session = make_session()
        ec2_client = MagicMock()
        session.client.return_value = ec2_client

        ec2_client.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        ec2_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "wide-open",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                        }
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        }
        ec2_client.describe_volumes.return_value = {"Volumes": []}
        ec2_client.describe_instances.return_value = {"Reservations": []}

        scanner = EC2Scanner(session)
        findings = scanner.scan()

        ssh_findings = [f for f in findings if f.check_id == "CIS-4.1"]
        assert len(ssh_findings) >= 1
        assert ssh_findings[0].status == Status.FAIL
        assert ssh_findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# lambda_scanner
# ---------------------------------------------------------------------------


class TestLambdaScanner:
    def _make_lambda_session(
        self, configuration, *, url_config=None, policy=None, tags=None, subnets=None
    ):
        session = make_session()
        lambda_client = MagicMock()
        ec2_global = MagicMock()
        ec2_regional = MagicMock()
        paginator = MagicMock()

        paginator.paginate.return_value = [
            {"Functions": [{"FunctionName": configuration["FunctionName"]}]}
        ]
        lambda_client.get_paginator.return_value = paginator
        lambda_client.get_function_configuration.return_value = configuration

        if isinstance(url_config, Exception):
            lambda_client.get_function_url_config.side_effect = url_config
        elif url_config is not None:
            lambda_client.get_function_url_config.return_value = url_config
        else:
            lambda_client.get_function_url_config.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
                "GetFunctionUrlConfig",
            )

        if isinstance(policy, Exception):
            lambda_client.get_policy.side_effect = policy
        elif policy is not None:
            lambda_client.get_policy.return_value = {"Policy": json.dumps(policy)}
        else:
            lambda_client.get_policy.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
                "GetPolicy",
            )

        lambda_client.list_tags.return_value = {"Tags": tags or {}}
        ec2_global.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        ec2_regional.describe_subnets.return_value = {"Subnets": subnets or []}

        def client(service_name, region_name=None):
            if service_name == "lambda":
                return lambda_client
            if service_name == "ec2" and region_name is None:
                return ec2_global
            if service_name == "ec2":
                return ec2_regional
            raise AssertionError(f"Unexpected service requested: {service_name}")

        session.client.side_effect = client
        return session

    def test_public_function_url_detected(self):
        configuration = {
            "FunctionName": "public-url-fn",
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:public-url-fn",
            "VpcConfig": {"SubnetIds": ["subnet-1", "subnet-2"], "VpcId": "vpc-123"},
            "TracingConfig": {"Mode": "Active"},
            "Environment": {"Variables": {"STAGE": "prod"}},
            "KMSKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc",
        }
        session = self._make_lambda_session(
            configuration,
            url_config={"AuthType": "NONE"},
            tags={"owner": "security"},
            subnets=[
                {"SubnetId": "subnet-1", "AvailabilityZone": "us-east-1a"},
                {"SubnetId": "subnet-2", "AvailabilityZone": "us-east-1b"},
            ],
        )

        findings = LambdaScanner(session).scan()

        public_finding = next(f for f in findings if f.check_id == "LAMBDA-1")
        assert public_finding.status == Status.FAIL
        assert public_finding.severity == Severity.CRITICAL
        assert "unauthenticated access" in public_finding.description

    def test_public_resource_policy_detected(self):
        configuration = {
            "FunctionName": "public-policy-fn",
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:public-policy-fn",
            "VpcConfig": {"SubnetIds": ["subnet-1", "subnet-2"], "VpcId": "vpc-123"},
            "TracingConfig": {"Mode": "Active"},
            "Environment": {"Variables": {"STAGE": "prod"}},
            "KMSKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc",
        }
        session = self._make_lambda_session(
            configuration,
            policy={
                "Statement": [
                    {
                        "Sid": "PublicInvoke",
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Principal": "*",
                    }
                ]
            },
            tags={"owner": "security"},
            subnets=[
                {"SubnetId": "subnet-1", "AvailabilityZone": "us-east-1a"},
                {"SubnetId": "subnet-2", "AvailabilityZone": "us-east-1b"},
            ],
        )

        findings = LambdaScanner(session).scan()

        public_finding = next(f for f in findings if f.check_id == "LAMBDA-1")
        assert public_finding.status == Status.FAIL
        assert "PublicInvoke" in public_finding.description

    def test_environment_variables_without_customer_kms_fail(self):
        configuration = {
            "FunctionName": "unencrypted-env-fn",
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:unencrypted-env-fn",
            "VpcConfig": {"SubnetIds": ["subnet-1", "subnet-2"], "VpcId": "vpc-123"},
            "TracingConfig": {"Mode": "Active"},
            "Environment": {"Variables": {"API_TOKEN": "placeholder"}},
        }
        session = self._make_lambda_session(
            configuration,
            tags={"owner": "security"},
            subnets=[
                {"SubnetId": "subnet-1", "AvailabilityZone": "us-east-1a"},
                {"SubnetId": "subnet-2", "AvailabilityZone": "us-east-1b"},
            ],
        )

        findings = LambdaScanner(session).scan()

        encryption_finding = next(f for f in findings if f.check_id == "LAMBDA-2")
        assert encryption_finding.status == Status.FAIL
        assert encryption_finding.severity == Severity.HIGH

    def test_lambda_controls_pass_with_private_multi_az_configuration(self):
        configuration = {
            "FunctionName": "secure-fn",
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:secure-fn",
            "VpcConfig": {"SubnetIds": ["subnet-1", "subnet-2"], "VpcId": "vpc-123"},
            "TracingConfig": {"Mode": "Active"},
            "Environment": {"Variables": {"STAGE": "prod"}},
            "KMSKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc",
        }
        session = self._make_lambda_session(
            configuration,
            tags={"owner": "security", "environment": "prod"},
            subnets=[
                {"SubnetId": "subnet-1", "AvailabilityZone": "us-east-1a"},
                {"SubnetId": "subnet-2", "AvailabilityZone": "us-east-1b"},
            ],
        )

        findings = LambdaScanner(session).scan()

        statuses = {finding.check_id: finding.status for finding in findings}
        assert statuses["LAMBDA-1"] == Status.PASS
        assert statuses["LAMBDA-2"] == Status.PASS
        assert statuses["LAMBDA-3"] == Status.PASS
        assert statuses["LAMBDA-4"] == Status.PASS
        assert statuses["LAMBDA-5"] == Status.PASS
        assert statuses["LAMBDA-6"] == Status.PASS


# ---------------------------------------------------------------------------
# report_generator
# ---------------------------------------------------------------------------


class TestReportGenerator:
    def _sample_findings(self):
        return [
            Finding(
                check_id="T-1",
                check_name="Check A",
                status=Status.PASS,
                severity=Severity.LOW,
                resource_id="r1",
                resource_type="AWS::T::R",
                region="us-east-1",
                description="ok",
            ),
            Finding(
                check_id="T-2",
                check_name="Check B",
                status=Status.FAIL,
                severity=Severity.HIGH,
                resource_id="r2",
                resource_type="AWS::T::R",
                region="us-east-1",
                description="not ok",
            ),
            Finding(
                check_id="T-3",
                check_name="Check C",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                resource_id="r3",
                resource_type="AWS::T::R",
                region="us-east-1",
                description="bad",
            ),
        ]

    def test_summary(self):
        gen = ReportGenerator(self._sample_findings())
        s = gen.summary()
        assert s["total_checks"] == 3
        assert s["passed"] == 1
        assert s["failed"] == 2
        assert s["score"] == pytest.approx(33.3, abs=0.1)
        assert s["failures_by_severity"]["HIGH"] == 1
        assert s["failures_by_severity"]["CRITICAL"] == 1

    def test_to_json(self):
        gen = ReportGenerator(self._sample_findings())
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            gen.to_json(path)
            with open(path) as f:
                data = json.load(f)
            assert "summary" in data
            assert len(data["findings"]) == 3
        finally:
            os.unlink(path)

    def test_to_csv(self):
        gen = ReportGenerator(self._sample_findings())
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            gen.to_csv(path)
            with open(path) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 4  # header + 3 rows
        finally:
            os.unlink(path)

    def test_to_sarif(self):
        gen = ReportGenerator(self._sample_findings(), timestamp="2026-03-22T15:30:00+00:00")
        fd, path = tempfile.mkstemp(suffix=".sarif")
        os.close(fd)
        try:
            gen.to_sarif(path)
            with open(path) as f:
                data = json.load(f)
            assert data["version"] == "2.1.0"
            run = data["runs"][0]
            assert run["automationDetails"]["id"] == "cloud-cspm/local-scan"
            assert len(run["results"]) == 2
            assert {result["ruleId"] for result in run["results"]} == {"T-2", "T-3"}
            for result in run["results"]:
                location = result["locations"][0]
                assert location["physicalLocation"]["artifactLocation"]["uri"].startswith(
                    "aws-resource://"
                )
                assert location["physicalLocation"]["region"]["startLine"] == 1
                assert "primaryLocationLineHash" in result["partialFingerprints"]
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# module imports
# ---------------------------------------------------------------------------


class TestImports:
    def test_import_all_scanners(self):
        from scanners import (
            EC2Scanner,
            IAMScanner,
            LambdaScanner,
            LoggingScanner,
            RDSScanner,
            S3Scanner,
        )

        assert IAMScanner is not None
        assert S3Scanner is not None
        assert EC2Scanner is not None
        assert RDSScanner is not None
        assert LoggingScanner is not None
        assert LambdaScanner is not None

    def test_severity_enum(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"

    def test_status_enum(self):
        assert Status.PASS.value == "PASS"
        assert Status.FAIL.value == "FAIL"
