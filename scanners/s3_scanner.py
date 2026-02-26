import json
import boto3
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, Finding, Severity, Status


class S3Scanner(BaseScanner):
    def scan(self) -> list[Finding]:
        s3 = self.session.client("s3")
        try:
            buckets = s3.list_buckets()["Buckets"]
        except ClientError as e:
            self.add_finding(
                check_id="CIS-3.0",
                check_name="S3 Access",
                status=Status.ERROR,
                severity=Severity.HIGH,
                resource_id="s3-service",
                resource_type="AWS::S3::Service",
                region="global",
                description=f"Cannot list S3 buckets: {e}",
            )
            return self.findings

        for bucket in buckets:
            name = bucket["Name"]
            self._check_public_access(s3, name)
            self._check_encryption(s3, name)
            self._check_versioning(s3, name)

        return self.findings

    def _check_public_access(self, s3, bucket_name):
        try:
            public_access = s3.get_public_access_block(Bucket=bucket_name)
            config = public_access["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])

            self.add_finding(
                check_id="CIS-3.1",
                check_name="S3 Public Access Block",
                status=Status.PASS if all_blocked else Status.FAIL,
                severity=Severity.CRITICAL,
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                region="global",
                description=f"Bucket '{bucket_name}' public access is "
                + ("fully blocked" if all_blocked else "NOT fully blocked"),
                remediation=f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            )
        except ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                self.add_finding(
                    check_id="CIS-3.1",
                    check_name="S3 Public Access Block",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    region="global",
                    description=f"Bucket '{bucket_name}' has no public access block configuration",
                    remediation=f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                )

    def _check_encryption(self, s3, bucket_name):
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption["ServerSideEncryptionConfiguration"]["Rules"]
            algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            self.add_finding(
                check_id="CIS-3.2",
                check_name="S3 Encryption",
                status=Status.PASS,
                severity=Severity.HIGH,
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                region="global",
                description=f"Bucket '{bucket_name}' has encryption enabled ({algo})",
            )
        except ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                self.add_finding(
                    check_id="CIS-3.2",
                    check_name="S3 Encryption",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    region="global",
                    description=f"Bucket '{bucket_name}' does NOT have encryption enabled",
                    remediation=f"Enable default encryption on bucket {bucket_name}",
                )

    def _check_versioning(self, s3, bucket_name):
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            # bug: was checking wrong field name
            status = versioning.get("Versioning", "Disabled")
            self.add_finding(
                check_id="CIS-3.3",
                check_name="S3 Versioning",
                status=Status.PASS if status == "Enabled" else Status.FAIL,
                severity=Severity.MEDIUM,
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                region="global",
                description=f"Bucket '{bucket_name}' versioning is {status}",
                remediation=f"aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled",
            )
        except ClientError:
            pass
