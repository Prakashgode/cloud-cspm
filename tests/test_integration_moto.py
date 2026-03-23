import json

import boto3
from moto import mock_aws

from scanners.base_scanner import Status
from scanners.s3_scanner import S3Scanner


def _harden_bucket(s3, bucket_name: str) -> None:
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyInsecureTransport",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}",
                            f"arn:aws:s3:::{bucket_name}/*",
                        ],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ],
            }
        ),
    )


@mock_aws
def test_s3_scanner_detects_secure_and_insecure_buckets_with_moto():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    secure_bucket = "portfolio-secure-bucket"
    insecure_bucket = "portfolio-insecure-bucket"

    s3.create_bucket(Bucket=secure_bucket)
    s3.create_bucket(Bucket=insecure_bucket)
    _harden_bucket(s3, secure_bucket)

    findings = S3Scanner(session).scan()
    by_key = {(finding.resource_id, finding.check_id): finding for finding in findings}

    assert by_key[(secure_bucket, "CIS-3.1")].status == Status.PASS
    assert by_key[(secure_bucket, "CIS-3.2")].status == Status.PASS
    assert by_key[(secure_bucket, "CIS-3.3")].status == Status.PASS
    assert by_key[(secure_bucket, "CIS-3.5")].status == Status.PASS

    assert by_key[(insecure_bucket, "CIS-3.1")].status == Status.FAIL
    assert by_key[(insecure_bucket, "CIS-3.2")].status == Status.FAIL
    assert by_key[(insecure_bucket, "CIS-3.3")].status == Status.FAIL
    assert by_key[(insecure_bucket, "CIS-3.5")].status == Status.FAIL
