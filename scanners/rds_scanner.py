import boto3
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, Finding, Severity, Status


class RDSScanner(BaseScanner):
    # TODO: add Aurora cluster checks

    def scan(self) -> list[Finding]:
        regions = self._get_regions()
        for region in regions:
            rds = self.session.client("rds", region_name=region)
            self._check_instances(rds, region)
        return self.findings

    def _get_regions(self):
        ec2 = self.session.client("ec2")
        try:
            regions = ec2.describe_regions()["Regions"]
            return [r["RegionName"] for r in regions]
        except ClientError:
            return ["us-east-1"]

    def _check_instances(self, rds, region):
        try:
            instances = rds.describe_db_instances()["DBInstances"]
        except ClientError:
            return

        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            self._check_encryption(db, db_id, region)
            self._check_public_access(db, db_id, region)
            self._check_multi_az(db, db_id, region)
            self._check_auto_minor_upgrade(db, db_id, region)
            self._check_backup_retention(db, db_id, region)
            self._check_deletion_protection(db, db_id, region)

    def _check_encryption(self, db, db_id, region):
        encrypted = db.get("StorageEncrypted", False)
        self.add_finding(
            check_id="CIS-5.1",
            check_name="RDS Encryption at Rest",
            status=Status.PASS if encrypted else Status.FAIL,
            severity=Severity.HIGH,
            resource_id=db_id,
            resource_type="AWS::RDS::DBInstance",
            region=region,
            description=f"RDS instance '{db_id}' encryption is "
            + ("enabled" if encrypted else "NOT enabled"),
            remediation=f"Create encrypted snapshot and restore: aws rds create-db-snapshot && aws rds copy-db-snapshot --kms-key-id alias/aws/rds",
        )

    def _check_public_access(self, db, db_id, region):
        public = db.get("PubliclyAccessible", False)
        self.add_finding(
            check_id="CIS-5.2",
            check_name="RDS Public Access",
            status=Status.PASS if not public else Status.FAIL,
            severity=Severity.CRITICAL,
            resource_id=db_id,
            resource_type="AWS::RDS::DBInstance",
            region=region,
            description=f"RDS instance '{db_id}' is "
            + ("publicly accessible" if public else "not publicly accessible"),
            remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible",
        )

    def _check_multi_az(self, db, db_id, region):
        multi_az = db.get("MultiAZ", False)
        if not multi_az:
            self.add_finding(
                check_id="CIS-5.3",
                check_name="RDS Multi-AZ",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                region=region,
                description=f"RDS instance '{db_id}' does NOT have Multi-AZ enabled",
                remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --multi-az",
            )

    def _check_auto_minor_upgrade(self, db, db_id, region):
        auto_upgrade = db.get("AutoMinorVersionUpgrade", False)
        if not auto_upgrade:
            self.add_finding(
                check_id="CIS-5.4",
                check_name="RDS Auto Minor Upgrade",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                region=region,
                description=f"RDS instance '{db_id}' does NOT have auto minor version upgrade enabled",
                remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --auto-minor-version-upgrade",
            )

    def _check_backup_retention(self, db, db_id, region):
        retention = db.get("BackupRetentionPeriod", 0)
        if retention < 7:
            self.add_finding(
                check_id="CIS-5.5",
                check_name="RDS Backup Retention",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                region=region,
                description=f"RDS instance '{db_id}' backup retention is {retention} days (recommended: >= 7)",
                remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --backup-retention-period 7",
            )

    def _check_deletion_protection(self, db, db_id, region):
        protected = db.get("DeletionProtection", False)
        if not protected:
            self.add_finding(
                check_id="CIS-5.6",
                check_name="RDS Deletion Protection",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                region=region,
                description=f"RDS instance '{db_id}' does NOT have deletion protection enabled",
                remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --deletion-protection",
            )
