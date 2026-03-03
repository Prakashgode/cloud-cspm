import boto3
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, Finding, Severity, Status


class LoggingScanner(BaseScanner):
    def scan(self) -> list[Finding]:
        regions = self._get_regions()
        self._check_cloudtrail(regions)
        self._check_vpc_flow_logs(regions)
        return self.findings

    def _get_regions(self):
        ec2 = self.session.client("ec2")
        try:
            regions = ec2.describe_regions()["Regions"]
            return [r["RegionName"] for r in regions]
        except ClientError:
            return ["us-east-1"]

    def _check_cloudtrail(self, regions):
        try:
            ct = self.session.client("cloudtrail")
            trails = ct.describe_trails()["trailList"]

            if not trails:
                self.add_finding(
                    check_id="CIS-2.1",
                    check_name="CloudTrail Enabled",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    resource_id="cloudtrail",
                    resource_type="AWS::CloudTrail::Trail",
                    region="global",
                    description="No CloudTrail trails are configured",
                    remediation="aws cloudtrail create-trail --name my-trail --s3-bucket-name my-trail-bucket --is-multi-region-trail",
                )
                return

            has_multi_region = False
            for trail in trails:
                trail_name = trail["Name"]
                trail_arn = trail["TrailARN"]
                is_multi_region = trail.get("IsMultiRegionTrail", False)

                if is_multi_region:
                    has_multi_region = True

                status = ct.get_trail_status(Name=trail_arn)
                is_logging = status.get("IsLogging", False)

                if not is_logging:
                    self.add_finding(
                        check_id="CIS-2.1",
                        check_name="CloudTrail Logging",
                        status=Status.FAIL,
                        severity=Severity.CRITICAL,
                        resource_id=trail_name,
                        resource_type="AWS::CloudTrail::Trail",
                        region="global",
                        description=f"CloudTrail '{trail_name}' is NOT actively logging",
                        remediation=f"aws cloudtrail start-logging --name {trail_name}",
                    )

                log_validation = trail.get("LogFileValidationEnabled", False)
                self.add_finding(
                    check_id="CIS-2.2",
                    check_name="CloudTrail Log Validation",
                    status=Status.PASS if log_validation else Status.FAIL,
                    severity=Severity.HIGH,
                    resource_id=trail_name,
                    resource_type="AWS::CloudTrail::Trail",
                    region="global",
                    description=f"CloudTrail '{trail_name}' log file validation is "
                    + ("enabled" if log_validation else "NOT enabled"),
                    remediation=f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation",
                )

                encryption = trail.get("KmsKeyId")
                if not encryption:
                    self.add_finding(
                        check_id="CIS-2.3",
                        check_name="CloudTrail Encryption",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_id=trail_name,
                        resource_type="AWS::CloudTrail::Trail",
                        region="global",
                        description=f"CloudTrail '{trail_name}' is NOT encrypted with KMS",
                        remediation=f"aws cloudtrail update-trail --name {trail_name} --kms-key-id <kms-key-arn>",
                    )

            if not has_multi_region:
                self.add_finding(
                    check_id="CIS-2.1",
                    check_name="CloudTrail Multi-Region",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    resource_id="cloudtrail",
                    resource_type="AWS::CloudTrail::Trail",
                    region="global",
                    description="No multi-region CloudTrail trail configured",
                    remediation="aws cloudtrail update-trail --name <trail-name> --is-multi-region-trail",
                )

        except ClientError as e:
            self.add_finding(
                check_id="CIS-2.1",
                check_name="CloudTrail Enabled",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                resource_id="cloudtrail",
                resource_type="AWS::CloudTrail::Trail",
                region="global",
                description=f"Error checking CloudTrail: {e}",
            )

    def _check_vpc_flow_logs(self, regions):
        for region in regions:
            try:
                ec2 = self.session.client("ec2", region_name=region)
                vpcs = ec2.describe_vpcs()["Vpcs"]

                for vpc in vpcs:
                    vpc_id = vpc["VpcId"]
                    flow_logs = ec2.describe_flow_logs(
                        Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                    )["FlowLogs"]

                    if not flow_logs:
                        self.add_finding(
                            check_id="CIS-2.4",
                            check_name="VPC Flow Logs",
                            status=Status.FAIL,
                            severity=Severity.HIGH,
                            resource_id=vpc_id,
                            resource_type="AWS::EC2::VPC",
                            region=region,
                            description=f"VPC '{vpc_id}' does NOT have flow logs enabled",
                            remediation=f"aws ec2 create-flow-logs --resource-ids {vpc_id} --resource-type VPC --traffic-type ALL --log-destination-type cloud-watch-logs",
                        )
            except ClientError:
                pass
