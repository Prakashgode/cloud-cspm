import boto3
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, Finding, Severity, Status


class EC2Scanner(BaseScanner):
    # ports that should never be open to 0.0.0.0/0
    DANGEROUS_PORTS = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
    }

    def scan(self) -> list[Finding]:
        regions = self._get_regions()
        for region in regions:
            ec2 = self.session.client("ec2", region_name=region)
            self._check_security_groups(ec2, region)
            self._check_default_security_groups(ec2, region)
        return self.findings

    def _get_regions(self):
        ec2 = self.session.client("ec2")
        try:
            regions = ec2.describe_regions()["Regions"]
            return [r["RegionName"] for r in regions]
        except ClientError:
            return ["us-east-1"]

    def _check_security_groups(self, ec2, region):
        try:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)

                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr == "0.0.0.0/0":
                            self._report_open_port(
                                sg_id, sg_name, from_port, to_port, cidr, region
                            )

                    for ip_range in rule.get("Ipv6Ranges", []):
                        cidr = ip_range.get("CidrIpv6", "")
                        if cidr == "::/0":
                            self._report_open_port(
                                sg_id, sg_name, from_port, to_port, cidr, region
                            )
        except ClientError:
            pass

    def _report_open_port(self, sg_id, sg_name, from_port, to_port, cidr, region):
        for port, service in self.DANGEROUS_PORTS.items():
            if from_port <= port <= to_port:
                check_id = "CIS-4.1" if port == 22 else "CIS-4.2" if port == 3389 else "CIS-4.3"
                self.add_finding(
                    check_id=check_id,
                    check_name=f"Open {service} Port",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    resource_id=sg_id,
                    resource_type="AWS::EC2::SecurityGroup",
                    region=region,
                    description=f"Security group '{sg_name}' ({sg_id}) allows {service} (port {port}) from {cidr}",
                    remediation=f"Restrict port {port} access: aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port {port} --cidr {cidr}",
                )

    def _check_default_security_groups(self, ec2, region):
        try:
            sgs = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            )["SecurityGroups"]

            for sg in sgs:
                has_rules = bool(
                    sg.get("IpPermissions") or sg.get("IpPermissionsEgress")
                )
                egress_only = (
                    not sg.get("IpPermissions")
                    and len(sg.get("IpPermissionsEgress", [])) <= 1
                )

                if has_rules and not egress_only:
                    self.add_finding(
                        check_id="CIS-4.4",
                        check_name="Default Security Group",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_id=sg["GroupId"],
                        resource_type="AWS::EC2::SecurityGroup",
                        region=region,
                        description=f"Default security group in VPC '{sg.get('VpcId', 'N/A')}' has active rules",
                        remediation="Remove all inbound and outbound rules from the default security group",
                    )
        except ClientError:
            pass
