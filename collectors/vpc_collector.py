"""VPC Evidence Collector.

This collector gathers compliance evidence from AWS VPC service, checking for
network security best practices and compliance requirements.
"""

import logging
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from collectors.base_collector import (
    BaseCollector,
    ControlStatus,
    EvidenceRecord,
    Priority,
)

logger = logging.getLogger(__name__)

# Database ports that should not be open to the world
DATABASE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1521: "Oracle",
    5439: "Redshift",
    8182: "Cassandra",
    27017: "MongoDB",
    6379: "Redis",
    5672: "RabbitMQ",
    9042: "Cassandra",
}

# Remote access ports that should not be open to the world
REMOTE_ACCESS_PORTS = {
    22: "SSH",
    3389: "RDP",
}


class VPCCollector(BaseCollector):
    """Collector for VPC network security and compliance evidence.

    This collector implements 6 VPC network security checks:
    1. VPC flow logs enabled
    2. Default security groups (should have no rules)
    3. Open SSH port (22) to 0.0.0.0/0
    4. Open RDP port (3389) to 0.0.0.0/0
    5. Open database ports to 0.0.0.0/0
    6. Security groups with overly permissive rules (0.0.0.0/0)
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "VPCCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all VPC evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting VPC evidence collection...", "INFO")

        # Check 1: VPC flow logs enabled
        records.extend(self._check_flow_logs())

        # Check 2: Default security groups
        records.extend(self._check_default_security_groups())

        # Check 3-6: Security group rules
        records.extend(self._check_security_group_rules())

        self.log_colored(f"VPC collection complete: {len(records)} records", "SUCCESS")
        return records

    def _check_flow_logs(self) -> List[EvidenceRecord]:
        """Check if VPCs have flow logs enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            ec2_client = self.get_client("ec2")

            # Get all VPCs
            vpc_paginator = self.get_paginator("ec2", "describe_vpcs")
            vpcs = []

            for page in vpc_paginator.paginate():
                vpcs.extend(page.get("Vpcs", []))

            # Get flow logs for all VPCs
            flow_logs_paginator = self.get_paginator("ec2", "describe_flow_logs")
            flow_logs = []

            for page in flow_logs_paginator.paginate():
                flow_logs.extend(page.get("FlowLogs", []))

            # Create a mapping of VPC ID to flow log status
            vpc_flow_logs = {}
            for flow_log in flow_logs:
                resource_id = flow_log.get("ResourceId", "")
                flow_log_id = flow_log.get("FlowLogId", "")
                status = flow_log.get("FlowLogStatus", "")

                if resource_id.startswith("vpc-"):
                    vpc_flow_logs[resource_id] = {
                        "flow_log_id": flow_log_id,
                        "status": status,
                        "enabled": status == "ACTIVE",
                    }

            # Check each VPC
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                vpc_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:vpc/{vpc_id}"
                is_default = vpc.get("IsDefault", False)
                cidr = vpc.get("CidrBlock", "")

                # Skip default VPC for flow log check (optional)
                if is_default:
                    continue

                flow_log_info = vpc_flow_logs.get(vpc_id, {})

                if flow_log_info.get("enabled", False):
                    record = self.make_record(
                        resource_type="AWS::EC2::VPC",
                        resource_id=vpc_id,
                        resource_arn=vpc_arn,
                        control_status=ControlStatus.PASS.value,
                        priority=Priority.INFO.value,
                        finding_title=f"VPC {vpc_id} Has Flow Logs",
                        finding_description=f"VPC {vpc_id} ({cidr}) has flow logs enabled.",
                        compliance_frameworks=[
                            "NIST 800-53",
                            "CIS AWS Foundations Benchmark",
                            "SOC 2",
                            "PCI-DSS",
                        ],
                        remediation_available=False,
                        raw_data={
                            "vpc_id": vpc_id,
                            "cidr": cidr,
                            "flow_log_id": flow_log_info.get("flow_log_id"),
                            "flow_log_status": flow_log_info.get("status"),
                        },
                    )
                    records.append(record)
                else:
                    record = self.make_record(
                        resource_type="AWS::EC2::VPC",
                        resource_id=vpc_id,
                        resource_arn=vpc_arn,
                        control_status=ControlStatus.FAIL.value,
                        priority=Priority.HIGH.value,
                        finding_title=f"VPC {vpc_id} No Flow Logs",
                        finding_description=f"VPC {vpc_id} ({cidr}) does not have flow logs enabled.",
                        compliance_frameworks=[
                            "NIST 800-53",
                            "CIS AWS Foundations Benchmark",
                            "SOC 2",
                            "PCI-DSS",
                        ],
                        remediation_available=True,
                        remediation_action=f"Enable VPC flow logs for VPC {vpc_id} to monitor network traffic.",
                        raw_data={
                            "vpc_id": vpc_id,
                            "cidr": cidr,
                            "flow_logs_enabled": False,
                        },
                    )
                    records.append(record)
                    self.log_colored(f"[FAIL] VPC {vpc_id} has no flow logs", "WARNING")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking VPC flow logs: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::EC2::VPC",
                resource_id="all_vpcs",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="VPC Flow Logs Check Failed",
                finding_description=f"Unable to check VPC flow logs: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                    "PCI-DSS",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_default_security_groups(self) -> List[EvidenceRecord]:
        """Check if default security groups have no rules.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            ec2_client = self.get_client("ec2")
            paginator = self.get_paginator("ec2", "describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg["GroupName"]
                    sg_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:security-group/{sg_id}"

                    # Check if this is a default security group
                    if sg_name == "default":
                        inbound_rules = sg.get("IpPermissions", [])
                        outbound_rules = sg.get("IpPermissionsEgress", [])

                        # Default security groups should have no rules
                        if not inbound_rules and not outbound_rules:
                            record = self.make_record(
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                resource_arn=sg_arn,
                                control_status=ControlStatus.PASS.value,
                                priority=Priority.INFO.value,
                                finding_title=f"Default Security Group {sg_id} Has No Rules",
                                finding_description=f"Default security group {sg_id} has no rules, which is the recommended configuration.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                    "PCI-DSS",
                                ],
                                remediation_available=False,
                                raw_data={
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "inbound_rules": len(inbound_rules),
                                    "outbound_rules": len(outbound_rules),
                                },
                            )
                            records.append(record)
                        else:
                            record = self.make_record(
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                resource_arn=sg_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.HIGH.value,
                                finding_title=f"Default Security Group {sg_id} Has Rules",
                                finding_description=f"Default security group {sg_id} has {len(inbound_rules)} inbound and {len(outbound_rules)} outbound rules. Default security groups should not have rules.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                    "PCI-DSS",
                                ],
                                remediation_available=True,
                                remediation_action=f"Remove all rules from default security group {sg_id} and use custom security groups instead.",
                                raw_data={
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "inbound_rules": inbound_rules,
                                    "outbound_rules": outbound_rules,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"[FAIL] Default security group {sg_id} has rules", "WARNING"
                            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking default security groups: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::EC2::SecurityGroup",
                resource_id="all_security_groups",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Default Security Group Check Failed",
                finding_description=f"Unable to check default security groups: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                    "PCI-DSS",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_security_group_rules(self) -> List[EvidenceRecord]:
        """Check security group rules for overly permissive access.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            ec2_client = self.get_client("ec2")
            paginator = self.get_paginator("ec2", "describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg["GroupName"]
                    sg_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:security-group/{sg_id}"

                    # Skip default security groups (already checked)
                    if sg_name == "default":
                        continue

                    # Check inbound rules
                    inbound_rules = sg.get("IpPermissions", [])
                    for rule in inbound_rules:
                        records.extend(
                            self._check_rule(sg_id, sg_name, sg_arn, rule, "inbound")
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking security group rules: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::EC2::SecurityGroup",
                resource_id="all_security_groups",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Security Group Rules Check Failed",
                finding_description=f"Unable to check security group rules: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                    "PCI-DSS",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_rule(
        self,
        sg_id: str,
        sg_name: str,
        sg_arn: str,
        rule: Dict[str, Any],
        direction: str,
    ) -> List[EvidenceRecord]:
        """Check a single security group rule for issues.

        Args:
            sg_id: Security group ID.
            sg_name: Security group name.
            sg_arn: Security group ARN.
            rule: Security group rule dictionary.
            direction: Rule direction (inbound/outbound).

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            # Get IP ranges
            ip_ranges = rule.get("IpRanges", [])
            ipv6_ranges = rule.get("Ipv6Ranges", [])

            # Check for 0.0.0.0/0 or ::/0 (open to the world)
            for ip_range in ip_ranges:
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    # Get protocol and port
                    ip_protocol = rule.get("IpProtocol", "")
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")

                    # Check if this is a sensitive port
                    if from_port and to_port:
                        # Check remote access ports
                        if from_port == 22 and to_port == 22:
                            record = self.make_record(
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                resource_arn=sg_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.CRITICAL.value,
                                finding_title=f"Security Group {sg_id} Open SSH to World",
                                finding_description=f"Security group {sg_name} ({sg_id}) allows SSH (port 22) access from 0.0.0.0/0.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                    "PCI-DSS",
                                ],
                                remediation_available=True,
                                remediation_action=f"Restrict SSH access in security group {sg_id} to specific IP ranges or use a bastion host.",
                                raw_data={
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "direction": direction,
                                    "ip_protocol": ip_protocol,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "cidr": cidr,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"[FAIL] Security group {sg_id} open SSH to world", "ERROR"
                            )

                        # Check RDP port
                        elif from_port == 3389 and to_port == 3389:
                            record = self.make_record(
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                resource_arn=sg_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.CRITICAL.value,
                                finding_title=f"Security Group {sg_id} Open RDP to World",
                                finding_description=f"Security group {sg_name} ({sg_id}) allows RDP (port 3389) access from 0.0.0.0/0.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                    "PCI-DSS",
                                ],
                                remediation_available=True,
                                remediation_action=f"Restrict RDP access in security group {sg_id} to specific IP ranges or use a bastion host.",
                                raw_data={
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "direction": direction,
                                    "ip_protocol": ip_protocol,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "cidr": cidr,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"[FAIL] Security group {sg_id} open RDP to world", "ERROR"
                            )

                        # Check database ports
                        elif from_port in DATABASE_PORTS:
                            db_name = DATABASE_PORTS[from_port]
                            record = self.make_record(
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                resource_arn=sg_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.CRITICAL.value,
                                finding_title=f"Security Group {sg_id} Open {db_name} to World",
                                finding_description=f"Security group {sg_name} ({sg_id}) allows {db_name} (port {from_port}) access from 0.0.0.0/0.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                    "PCI-DSS",
                                ],
                                remediation_available=True,
                                remediation_action=f"Restrict {db_name} access in security group {sg_id} to specific IP ranges or security groups.",
                                raw_data={
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "direction": direction,
                                    "ip_protocol": ip_protocol,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "cidr": cidr,
                                    "database": db_name,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"[FAIL] Security group {sg_id} open {db_name} to world",
                                "ERROR",
                            )

                        # Check for all ports open
                        elif ip_protocol == "-1":
                            record = self.make_record(
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                resource_arn=sg_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.CRITICAL.value,
                                finding_title=f"Security Group {sg_id} All Ports Open to World",
                                finding_description=f"Security group {sg_name} ({sg_id}) allows all traffic from 0.0.0.0/0.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                    "PCI-DSS",
                                ],
                                remediation_available=True,
                                remediation_action=f"Restrict traffic in security group {sg_id} to specific ports and IP ranges.",
                                raw_data={
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "direction": direction,
                                    "ip_protocol": ip_protocol,
                                    "cidr": cidr,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"[FAIL] Security group {sg_id} all ports open to world",
                                "ERROR",
                            )

                        # Other ports open to world
                        else:
                            record = self.make_record(
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                resource_arn=sg_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.HIGH.value,
                                finding_title=f"Security Group {sg_id} Open Port {from_port} to World",
                                finding_description=f"Security group {sg_name} ({sg_id}) allows port {from_port}-{to_port} access from 0.0.0.0/0.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                    "PCI-DSS",
                                ],
                                remediation_available=True,
                                remediation_action=f"Review and restrict port {from_port}-{to_port} access in security group {sg_id}.",
                                raw_data={
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "direction": direction,
                                    "ip_protocol": ip_protocol,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "cidr": cidr,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"[FAIL] Security group {sg_id} open port {from_port} to world",
                                "WARNING",
                            )

            # Check IPv6 ranges
            for ipv6_range in ipv6_ranges:
                cidr = ipv6_range.get("CidrIpv6", "")
                if cidr == "::/0":
                    # Similar checks for IPv6
                    ip_protocol = rule.get("IpProtocol", "")
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")

                    record = self.make_record(
                        resource_type="AWS::EC2::SecurityGroup",
                        resource_id=sg_id,
                        resource_arn=sg_arn,
                        control_status=ControlStatus.FAIL.value,
                        priority=Priority.HIGH.value,
                        finding_title=f"Security Group {sg_id} Open to IPv6 World",
                        finding_description=f"Security group {sg_name} ({sg_id}) allows traffic from ::/0 (all IPv6 addresses).",
                        compliance_frameworks=[
                            "NIST 800-53",
                            "CIS AWS Foundations Benchmark",
                            "SOC 2",
                            "PCI-DSS",
                        ],
                        remediation_available=True,
                        remediation_action=f"Restrict IPv6 access in security group {sg_id} to specific IP ranges.",
                        raw_data={
                            "sg_id": sg_id,
                            "sg_name": sg_name,
                            "direction": direction,
                            "ip_protocol": ip_protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr_ipv6": cidr,
                        },
                    )
                    records.append(record)
                    self.log_colored(
                        f"[FAIL] Security group {sg_id} open to IPv6 world", "WARNING"
                    )

        except Exception as e:
            logger.error(f"Error checking rule: {e}")

        return records
