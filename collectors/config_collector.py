"""AWS Config Evidence Collector.

This collector gathers compliance evidence from AWS Config service, checking
the compliance status of Config rules.
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

# Mapping of Config rule names to compliance frameworks
COMPLIANCE_TAG_MAP = {
    # S3 Rules
    "s3-bucket-server-side-encryption-enabled": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "s3-bucket-public-read-prohibited": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "s3-bucket-public-write-prohibited": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "s3-bucket-ssl-requests-only": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    # IAM Rules
    "iam-user-no-policies-check": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
    ],
    "iam-group-has-users-check": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
    ],
    "iam-password-policy": ["NIST 800-53", "CIS AWS Foundations Benchmark", "SOC 2"],
    "iam-root-access-key-check": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
    ],
    "iam-user-mfa-enabled": ["NIST 800-53", "CIS AWS Foundations Benchmark", "SOC 2"],
    # RDS Rules
    "rds-storage-encrypted": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "rds-instance-public-access-check": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "rds-automatic-minor-version-upgrade-check": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
    ],
    "rds-snapshot-encrypted": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    # VPC Rules
    "vpc-sg-open-only-to-authorized-ports": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "vpc-flow-logs-enabled": ["NIST 800-53", "CIS AWS Foundations Benchmark", "SOC 2"],
    # EC2 Rules
    "ec2-instance-no-public-ip": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "ec2-security-group-attached-to-eni": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
    ],
    # CloudTrail Rules
    "cloud-trail-enabled": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "cloud-trail-encryption-enabled": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "cloud-trail-log-file-validation-enabled": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
}


class ConfigCollector(BaseCollector):
    """Collector for AWS Config compliance evidence.

    This collector implements 20 AWS Config rules checks:
    1. s3-bucket-server-side-encryption-enabled
    2. s3-bucket-public-read-prohibited
    3. s3-bucket-public-write-prohibited
    4. s3-bucket-ssl-requests-only
    5. iam-user-no-policies-check
    6. iam-group-has-users-check
    7. iam-password-policy
    8. iam-root-access-key-check
    9. iam-user-mfa-enabled
    10. rds-storage-encrypted
    11. rds-instance-public-access-check
    12. rds-automatic-minor-version-upgrade-check
    13. rds-snapshot-encrypted
    14. vpc-sg-open-only-to-authorized-ports
    15. vpc-flow-logs-enabled
    16. ec2-instance-no-public-ip
    17. ec2-security-group-attached-to-eni
    18. cloud-trail-enabled
    19. cloud-trail-encryption-enabled
    20. cloud-trail-log-file-validation-enabled
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "ConfigCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all AWS Config evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting AWS Config evidence collection...", "INFO")

        try:
            config_client = self.get_client("config")

            # Get compliance status for all Config rules
            records.extend(self._collect_rule_compliance(config_client))

            self.log_colored(
                f"Config collection complete: {len(records)} records", "SUCCESS"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error in Config collection: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::Config::Rule",
                resource_id="all_rules",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Config Collection Failed",
                finding_description=f"Unable to collect Config compliance data: {error_code}",
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

    def _collect_rule_compliance(self, config_client) -> List[EvidenceRecord]:
        """Collect compliance data for all Config rules.

        Args:
            config_client: Boto3 Config client.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            # Get compliance summary by config rule
            paginator = self.get_paginator(
                "config", "describe_compliance_by_config_rule"
            )

            for page in paginator.paginate():
                for rule_compliance in page.get("ComplianceByConfigRules", []):
                    rule_name = rule_compliance.get("ConfigRuleName", "")
                    compliance_type = rule_compliance.get("Compliance", {}).get(
                        "ComplianceType", "INSUFFICIENT_DATA"
                    )

                    # Get compliance frameworks for this rule
                    compliance_frameworks = COMPLIANCE_TAG_MAP.get(
                        rule_name, ["NIST 800-53", "SOC 2"]
                    )

                    # Get detailed compliance information
                    rule_details = self._get_rule_details(config_client, rule_name)

                    # Determine control status and priority
                    control_status, priority = self._map_compliance_to_status(
                        compliance_type
                    )

                    # Create record for the rule itself
                    record = self.make_record(
                        resource_type="AWS::Config::Rule",
                        resource_id=rule_name,
                        resource_arn=f"arn:aws:config:{self.region}:{self.account_id}:config-rule/{rule_name}",
                        control_status=control_status,
                        priority=priority,
                        finding_title=f"Config Rule {rule_name}: {compliance_type}",
                        finding_description=self._get_rule_description(
                            rule_name, compliance_type, rule_details
                        ),
                        compliance_frameworks=compliance_frameworks,
                        remediation_available=compliance_type == "NON_COMPLIANT",
                        remediation_action=self._get_rule_remediation(rule_name),
                        raw_data={
                            "rule_name": rule_name,
                            "compliance_type": compliance_type,
                            "rule_details": rule_details,
                        },
                    )
                    records.append(record)

                    # If non-compliant, get detailed resource compliance
                    if compliance_type == "NON_COMPLIANT":
                        resource_records = self._get_non_compliant_resources(
                            config_client, rule_name, compliance_frameworks
                        )
                        records.extend(resource_records)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error collecting rule compliance: {error_code} - {e}")

        return records

    def _get_rule_details(self, config_client, rule_name: str) -> Dict[str, Any]:
        """Get detailed information about a Config rule.

        Args:
            config_client: Boto3 Config client.
            rule_name: Name of the Config rule.

        Returns:
            Dictionary with rule details.
        """
        try:
            response = config_client.describe_config_rules(ConfigRuleNames=[rule_name])

            if response.get("ConfigRules"):
                rule = response["ConfigRules"][0]
                return {
                    "rule_name": rule.get("ConfigRuleName", ""),
                    "rule_arn": rule.get("ConfigRuleArn", ""),
                    "description": rule.get("Description", ""),
                    "source": rule.get("Source", {}).get("Owner", ""),
                    "input_parameters": rule.get("InputParameters", ""),
                    "scope": rule.get("Scope", {}),
                }

        except ClientError as e:
            logger.error(f"Error getting details for rule {rule_name}: {e}")

        return {}

    def _get_non_compliant_resources(
        self, config_client, rule_name: str, compliance_frameworks: List[str]
    ) -> List[EvidenceRecord]:
        """Get non-compliant resources for a Config rule.

        Args:
            config_client: Boto3 Config client.
            rule_name: Name of the Config rule.
            compliance_frameworks: List of compliance frameworks.

        Returns:
            List of EvidenceRecord objects for non-compliant resources.
        """
        records: List[EvidenceRecord] = []

        try:
            paginator = self.get_paginator(
                "config", "get_compliance_details_by_config_rule"
            )

            for page in paginator.paginate(
                ConfigRuleName=rule_name, ComplianceTypes=["NON_COMPLIANT"]
            ):
                for evaluation_result in page.get("EvaluationResults", []):
                    resource_type = evaluation_result.get(
                        "EvaluationResultIdentifier", {}
                    ).get("ResourceType", "")
                    resource_id = evaluation_result.get(
                        "EvaluationResultIdentifier", {}
                    ).get("ResourceId", "")

                    record = self.make_record(
                        resource_type=resource_type,
                        resource_id=resource_id,
                        resource_arn=evaluation_result.get(
                            "EvaluationResultIdentifier", {}
                        ).get("ResourceEvaluationId", ""),
                        control_status=ControlStatus.FAIL.value,
                        priority=Priority.HIGH.value,
                        finding_title=f"Non-Compliant Resource: {resource_id}",
                        finding_description=f"Resource {resource_id} ({resource_type}) is non-compliant with Config rule {rule_name}.",
                        compliance_frameworks=compliance_frameworks,
                        remediation_available=True,
                        remediation_action=f"Review and remediate resource {resource_id} to comply with {rule_name}.",
                        raw_data={
                            "rule_name": rule_name,
                            "resource_type": resource_type,
                            "resource_id": resource_id,
                            "evaluation_result": evaluation_result,
                        },
                    )
                    records.append(record)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(
                f"Error getting non-compliant resources for rule {rule_name}: {error_code} - {e}"
            )

        return records

    def _map_compliance_to_status(self, compliance_type: str) -> tuple:
        """Map AWS Config compliance type to control status and priority.

        Args:
            compliance_type: AWS Config compliance type.

        Returns:
            Tuple of (control_status, priority).
        """
        if compliance_type == "COMPLIANT":
            return ControlStatus.PASS.value, Priority.INFO.value
        elif compliance_type == "NON_COMPLIANT":
            return ControlStatus.FAIL.value, Priority.HIGH.value
        elif compliance_type == "NOT_APPLICABLE":
            return ControlStatus.NOT_APPLICABLE.value, Priority.INFO.value
        else:  # INSUFFICIENT_DATA or unknown
            return ControlStatus.UNKNOWN.value, Priority.LOW.value

    def _get_rule_description(
        self, rule_name: str, compliance_type: str, rule_details: Dict[str, Any]
    ) -> str:
        """Get a human-readable description for a Config rule.

        Args:
            rule_name: Name of the Config rule.
            compliance_type: Compliance type of the rule.
            rule_details: Detailed information about the rule.

        Returns:
            Human-readable description.
        """
        descriptions = {
            "s3-bucket-server-side-encryption-enabled": "S3 buckets should have server-side encryption enabled.",
            "s3-bucket-public-read-prohibited": "S3 buckets should not allow public read access.",
            "s3-bucket-public-write-prohibited": "S3 buckets should not allow public write access.",
            "s3-bucket-ssl-requests-only": "S3 buckets should only accept SSL/TLS requests.",
            "iam-user-no-policies-check": "IAM users should not have inline policies attached.",
            "iam-group-has-users-check": "IAM groups should have at least one user.",
            "iam-password-policy": "IAM password policy should meet security requirements.",
            "iam-root-access-key-check": "Root account should not have access keys.",
            "iam-user-mfa-enabled": "IAM users should have MFA enabled.",
            "rds-storage-encrypted": "RDS instances should have storage encryption enabled.",
            "rds-instance-public-access-check": "RDS instances should not be publicly accessible.",
            "rds-automatic-minor-version-upgrade-check": "RDS instances should have automatic minor version upgrade enabled.",
            "rds-snapshot-encrypted": "RDS snapshots should be encrypted.",
            "vpc-sg-open-only-to-authorized-ports": "Security groups should only allow access to authorized ports.",
            "vpc-flow-logs-enabled": "VPCs should have flow logs enabled.",
            "ec2-instance-no-public-ip": "EC2 instances should not have public IP addresses.",
            "ec2-security-group-attached-to-eni": "Security groups should be attached to network interfaces.",
            "cloud-trail-enabled": "CloudTrail should be enabled.",
            "cloud-trail-encryption-enabled": "CloudTrail logs should be encrypted.",
            "cloud-trail-log-file-validation-enabled": "CloudTrail log file validation should be enabled.",
        }

        base_description = descriptions.get(rule_name, f"Config rule {rule_name}")

        if compliance_type == "COMPLIANT":
            return f"{base_description} Status: Compliant."
        elif compliance_type == "NON_COMPLIANT":
            return f"{base_description} Status: Non-Compliant. Action required."
        elif compliance_type == "NOT_APPLICABLE":
            return f"{base_description} Status: Not Applicable."
        else:
            return (
                f"{base_description} Status: Insufficient data to determine compliance."
            )

    def _get_rule_remediation(self, rule_name: str) -> str:
        """Get remediation action for a Config rule.

        Args:
            rule_name: Name of the Config rule.

        Returns:
            Remediation action description.
        """
        remediations = {
            "s3-bucket-server-side-encryption-enabled": "Enable default encryption on the S3 bucket using SSE-S3 or SSE-KMS.",
            "s3-bucket-public-read-prohibited": "Remove public read access from the S3 bucket policy and ACLs.",
            "s3-bucket-public-write-prohibited": "Remove public write access from the S3 bucket policy and ACLs.",
            "s3-bucket-ssl-requests-only": "Configure the bucket policy to deny non-SSL/TLS requests.",
            "iam-user-no-policies-check": "Move inline policies to managed policies and detach from users.",
            "iam-group-has-users-check": "Add users to the IAM group or delete the group if not needed.",
            "iam-password-policy": "Update the IAM password policy to meet security requirements.",
            "iam-root-access-key-check": "Delete any access keys associated with the root account.",
            "iam-user-mfa-enabled": "Enable MFA for the IAM user.",
            "rds-storage-encrypted": "Enable encryption at rest for the RDS instance (requires snapshot and restore).",
            "rds-instance-public-access-check": "Disable public accessibility for the RDS instance.",
            "rds-automatic-minor-version-upgrade-check": "Enable automatic minor version upgrade for the RDS instance.",
            "rds-snapshot-encrypted": "Copy the snapshot to an encrypted snapshot.",
            "vpc-sg-open-only-to-authorized-ports": "Review and restrict security group rules to only allow necessary ports.",
            "vpc-flow-logs-enabled": "Enable VPC flow logs for the VPC.",
            "ec2-instance-no-public-ip": "Remove the public IP address from the EC2 instance.",
            "ec2-security-group-attached-to-eni": "Attach security groups to network interfaces or delete unused security groups.",
            "cloud-trail-enabled": "Enable CloudTrail in the AWS account.",
            "cloud-trail-encryption-enabled": "Enable encryption for CloudTrail logs using KMS.",
            "cloud-trail-log-file-validation-enabled": "Enable log file validation for CloudTrail.",
        }

        return remediations.get(
            rule_name, "Review the Config rule documentation for remediation steps."
        )
