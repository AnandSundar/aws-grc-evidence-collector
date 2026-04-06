"""Security Hub Evidence Collector.

This collector gathers compliance evidence from AWS Security Hub service,
collecting security findings from enabled security standards.
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

# Security standards to enable
SECURITY_STANDARDS = [
    "aws-foundational-security-best-practices",
    "cis-aws-foundations-benchmark",
    "pci-dss",
]

# Mapping of Security Hub severity to priority
SEVERITY_PRIORITY_MAP = {
    "CRITICAL": Priority.CRITICAL.value,
    "HIGH": Priority.HIGH.value,
    "MEDIUM": Priority.MEDIUM.value,
    "LOW": Priority.LOW.value,
    "INFORMATIONAL": Priority.INFO.value,
}

# Mapping of Security Hub standards to compliance frameworks
STANDARDS_FRAMEWORK_MAP = {
    "aws-foundational-security-best-practices": ["NIST 800-53", "SOC 2", "PCI-DSS"],
    "cis-aws-foundations-benchmark": [
        "CIS AWS Foundations Benchmark",
        "NIST 800-53",
        "SOC 2",
    ],
    "pci-dss": ["PCI-DSS", "NIST 800-53", "SOC 2"],
}


class SecurityHubCollector(BaseCollector):
    """Collector for AWS Security Hub evidence.

    This collector implements Security Hub findings collection from:
    1. AWS Foundational Security Best Practices
    2. CIS AWS Foundations Benchmark
    3. PCI DSS

    It collects findings with filters for RecordState, WorkflowStatus, and SeverityLabel.
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "SecurityHubCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all Security Hub evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting Security Hub evidence collection...", "INFO")

        try:
            securityhub_client = self.get_client("securityhub")

            # Check if Security Hub is enabled
            if not self._is_securityhub_enabled(securityhub_client):
                self.log_colored(
                    "Security Hub is not enabled in this account/region", "WARNING"
                )
                record = self.make_record(
                    resource_type="AWS::SecurityHub::Hub",
                    resource_id="security-hub",
                    control_status=ControlStatus.UNKNOWN.value,
                    priority=Priority.INFO.value,
                    finding_title="Security Hub Not Enabled",
                    finding_description="Security Hub is not enabled in this account/region.",
                    compliance_frameworks=[
                        "NIST 800-53",
                        "CIS AWS Foundations Benchmark",
                        "SOC 2",
                        "PCI-DSS",
                    ],
                    remediation_available=True,
                    remediation_action="Enable Security Hub to start collecting security findings.",
                    raw_data={"enabled": False},
                )
                records.append(record)
                return records

            # Collect findings from all standards
            records.extend(self._collect_findings(securityhub_client))

            self.log_colored(
                f"Security Hub collection complete: {len(records)} records", "SUCCESS"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error in Security Hub collection: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::SecurityHub::Hub",
                resource_id="security-hub",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Security Hub Collection Failed",
                finding_description=f"Unable to collect Security Hub findings: {error_code}",
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

    def _is_securityhub_enabled(self, securityhub_client) -> bool:
        """Check if Security Hub is enabled.

        Args:
            securityhub_client: Boto3 Security Hub client.

        Returns:
            True if Security Hub is enabled, False otherwise.
        """
        try:
            securityhub_client.describe_hub()
            return True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return False
            raise

    def _collect_findings(self, securityhub_client) -> List[EvidenceRecord]:
        """Collect Security Hub findings from all enabled standards.

        Args:
            securityhub_client: Boto3 Security Hub client.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            # Build filters for active findings
            filters = {
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [
                    {"Value": "NEW", "Comparison": "EQUALS"},
                    {"Value": "NOTIFIED", "Comparison": "EQUALS"},
                ],
            }

            # Get findings using paginator
            paginator = self.get_paginator("securityhub", "get_findings")

            for page in paginator.paginate(Filters=filters):
                findings = page.get("Findings", [])

                for finding in findings:
                    record = self._convert_finding_to_record(finding)
                    if record:
                        records.append(record)

            logger.info(f"Collected {len(records)} Security Hub findings")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error collecting Security Hub findings: {error_code} - {e}")

        return records

    def _convert_finding_to_record(self, finding: Dict[str, Any]) -> EvidenceRecord:
        """Convert a Security Hub finding to an EvidenceRecord.

        Args:
            finding: Security Hub finding dictionary.

        Returns:
            EvidenceRecord object.
        """
        try:
            # Extract finding details
            finding_id = finding.get("Id", "")
            title = finding.get("Title", "")
            description = finding.get("Description", "")
            severity = finding.get("Severity", {})
            severity_label = severity.get("Label", "INFORMATIONAL")

            # Extract resource details
            resources = finding.get("Resources", [])
            if resources:
                resource = resources[0]
                resource_type = resource.get("Type", "")
                resource_id = resource.get("Id", "")
                resource_arn = (
                    resource.get("Details", {}).get("Other", {}).get("aws:arn", "")
                )
            else:
                resource_type = "AWS::SecurityHub::Finding"
                resource_id = finding_id
                resource_arn = ""

            # Extract compliance information
            compliance = finding.get("Compliance", {})
            compliance_standards = compliance.get("StatusReasons", [])

            # Determine compliance frameworks based on standards
            compliance_frameworks = self._get_compliance_frameworks(finding)

            # Map severity to priority
            priority = SEVERITY_PRIORITY_MAP.get(severity_label, Priority.INFO.value)

            # Determine control status based on workflow status
            workflow_status = finding.get("Workflow", {}).get("Status", "NEW")
            if workflow_status in ["NEW", "NOTIFIED"]:
                control_status = ControlStatus.FAIL.value
            elif workflow_status == "RESOLVED":
                control_status = ControlStatus.PASS.value
            else:
                control_status = ControlStatus.UNKNOWN.value

            # Extract remediation information
            remediation = finding.get("Remediation", {})
            remediation_available = bool(remediation.get("Recommendation", {}))
            remediation_action = remediation.get("Recommendation", {}).get("Text", "")

            # Extract product fields for additional context
            product_fields = finding.get("ProductFields", {})

            # Create the evidence record
            record = self.make_record(
                resource_type=resource_type,
                resource_id=resource_id,
                resource_arn=resource_arn,
                control_status=control_status,
                priority=priority,
                finding_title=title,
                finding_description=description,
                compliance_frameworks=compliance_frameworks,
                remediation_available=remediation_available,
                remediation_action=remediation_action,
                raw_data={
                    "finding_id": finding_id,
                    "finding": finding,
                    "product_fields": product_fields,
                },
            )

            return record

        except Exception as e:
            logger.error(f"Error converting finding to record: {e}")
            return None

    def _get_compliance_frameworks(self, finding: Dict[str, Any]) -> List[str]:
        """Get compliance frameworks for a finding.

        Args:
            finding: Security Hub finding dictionary.

        Returns:
            List of compliance framework names.
        """
        frameworks = []

        # Check for standards in the finding
        standards = finding.get("Standards", [])
        for standard in standards:
            standard_arn = standard.get("StandardsArn", "")

            # Map standard ARN to framework
            for std_name, std_frameworks in STANDARDS_FRAMEWORK_MAP.items():
                if std_name in standard_arn.lower():
                    frameworks.extend(std_frameworks)
                    break

        # Remove duplicates
        frameworks = list(set(frameworks))

        # If no frameworks found, use default
        if not frameworks:
            frameworks = ["NIST 800-53", "SOC 2"]

        return frameworks

    def _get_enabled_standards(self, securityhub_client) -> List[str]:
        """Get list of enabled Security Hub standards.

        Args:
            securityhub_client: Boto3 Security Hub client.

        Returns:
            List of enabled standard ARNs.
        """
        standards = []

        try:
            paginator = self.get_paginator(
                "securityhub", "list_enabled_standards_for_import"
            )

            for page in paginator.paginate():
                standards_subscriptions = page.get("StandardsSubscriptions", [])
                for subscription in standards_subscriptions:
                    standards_arn = subscription.get("StandardsArn", "")
                    standards.append(standards_arn)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error getting enabled standards: {error_code} - {e}")

        return standards
