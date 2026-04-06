"""Macie Evidence Collector.

This collector gathers compliance evidence from AWS Macie service, checking for
PII (Personally Identifiable Information) discovery and data classification.
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

# Mapping of Macie sensitive data categories to priority
SENSITIVE_DATA_PRIORITY_MAP = {
    "CREDENTIALS": Priority.CRITICAL.value,
    "FINANCIAL_INFORMATION": Priority.CRITICAL.value,
    "PERSONAL_HEALTH_INFORMATION": Priority.CRITICAL.value,
    "PERSONAL_IDENTIFIERS": Priority.HIGH.value,
    "CUSTOM_IDENTIFIER": Priority.HIGH.value,
    "AWS_CREDENTIALS": Priority.CRITICAL.value,
    "default": Priority.MEDIUM.value,
}

# Mapping of Macie data types to human-readable names
DATA_TYPE_NAMES = {
    "AWS_CREDENTIALS": "AWS Credentials",
    "CREDIT_CARD_NUMBER": "Credit Card Number",
    "BANK_ACCOUNT_NUMBER": "Bank Account Number",
    "PHONE_NUMBER": "Phone Number",
    "EMAIL_ADDRESS": "Email Address",
    "PASSPORT_NUMBER": "Passport Number",
    "DRIVER_LICENSE": "Driver's License",
    "SOCIAL_SECURITY_NUMBER": "Social Security Number",
    "IBAN_CODE": "IBAN Code",
    "IP_ADDRESS": "IP Address",
    "MAC_ADDRESS": "MAC Address",
    "URL": "URL",
}


class MacieCollector(BaseCollector):
    """Collector for Macie PII discovery and compliance evidence.

    This collector implements PII discovery checks:
    1. Check Macie enabled status
    2. Collect active PII findings with sensitive data categories
    3. Map findings to priority based on data type
    4. Use paginators for all API calls
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "MacieCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all Macie evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting Macie evidence collection...", "INFO")

        try:
            macie2_client = self.get_client("macie2")

            # Check if Macie is enabled
            if not self._is_macie_enabled(macie2_client):
                self.log_colored(
                    "Macie is not enabled in this account/region", "WARNING"
                )
                record = self.make_record(
                    resource_type="AWS::Macie::Session",
                    resource_id="macie",
                    control_status=ControlStatus.UNKNOWN.value,
                    priority=Priority.INFO.value,
                    finding_title="Macie Not Enabled",
                    finding_description="Macie is not enabled in this account/region.",
                    compliance_frameworks=[
                        "NIST 800-53",
                        "CIS AWS Foundations Benchmark",
                        "SOC 2",
                        "PCI-DSS",
                        "GDPR",
                        "HIPAA",
                    ],
                    remediation_available=True,
                    remediation_action="Enable Macie to start discovering PII and sensitive data.",
                    raw_data={"enabled": False},
                )
                records.append(record)
                return records

            # Collect PII findings
            records.extend(self._collect_pii_findings(macie2_client))

            self.log_colored(
                f"Macie collection complete: {len(records)} records", "SUCCESS"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error in Macie collection: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::Macie::Session",
                resource_id="macie",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Macie Collection Failed",
                finding_description=f"Unable to collect Macie findings: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                    "PCI-DSS",
                    "GDPR",
                    "HIPAA",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _is_macie_enabled(self, macie2_client) -> bool:
        """Check if Macie is enabled.

        Args:
            macie2_client: Boto3 Macie2 client.

        Returns:
            True if Macie is enabled, False otherwise.
        """
        try:
            response = macie2_client.get_macie_session()
            status = response.get("status", "")
            return status == "ENABLED"
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return False
            raise

    def _collect_pii_findings(self, macie2_client) -> List[EvidenceRecord]:
        """Collect Macie PII findings.

        Args:
            macie2_client: Boto3 Macie2 client.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            # Build filters for active findings
            finding_criteria = {"criterion": {"status": {"eq": ["ACTIVE"]}}}

            # Get findings using paginator
            paginator = self.get_paginator("macie2", "list_findings")

            for page in paginator.paginate(findingCriteria=finding_criteria):
                finding_ids = page.get("findingIds", [])

                if finding_ids:
                    # Get detailed findings
                    findings = self._get_findings_details(macie2_client, finding_ids)

                    for finding in findings:
                        record = self._convert_finding_to_record(finding)
                        if record:
                            records.append(record)

            logger.info(f"Collected {len(records)} Macie PII findings")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error collecting Macie findings: {error_code} - {e}")

        return records

    def _get_findings_details(
        self, macie2_client, finding_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """Get detailed information about Macie findings.

        Args:
            macie2_client: Boto3 Macie2 client.
            finding_ids: List of finding IDs.

        Returns:
            List of finding dictionaries.
        """
        findings = []

        try:
            # Macie allows getting up to 100 findings at a time
            batch_size = 100

            for i in range(0, len(finding_ids), batch_size):
                batch = finding_ids[i : i + batch_size]

                response = macie2_client.get_findings(findingIds=batch)
                findings.extend(response.get("findings", []))

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error getting findings details: {error_code} - {e}")

        return findings

    def _convert_finding_to_record(self, finding: Dict[str, Any]) -> EvidenceRecord:
        """Convert a Macie finding to an EvidenceRecord.

        Args:
            finding: Macie finding dictionary.

        Returns:
            EvidenceRecord object.
        """
        try:
            # Extract finding details
            finding_id = finding.get("id", "")
            title = finding.get("title", "")
            description = finding.get("description", "")
            severity = finding.get("severity", {})
            severity_score = severity.get("score", 0)
            severity_description = severity.get("description", "")

            # Extract resource details
            resources = finding.get("resourcesAffected", [])
            if resources:
                resource = resources[0]
                resource_type = resource.get("s3Bucket", {}).get("arn", "")
                resource_id = resource.get("s3Bucket", {}).get("name", "")
            else:
                resource_type = "AWS::Macie::Finding"
                resource_id = finding_id

            # Extract sensitive data information
            sensitive_data = finding.get("sensitiveData", [])
            data_categories = []
            data_types = []

            for data_item in sensitive_data:
                category = data_item.get("category", "")
                data_categories.append(category)

                # Get data types
                item_types = data_item.get("detections", [])
                for item_type in item_types:
                    type_name = item_type.get("type", "")
                    data_types.append(type_name)

            # Determine priority based on sensitive data categories
            priority = self._map_data_categories_to_priority(data_categories)

            # Get compliance frameworks
            compliance_frameworks = self._get_compliance_frameworks(data_categories)

            # Build enhanced description
            enhanced_description = description
            if data_categories:
                category_names = [
                    DATA_TYPE_NAMES.get(cat, cat) for cat in data_categories
                ]
                enhanced_description += (
                    f" Sensitive data categories: {', '.join(category_names)}."
                )
            if data_types:
                type_names = [DATA_TYPE_NAMES.get(dt, dt) for dt in data_types]
                enhanced_description += f" Data types: {', '.join(type_names)}."

            # Extract location information
            location = finding.get("sample", False)

            # Create remediation action
            remediation_action = self._get_remediation_action(
                data_categories, resource_id
            )

            # Create the evidence record
            record = self.make_record(
                resource_type=resource_type or "AWS::Macie::Finding",
                resource_id=resource_id or finding_id,
                resource_arn=resource_type if resource_type else "",
                control_status=ControlStatus.FAIL.value,
                priority=priority,
                finding_title=title or f"Macie PII Finding: {finding_id}",
                finding_description=enhanced_description,
                compliance_frameworks=compliance_frameworks,
                remediation_available=True,
                remediation_action=remediation_action,
                raw_data={
                    "finding_id": finding_id,
                    "severity_score": severity_score,
                    "severity_description": severity_description,
                    "data_categories": data_categories,
                    "data_types": data_types,
                    "location": location,
                    "finding": finding,
                },
            )

            return record

        except Exception as e:
            logger.error(f"Error converting finding to record: {e}")
            return None

    def _map_data_categories_to_priority(self, data_categories: List[str]) -> str:
        """Map sensitive data categories to priority level.

        Args:
            data_categories: List of sensitive data categories.

        Returns:
            Priority level string.
        """
        # Check for critical categories first
        for category in data_categories:
            if category in SENSITIVE_DATA_PRIORITY_MAP:
                priority = SENSITIVE_DATA_PRIORITY_MAP[category]
                if priority == Priority.CRITICAL.value:
                    return priority

        # If no critical category found, check for high priority
        for category in data_categories:
            if category in SENSITIVE_DATA_PRIORITY_MAP:
                priority = SENSITIVE_DATA_PRIORITY_MAP[category]
                if priority == Priority.HIGH.value:
                    return priority

        # Default to medium priority
        return SENSITIVE_DATA_PRIORITY_MAP.get("default", Priority.MEDIUM.value)

    def _get_compliance_frameworks(self, data_categories: List[str]) -> List[str]:
        """Get compliance frameworks based on sensitive data categories.

        Args:
            data_categories: List of sensitive data categories.

        Returns:
            List of compliance framework names.
        """
        frameworks = ["NIST 800-53", "CIS AWS Foundations Benchmark", "SOC 2"]

        # Add PCI-DSS for financial information
        if "FINANCIAL_INFORMATION" in data_categories:
            frameworks.append("PCI-DSS")

        # Add HIPAA for personal health information
        if "PERSONAL_HEALTH_INFORMATION" in data_categories:
            frameworks.append("HIPAA")

        # Add GDPR for personal identifiers
        if "PERSONAL_IDENTIFIERS" in data_categories:
            frameworks.append("GDPR")

        # Remove duplicates
        frameworks = list(set(frameworks))

        return frameworks

    def _get_remediation_action(
        self, data_categories: List[str], resource_id: str
    ) -> str:
        """Get remediation action for a finding.

        Args:
            data_categories: List of sensitive data categories.
            resource_id: ID of the resource affected.

        Returns:
            Remediation action description.
        """
        # Check for critical categories
        if "CREDENTIALS" in data_categories or "AWS_CREDENTIALS" in data_categories:
            return f"CRITICAL: Credentials found in {resource_id}. Immediately remove or encrypt the credentials and rotate any exposed keys."

        if "FINANCIAL_INFORMATION" in data_categories:
            return f"CRITICAL: Financial information found in {resource_id}. Encrypt the data and restrict access to authorized personnel only."

        if "PERSONAL_HEALTH_INFORMATION" in data_categories:
            return f"CRITICAL: Personal health information found in {resource_id}. Ensure HIPAA compliance by encrypting the data and implementing access controls."

        if "PERSONAL_IDENTIFIERS" in data_categories:
            return f"Review PII data in {resource_id}. Ensure GDPR compliance by implementing proper data protection measures."

        # Default remediation
        return f"Review sensitive data in {resource_id} and ensure proper protection measures are in place."
