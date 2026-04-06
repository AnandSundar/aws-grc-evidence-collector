"""Inspector Evidence Collector.

This collector gathers compliance evidence from AWS Inspector service, checking for
CVE (Common Vulnerabilities and Exposures) findings in EC2 instances.
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

# Mapping of CVSS score to priority
CVSS_PRIORITY_MAP = {
    (9.0, 10.0): Priority.CRITICAL.value,  # Critical
    (7.0, 8.9): Priority.HIGH.value,  # High
    (4.0, 6.9): Priority.MEDIUM.value,  # Medium
    (1.0, 3.9): Priority.LOW.value,  # Low
    (0.0, 0.9): Priority.INFO.value,  # Informational
}


class InspectorCollector(BaseCollector):
    """Collector for AWS Inspector CVE findings evidence.

    This collector implements CVE findings collection:
    1. Use list_findings with fixAvailable=YES filter
    2. Map CVSS score: 9.0-10.0 → CRITICAL, 7.0-8.9 → HIGH, 4.0-6.9 → MEDIUM
    3. Include CVE ID, CVSS score, affected package, fixed version, resource ARN
    4. Use paginators for all API calls
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "InspectorCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all Inspector evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting Inspector evidence collection...", "INFO")

        try:
            inspector2_client = self.get_client("inspector2")

            # Check if Inspector is enabled
            if not self._is_inspector_enabled(inspector2_client):
                self.log_colored(
                    "Inspector is not enabled in this account/region", "WARNING"
                )
                record = self.make_record(
                    resource_type="AWS::Inspector2::Account",
                    resource_id="inspector",
                    control_status=ControlStatus.UNKNOWN.value,
                    priority=Priority.INFO.value,
                    finding_title="Inspector Not Enabled",
                    finding_description="Inspector is not enabled in this account/region.",
                    compliance_frameworks=[
                        "NIST 800-53",
                        "CIS AWS Foundations Benchmark",
                        "SOC 2",
                        "PCI-DSS",
                    ],
                    remediation_available=True,
                    remediation_action="Enable Inspector to start scanning for vulnerabilities.",
                    raw_data={"enabled": False},
                )
                records.append(record)
                return records

            # Collect CVE findings
            records.extend(self._collect_cve_findings(inspector2_client))

            self.log_colored(
                f"Inspector collection complete: {len(records)} records", "SUCCESS"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error in Inspector collection: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::Inspector2::Account",
                resource_id="inspector",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Inspector Collection Failed",
                finding_description=f"Unable to collect Inspector findings: {error_code}",
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

    def _is_inspector_enabled(self, inspector2_client) -> bool:
        """Check if Inspector is enabled.

        Args:
            inspector2_client: Boto3 Inspector2 client.

        Returns:
            True if Inspector is enabled, False otherwise.
        """
        try:
            response = inspector2_client.batch_get_account_status(
                accountIds=[self.account_id]
            )
            statuses = response.get("accounts", [])

            if statuses:
                status = statuses[0].get("resourceState", {}).get("status", "")
                return status == "ENABLED"

            return False
        except ClientError as e:
            logger.error(f"Error checking Inspector status: {e}")
            return False

    def _collect_cve_findings(self, inspector2_client) -> List[EvidenceRecord]:
        """Collect Inspector CVE findings.

        Args:
            inspector2_client: Boto3 Inspector2 client.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            # Build filters for findings with fixes available
            filter_criteria = {
                "fixAvailable": ["YES"],
                "findingStatus": ["ACTIVE"],
            }

            # Get findings using paginator
            paginator = self.get_paginator("inspector2", "list_findings")

            for page in paginator.paginate(filterCriteria=filter_criteria):
                finding_arns = page.get("findings", [])

                if finding_arns:
                    # Get detailed findings
                    findings = self._get_findings_details(
                        inspector2_client, finding_arns
                    )

                    for finding in findings:
                        record = self._convert_finding_to_record(finding)
                        if record:
                            records.append(record)

            logger.info(f"Collected {len(records)} Inspector CVE findings")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error collecting Inspector findings: {error_code} - {e}")

        return records

    def _get_findings_details(
        self, inspector2_client, finding_arns: List[str]
    ) -> List[Dict[str, Any]]:
        """Get detailed information about Inspector findings.

        Args:
            inspector2_client: Boto3 Inspector2 client.
            finding_arns: List of finding ARNs.

        Returns:
            List of finding dictionaries.
        """
        findings = []

        try:
            # Inspector allows getting up to 100 findings at a time
            batch_size = 100

            for i in range(0, len(finding_arns), batch_size):
                batch = finding_arns[i : i + batch_size]

                response = inspector2_client.batch_get_findings(findingArns=batch)
                findings.extend(response.get("findings", []))

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error getting findings details: {error_code} - {e}")

        return findings

    def _convert_finding_to_record(self, finding: Dict[str, Any]) -> EvidenceRecord:
        """Convert an Inspector finding to an EvidenceRecord.

        Args:
            finding: Inspector finding dictionary.

        Returns:
            EvidenceRecord object.
        """
        try:
            # Extract finding details
            finding_arn = finding.get("findingArn", "")
            finding_id = finding.get("findingArn", "").split("/")[-1]
            title = finding.get("title", "")
            description = finding.get("description", "")

            # Extract severity information
            severity = finding.get("severity", "")
            cvss_score = finding.get("cvss2", {}).get("baseScore", 0.0)
            cvss_vector = finding.get("cvss2", {}).get("vectorString", "")

            # Extract CVE information
            vulnerabilities = finding.get("vulnerabilities", [])
            cve_ids = []
            for vuln in vulnerabilities:
                cve_id = vuln.get("id", "")
                if cve_id:
                    cve_ids.append(cve_id)

            # Extract resource details
            resources = finding.get("resources", [])
            if resources:
                resource = resources[0]
                resource_type = resource.get("type", "")
                resource_id = resource.get("id", "")
                resource_arn = (
                    resource.get("details", {})
                    .get("awsEc2Instance", {})
                    .get("iamInstanceProfileArn", "")
                )

                # Extract package information
                package_info = (
                    resource.get("details", {})
                    .get("awsEc2Instance", {})
                    .get("packages", [])
                )
                if package_info:
                    package_name = package_info[0].get("name", "")
                    package_version = package_info[0].get("version", "")
                else:
                    package_name = ""
                    package_version = ""
            else:
                resource_type = "AWS::Inspector2::Finding"
                resource_id = finding_id
                resource_arn = finding_arn
                package_name = ""
                package_version = ""

            # Extract remediation information
            remediation = finding.get("remediation", {})
            recommendation = remediation.get("recommendation", {})
            fixed_version = recommendation.get("text", "")

            # Map CVSS score to priority
            priority = self._map_cvss_to_priority(cvss_score)

            # Build enhanced description
            enhanced_description = description
            if cve_ids:
                enhanced_description += f" CVE IDs: {', '.join(cve_ids)}."
            if cvss_score > 0:
                enhanced_description += f" CVSS Score: {cvss_score}."
            if package_name:
                enhanced_description += (
                    f" Affected Package: {package_name} {package_version}."
                )
            if fixed_version:
                enhanced_description += f" Fixed Version: {fixed_version}."

            # Create remediation action
            remediation_action = self._get_remediation_action(
                cve_ids, package_name, package_version, fixed_version, resource_id
            )

            # Create the evidence record
            record = self.make_record(
                resource_type=resource_type or "AWS::Inspector2::Finding",
                resource_id=resource_id or finding_id,
                resource_arn=resource_arn,
                control_status=ControlStatus.FAIL.value,
                priority=priority,
                finding_title=title or f"Inspector CVE Finding: {finding_id}",
                finding_description=enhanced_description,
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                    "PCI-DSS",
                ],
                remediation_available=True,
                remediation_action=remediation_action,
                raw_data={
                    "finding_arn": finding_arn,
                    "finding_id": finding_id,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cve_ids": cve_ids,
                    "package_name": package_name,
                    "package_version": package_version,
                    "fixed_version": fixed_version,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "resource_arn": resource_arn,
                    "finding": finding,
                },
            )

            return record

        except Exception as e:
            logger.error(f"Error converting finding to record: {e}")
            return None

    def _map_cvss_to_priority(self, cvss_score: float) -> str:
        """Map CVSS score to priority level.

        Args:
            cvss_score: CVSS score (0.0-10.0).

        Returns:
            Priority level string.
        """
        for (min_score, max_score), priority in CVSS_PRIORITY_MAP.items():
            if min_score <= cvss_score <= max_score:
                return priority

        # Default to low priority
        return Priority.LOW.value

    def _get_remediation_action(
        self,
        cve_ids: List[str],
        package_name: str,
        package_version: str,
        fixed_version: str,
        resource_id: str,
    ) -> str:
        """Get remediation action for a finding.

        Args:
            cve_ids: List of CVE IDs.
            package_name: Name of the affected package.
            package_version: Version of the affected package.
            fixed_version: Fixed version of the package.
            resource_id: ID of the resource affected.

        Returns:
            Remediation action description.
        """
        # Build CVE list
        cve_list = ", ".join(cve_ids) if cve_ids else "Unknown CVE"

        # Build remediation message
        if package_name and fixed_version:
            remediation = f"Update {package_name} from version {package_version} to {fixed_version} or later on {resource_id} to fix {cve_list}."
        elif package_name:
            remediation = f"Update {package_name} on {resource_id} to fix {cve_list}."
        else:
            remediation = f"Apply security patches to {resource_id} to fix {cve_list}."

        return remediation
