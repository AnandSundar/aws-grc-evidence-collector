"""GuardDuty Evidence Collector.

This collector gathers compliance evidence from AWS GuardDuty service,
collecting security findings from threat detection.
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

# Mapping of GuardDuty finding types to compliance frameworks
FINDING_TYPE_COMPLIANCE_MAP = {
    # CryptoCurrency
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": ["NIST 800-53", "SOC 2"],
    "CryptoCurrency:EC2/BitcoinTool.B!TCP": ["NIST 800-53", "SOC 2"],
    # Backdoor
    "Backdoor:EC2/C&CActivity.B!DNS": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "Backdoor:EC2/DenialOfService.TcpFlood": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "Backdoor:EC2/Spambot": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    # Behavior
    "Behavior:EC2/NetworkPortUnusual": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
    ],
    "Behavior:EC2/TorIPCaller": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "Behavior:EC2/TorRelay": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    # Trojan
    "Trojan:EC2/BlackholeTraffic": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "Trojan:EC2/DGADomainRequest.B": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "Trojan:EC2/DriveByDownloadTraffic!DNS": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    # Policy
    "Policy:IAMUser/S3BucketAccess": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "Policy:IAMUser/RootCredentialUsage": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "Policy:S3/BucketPublicAccess": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    # Stealth
    "Stealth:IAMUser/UserPermissions": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
    ],
    # Discovery
    "Discovery:S3/MaliciousIPCaller": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
        "PCI-DSS",
    ],
    "Discovery:EC2/PortScanUnusualPort": [
        "NIST 800-53",
        "CIS AWS Foundations Benchmark",
        "SOC 2",
    ],
    # Default for unknown types
    "default": ["NIST 800-53", "SOC 2"],
}


class GuardDutyCollector(BaseCollector):
    """Collector for AWS GuardDuty evidence.

    This collector implements GuardDuty findings collection with:
    1. List detectors and collect findings with severity >= 4.0
    2. Map findings to compliance frameworks using FINDING_TYPE_COMPLIANCE_MAP
    3. Map severity to priority: 7.0-10.0 → CRITICAL, 4.0-6.9 → HIGH, 1.0-3.9 → MEDIUM
    4. Use paginators for all API calls
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "GuardDutyCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all GuardDuty evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting GuardDuty evidence collection...", "INFO")

        try:
            guardduty_client = self.get_client("guardduty")

            # Get all detectors
            detectors = self._get_detectors(guardduty_client)

            if not detectors:
                self.log_colored("No GuardDuty detectors found", "WARNING")
                record = self.make_record(
                    resource_type="AWS::GuardDuty::Detector",
                    resource_id="guardduty",
                    control_status=ControlStatus.UNKNOWN.value,
                    priority=Priority.INFO.value,
                    finding_title="GuardDuty Not Enabled",
                    finding_description="No GuardDuty detectors found. GuardDuty may not be enabled.",
                    compliance_frameworks=[
                        "NIST 800-53",
                        "CIS AWS Foundations Benchmark",
                        "SOC 2",
                        "PCI-DSS",
                    ],
                    remediation_available=True,
                    remediation_action="Enable GuardDuty to start threat detection.",
                    raw_data={"detectors": []},
                )
                records.append(record)
                return records

            # Collect findings from all detectors
            for detector_id in detectors:
                detector_records = self._collect_findings(guardduty_client, detector_id)
                records.extend(detector_records)

            self.log_colored(
                f"GuardDuty collection complete: {len(records)} records", "SUCCESS"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error in GuardDuty collection: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::GuardDuty::Detector",
                resource_id="guardduty",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="GuardDuty Collection Failed",
                finding_description=f"Unable to collect GuardDuty findings: {error_code}",
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

    def _get_detectors(self, guardduty_client) -> List[str]:
        """Get all GuardDuty detector IDs.

        Args:
            guardduty_client: Boto3 GuardDuty client.

        Returns:
            List of detector IDs.
        """
        detectors = []

        try:
            paginator = self.get_paginator("guardduty", "list_detectors")

            for page in paginator.paginate():
                detector_ids = page.get("DetectorIds", [])
                detectors.extend(detector_ids)

            logger.info(f"Found {len(detectors)} GuardDuty detectors")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error listing detectors: {error_code} - {e}")

        return detectors

    def _collect_findings(
        self, guardduty_client, detector_id: str
    ) -> List[EvidenceRecord]:
        """Collect GuardDuty findings from a detector.

        Args:
            guardduty_client: Boto3 GuardDuty client.
            detector_id: GuardDuty detector ID.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            # Build criteria to filter findings with severity >= 4.0
            criteria = {"severity": {"gte": 4.0}}

            # Get findings using paginator
            paginator = self.get_paginator("guardduty", "list_findings")

            for page in paginator.paginate(
                DetectorId=detector_id, FindingCriteria=criteria
            ):
                finding_ids = page.get("FindingIds", [])

                if finding_ids:
                    # Get detailed findings
                    findings = self._get_findings_details(
                        guardduty_client, detector_id, finding_ids
                    )

                    for finding in findings:
                        record = self._convert_finding_to_record(finding, detector_id)
                        if record:
                            records.append(record)

            logger.info(
                f"Collected {len(records)} findings from detector {detector_id}"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(
                f"Error collecting findings from detector {detector_id}: {error_code} - {e}"
            )

        return records

    def _get_findings_details(
        self, guardduty_client, detector_id: str, finding_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """Get detailed information about GuardDuty findings.

        Args:
            guardduty_client: Boto3 GuardDuty client.
            detector_id: GuardDuty detector ID.
            finding_ids: List of finding IDs.

        Returns:
            List of finding dictionaries.
        """
        findings = []

        try:
            # GuardDuty allows getting up to 50 findings at a time
            batch_size = 50

            for i in range(0, len(finding_ids), batch_size):
                batch = finding_ids[i : i + batch_size]

                response = guardduty_client.get_findings(
                    DetectorId=detector_id, FindingIds=batch
                )

                findings.extend(response.get("Findings", []))

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error getting findings details: {error_code} - {e}")

        return findings

    def _convert_finding_to_record(
        self, finding: Dict[str, Any], detector_id: str
    ) -> EvidenceRecord:
        """Convert a GuardDuty finding to an EvidenceRecord.

        Args:
            finding: GuardDuty finding dictionary.
            detector_id: GuardDuty detector ID.

        Returns:
            EvidenceRecord object.
        """
        try:
            # Extract finding details
            finding_id = finding.get("Id", "")
            title = finding.get("Title", "")
            description = finding.get("Description", "")
            finding_type = finding.get("Type", "")
            severity = finding.get("Severity", 0.0)

            # Extract resource details
            resource = finding.get("Resource", {})
            resource_type = resource.get("ResourceType", "")
            resource_id = resource.get("InstanceId", "")

            # Build resource ARN if possible
            resource_arn = ""
            if resource_type == "Instance":
                resource_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{resource_id}"
            elif resource_type == "AccessKey":
                resource_id = resource.get("AccessKeyId", "")
                resource_arn = (
                    f"arn:aws:iam::{self.account_id}:access-key/{resource_id}"
                )
            elif resource_type == "S3Bucket":
                resource_id = resource.get("S3BucketDetails", [{}])[0].get("Name", "")
                resource_arn = f"arn:aws:s3:::{resource_id}"

            # Map severity to priority
            priority = self._map_severity_to_priority(severity)

            # Get compliance frameworks for this finding type
            compliance_frameworks = FINDING_TYPE_COMPLIANCE_MAP.get(
                finding_type,
                FINDING_TYPE_COMPLIANCE_MAP.get("default", ["NIST 800-53", "SOC 2"]),
            )

            # Extract service details for additional context
            service = finding.get("Service", {})
            service_name = service.get("ServiceName", "")

            # Extract action details
            action = finding.get("Action", {})
            action_type = action.get("ActionType", "")

            # Create finding description with additional context
            enhanced_description = description
            if action_type:
                enhanced_description += f" Action Type: {action_type}."
            if service_name:
                enhanced_description += f" Service: {service_name}."

            # Determine remediation based on finding type
            remediation_available = True
            remediation_action = self._get_remediation_action(
                finding_type, resource_type, resource_id
            )

            # Create the evidence record
            record = self.make_record(
                resource_type=(
                    f"AWS::{resource_type}"
                    if resource_type
                    else "AWS::GuardDuty::Finding"
                ),
                resource_id=resource_id or finding_id,
                resource_arn=resource_arn,
                control_status=ControlStatus.FAIL.value,
                priority=priority,
                finding_title=title or f"GuardDuty Finding: {finding_type}",
                finding_description=enhanced_description,
                compliance_frameworks=compliance_frameworks,
                remediation_available=remediation_available,
                remediation_action=remediation_action,
                raw_data={
                    "finding_id": finding_id,
                    "finding_type": finding_type,
                    "severity": severity,
                    "detector_id": detector_id,
                    "finding": finding,
                },
            )

            return record

        except Exception as e:
            logger.error(f"Error converting finding to record: {e}")
            return None

    def _map_severity_to_priority(self, severity: float) -> str:
        """Map GuardDuty severity to priority level.

        Args:
            severity: GuardDuty severity score (0.0-10.0).

        Returns:
            Priority level string.
        """
        if severity >= 7.0:
            return Priority.CRITICAL.value
        elif severity >= 4.0:
            return Priority.HIGH.value
        elif severity >= 1.0:
            return Priority.MEDIUM.value
        else:
            return Priority.LOW.value

    def _get_remediation_action(
        self, finding_type: str, resource_type: str, resource_id: str
    ) -> str:
        """Get remediation action for a finding type.

        Args:
            finding_type: GuardDuty finding type.
            resource_type: Type of resource affected.
            resource_id: ID of the resource affected.

        Returns:
            Remediation action description.
        """
        # CryptoCurrency findings
        if "CryptoCurrency" in finding_type:
            return f"Isolate EC2 instance {resource_id} and investigate for cryptocurrency mining activity."

        # Backdoor findings
        if "Backdoor" in finding_type:
            if "C&CActivity" in finding_type:
                return f"Block network traffic from EC2 instance {resource_id} and investigate for command and control activity."
            elif "DenialOfService" in finding_type:
                return f"Investigate EC2 instance {resource_id} for potential denial of service participation."
            elif "Spambot" in finding_type:
                return f"Isolate EC2 instance {resource_id} and investigate for spam bot activity."

        # Behavior findings
        if "Behavior" in finding_type:
            if "TorIPCaller" in finding_type or "TorRelay" in finding_type:
                return (
                    f"Investigate EC2 instance {resource_id} for Tor network activity."
                )
            elif "NetworkPortUnusual" in finding_type:
                return f"Review network activity on EC2 instance {resource_id} for unusual port usage."

        # Trojan findings
        if "Trojan" in finding_type:
            return f"Isolate EC2 instance {resource_id} and scan for malware/trojan infection."

        # Policy findings
        if "Policy" in finding_type:
            if "IAMUser" in finding_type:
                return f"Review IAM user {resource_id} permissions and activity."
            elif "S3" in finding_type:
                return (
                    f"Review S3 bucket {resource_id} permissions and access patterns."
                )

        # Stealth findings
        if "Stealth" in finding_type:
            return f"Review IAM user {resource_id} for unusual permission changes."

        # Discovery findings
        if "Discovery" in finding_type:
            if "S3" in finding_type:
                return f"Review S3 bucket {resource_id} access logs for malicious IP access."
            elif "PortScan" in finding_type:
                return f"Investigate EC2 instance {resource_id} for port scanning activity."

        # Default remediation
        return f"Investigate resource {resource_id} for security issues identified by GuardDuty."
