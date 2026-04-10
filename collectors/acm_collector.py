"""ACM Evidence Collector.

This collector gathers compliance evidence from AWS ACM service, checking for
certificate expiry and best practices.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from collectors.base_collector import (
    BaseCollector,
    ControlStatus,
    EvidenceRecord,
    Priority,
)

logger = logging.getLogger(__name__)

# Certificate expiry thresholds (in days)
CRITICAL_DAYS = 30
HIGH_DAYS = 60
MEDIUM_DAYS = 90


class ACMCollector(BaseCollector):
    """Collector for ACM certificate compliance evidence.

    This collector implements certificate expiry checks:
    - Days to expiry < 30: CRITICAL
    - Days to expiry 30-60: HIGH
    - Days to expiry 60-90: MEDIUM
    - Days to expiry > 90: INFO
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "ACMCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all ACM evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting ACM evidence collection...", "INFO")

        try:
            acm_client = self.get_client("acm")

            # Get all certificates
            certificates = self._get_certificates(acm_client)

            # Check each certificate for expiry
            for cert in certificates:
                record = self._check_certificate_expiry(cert)
                if record:
                    records.append(record)

            self.log_colored(
                f"ACM collection complete: {len(records)} records", "SUCCESS"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error in ACM collection: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::ACM::Certificate",
                resource_id="all_certificates",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="ACM Collection Failed",
                finding_description=f"Unable to collect ACM certificates: {error_code}",
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

    def _get_certificates(self, acm_client) -> List[Dict[str, Any]]:
        """Get all ACM certificates.

        Args:
            acm_client: Boto3 ACM client.

        Returns:
            List of certificate dictionaries.
        """
        certificates = []

        try:
            paginator = self.get_paginator("acm", "list_certificates")

            for page in paginator.paginate():
                cert_summaries = page.get("CertificateSummaryList", [])

                for summary in cert_summaries:
                    cert_arn = summary.get("CertificateArn", "")

                    # Get detailed certificate information
                    try:
                        cert_detail = acm_client.describe_certificate(
                            CertificateArn=cert_arn
                        )
                        certificates.append(cert_detail)

                    except ClientError as e:
                        logger.error(f"Error describing certificate {cert_arn}: {e}")

            logger.info(f"Found {len(certificates)} ACM certificates")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error listing certificates: {error_code} - {e}")

        return certificates

    def _check_certificate_expiry(self, cert: Dict[str, Any]) -> EvidenceRecord:
        """Check a certificate for expiry and create an evidence record.

        Args:
            cert: Certificate detail dictionary.

        Returns:
            EvidenceRecord object or None if certificate is not applicable.
        """
        try:
            cert_arn = cert.get("CertificateArn", "")
            cert_domain = cert.get("DomainName", "")
            cert_status = cert.get("Status", "")
            not_after = cert.get("NotAfter")
            type_val = cert.get("Type", "")

            # Skip certificates that are not valid
            if cert_status in ["EXPIRED", "VALIDATION_TIMED_OUT", "REVOKED", "FAILED"]:
                return None

            # Calculate days until expiry
            if not_after:
                days_until_expiry = (not_after - datetime.now(timezone.utc)).days

                # Determine priority based on days until expiry
                if days_until_expiry < 0:
                    # Already expired
                    priority = Priority.CRITICAL.value
                    control_status = ControlStatus.FAIL.value
                    finding_title = f"Certificate {cert_domain} Expired"
                    finding_description = f"Certificate {cert_domain} expired {abs(days_until_expiry)} days ago."
                elif days_until_expiry < CRITICAL_DAYS:
                    priority = Priority.CRITICAL.value
                    control_status = ControlStatus.FAIL.value
                    finding_title = (
                        f"Certificate {cert_domain} Expiring Soon (CRITICAL)"
                    )
                    finding_description = f"Certificate {cert_domain} expires in {days_until_expiry} days. Immediate action required."
                elif days_until_expiry < HIGH_DAYS:
                    priority = Priority.HIGH.value
                    control_status = ControlStatus.FAIL.value
                    finding_title = f"Certificate {cert_domain} Expiring Soon (HIGH)"
                    finding_description = f"Certificate {cert_domain} expires in {days_until_expiry} days. Action required soon."
                elif days_until_expiry < MEDIUM_DAYS:
                    priority = Priority.MEDIUM.value
                    control_status = ControlStatus.WARNING.value
                    finding_title = f"Certificate {cert_domain} Expiring Soon (MEDIUM)"
                    finding_description = f"Certificate {cert_domain} expires in {days_until_expiry} days. Plan for renewal."
                else:
                    # Certificate is valid for a while
                    priority = Priority.INFO.value
                    control_status = ControlStatus.PASS.value
                    finding_title = f"Certificate {cert_domain} Valid"
                    finding_description = f"Certificate {cert_domain} is valid and expires in {days_until_expiry} days."

                # Determine remediation availability
                remediation_available = days_until_expiry < MEDIUM_DAYS

                # Create remediation action
                if days_until_expiry < 0:
                    remediation_action = f"Certificate {cert_domain} has expired. Renew or replace the certificate immediately."
                elif days_until_expiry < CRITICAL_DAYS:
                    remediation_action = f"Renew certificate {cert_domain} immediately to avoid service disruption."
                elif days_until_expiry < HIGH_DAYS:
                    remediation_action = f"Renew certificate {cert_domain} soon to avoid service disruption."
                elif days_until_expiry < MEDIUM_DAYS:
                    remediation_action = (
                        f"Plan to renew certificate {cert_domain} before it expires."
                    )
                else:
                    remediation_action = ""

                # Create the evidence record
                record = self.make_record(
                    resource_type="AWS::ACM::Certificate",
                    resource_id=cert_domain,
                    resource_arn=cert_arn,
                    control_status=control_status,
                    priority=priority,
                    finding_title=finding_title,
                    finding_description=finding_description,
                    compliance_frameworks=[
                        "NIST 800-53",
                        "CIS AWS Foundations Benchmark",
                        "SOC 2",
                        "PCI-DSS",
                    ],
                    remediation_available=remediation_available,
                    remediation_action=remediation_action,
                    raw_data={
                        "certificate_arn": cert_arn,
                        "domain_name": cert_domain,
                        "status": cert_status,
                        "type": type_val,
                        "not_after": not_after.isoformat() if not_after else None,
                        "days_until_expiry": days_until_expiry,
                    },
                )

                # Log critical and high priority findings
                if priority in [Priority.CRITICAL.value, Priority.HIGH.value]:
                    self.log_colored(
                        f"[FAIL] {finding_title}: {days_until_expiry} days remaining",
                        "ERROR" if priority == Priority.CRITICAL.value else "WARNING",
                    )

                return record

            else:
                # Certificate has no expiry date
                logger.warning(f"Certificate {cert_arn} has no expiry date")
                return None

        except Exception as e:
            logger.error(f"Error checking certificate expiry: {e}")
            return None
