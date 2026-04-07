"""
Notification module for GRC Evidence Platform.

This module provides SNS notification functionality for remediation actions.
Separated from remediation_registry to avoid circular imports.
"""

import logging
import os
from datetime import datetime
from typing import List, Optional

import boto3


# Configure logging
logger = logging.getLogger(__name__)


# ANSI color codes for terminal output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def send_remediation_notification(
    action_taken: str,
    resource_id: str,
    resource_type: str,
    finding_title: str,
    finding_description: str,
    finding_priority: str = "HIGH",
    compliance_frameworks: Optional[List[str]] = None,
    region: str = "us-east-1",
) -> bool:
    """Send SNS notification about remediation action.

    This function sends an SNS notification to the admin team about a remediation
    action that was executed. It includes details about the resource, action taken,
    and compliance frameworks affected.

    Args:
        action_taken: Description of the remediation action
        resource_id: ID of the resource that was remediated
        resource_type: Type of the resource (e.g., "aws.s3.bucket")
        finding_title: Title of the security finding
        finding_description: Description of the security issue
        finding_priority: Priority level (CRITICAL, HIGH, MEDIUM, LOW)
        compliance_frameworks: List of compliance frameworks affected
        region: AWS region

    Returns:
        True if notification was sent successfully, False otherwise

    Example:
        >>> send_remediation_notification(
        ...     action_taken="Blocked public access",
        ...     resource_id="my-bucket",
        ...     resource_type="aws.s3.bucket",
        ...     finding_title="S3 Bucket Public Access Blocked",
        ...     finding_description="S3 bucket had public read access - blocked automatically",
        ...     finding_priority="CRITICAL",
        ...     compliance_frameworks=["PCI-DSS-1.3.2", "SOC2-CC6.6"]
        ... )
    """
    try:
        # Get SNS topic ARN from environment
        sns_topic_arn = os.getenv("ALERT_TOPIC_ARN")

        if not sns_topic_arn or sns_topic_arn == "":
            logger.debug(
                f"{Colors.YELLOW}No SNS topic configured, skipping notification{Colors.RESET}"
            )
            return False

        # Build compliance frameworks string
        frameworks_str = ", ".join(compliance_frameworks) if compliance_frameworks else "N/A"

        # Build message
        message = f"""GRC Platform - Automatic Remediation Notification

Action Taken: {action_taken}
Resource ID: {resource_id}
Resource Type: {resource_type}
Priority: {finding_priority}

Finding: {finding_title}
Description: {finding_description}

Compliance Frameworks: {frameworks_str}
Region: {region}
Timestamp: {datetime.utcnow().isoformat()}

This action was performed automatically by the GRC Evidence Platform.
For questions or concerns, please contact your security team."""

        # Send notification
        sns_client = boto3.client("sns", region_name=region)
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=f"GRC Alert: {finding_title} - {resource_id}",
            Message=message,
        )

        logger.info(
            f"{Colors.GREEN}✓ Sent remediation notification for {resource_id}{Colors.RESET}"
        )
        return True

    except Exception as e:
        logger.error(
            f"{Colors.RED}✗ Failed to send notification for {resource_id}: {str(e)}{Colors.RESET}"
        )
        return False
