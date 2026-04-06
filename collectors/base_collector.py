"""Base Collector Module.

This module provides the abstract base class and data structures for all evidence collectors.
"""

import abc
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class ControlStatus(Enum):
    """Enumeration for control status values."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Priority(Enum):
    """Enumeration for priority levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class EvidenceRecord:
    """Canonical evidence record schema for all compliance evidence.

    This dataclass represents a single piece of compliance evidence collected from
    an AWS service. It follows the canonical schema defined in SECTION 15 of the
    GRC Evidence Platform specification.

    Attributes:
        evidence_id: Unique identifier for this evidence record (UUID).
        collected_at: Timestamp when the evidence was collected (ISO 8601 UTC).
        collector_name: Name of the collector that produced this record.
        aws_account_id: AWS account ID where the evidence was collected.
        aws_region: AWS region where the evidence was collected.
        resource_type: AWS resource type (e.g., 'AWS::IAM::User', 'AWS::S3::Bucket').
        resource_id: Resource identifier (e.g., user name, bucket name).
        resource_arn: Full ARN of the resource (if available).
        control_status: Status of the control check (PASS/FAIL/WARNING/UNKNOWN/NOT_APPLICABLE).
        priority: Priority level of the finding (CRITICAL/HIGH/MEDIUM/LOW/INFO).
        finding_title: Human-readable title of the finding.
        finding_description: Detailed description of the finding.
        compliance_frameworks: List of compliance frameworks this evidence relates to.
        remediation_available: Whether a remediation action is available.
        remediation_action: Description of the remediation action (if available).
        raw_data: Raw data from the AWS API call for audit purposes.
        ttl: Time-to-live for this record in seconds (default: 2592000 = 30 days).
        ai_analysis: AI-generated analysis or recommendations (optional).
    """

    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    collector_name: str = ""
    aws_account_id: str = ""
    aws_region: str = ""
    resource_type: str = ""
    resource_id: str = ""
    resource_arn: str = ""
    control_status: str = ControlStatus.UNKNOWN.value
    priority: str = Priority.INFO.value
    finding_title: str = ""
    finding_description: str = ""
    compliance_frameworks: List[str] = field(default_factory=list)
    remediation_available: bool = False
    remediation_action: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    ttl: int = 2592000  # 30 days in seconds
    ai_analysis: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the EvidenceRecord to a dictionary.

        Returns:
            Dictionary representation of the evidence record.
        """
        return {
            "evidence_id": self.evidence_id,
            "collected_at": self.collected_at,
            "collector_name": self.collector_name,
            "aws_account_id": self.aws_account_id,
            "aws_region": self.aws_region,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "control_status": self.control_status,
            "priority": self.priority,
            "finding_title": self.finding_title,
            "finding_description": self.finding_description,
            "compliance_frameworks": self.compliance_frameworks,
            "remediation_available": self.remediation_available,
            "remediation_action": self.remediation_action,
            "raw_data": self.raw_data,
            "ttl": self.ttl,
            "ai_analysis": self.ai_analysis,
        }


class BaseCollector(abc.ABC):
    """Abstract base class for all evidence collectors.

    This class provides the common interface and functionality that all collectors
    must implement. It handles AWS client initialization, error handling, and
    evidence record creation.

    Attributes:
        region: AWS region where the collector will operate.
        account_id: AWS account ID for the collector.
        session: Boto3 session for creating AWS clients.
        records: List of evidence records collected by this collector.
    """

    def __init__(
        self, region: Optional[str] = None, account_id: Optional[str] = None
    ) -> None:
        """Initialize the base collector.

        Args:
            region: AWS region. If None, uses default from AWS config or environment.
            account_id: AWS account ID. If None, attempts to auto-detect.
        """
        self.region = region or self._get_default_region()
        self.account_id = account_id or self._get_account_id()
        self.session = boto3.Session(region_name=self.region)
        self.records: List[EvidenceRecord] = []

        logger.info(
            f"Initialized {self.__class__.__name__} for region {self.region} and account {self.account_id}"
        )

    def _get_default_region(self) -> str:
        """Get the default AWS region from environment or config.

        Returns:
            Default AWS region string.
        """
        try:
            # Try to get from environment variable
            import os

            region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get(
                "AWS_REGION"
            )
            if region:
                return region

            # Try to get from boto3 session
            session = boto3.Session()
            region = session.region_name
            if region:
                return region

            # Default to us-east-1 if not found
            logger.warning("No region found, defaulting to us-east-1")
            return "us-east-1"
        except Exception as e:
            logger.error(f"Error getting default region: {e}")
            return "us-east-1"

    def _get_account_id(self) -> str:
        """Get the AWS account ID.

        Returns:
            AWS account ID as string.
        """
        try:
            sts_client = boto3.client("sts")
            account_id = sts_client.get_caller_identity()["Account"]
            return account_id
        except ClientError as e:
            logger.error(f"Error getting account ID: {e}")
            return ""
        except Exception as e:
            logger.error(f"Unexpected error getting account ID: {e}")
            return ""

    @abc.abstractmethod
    def collect(self) -> List[EvidenceRecord]:
        """Collect evidence records from the AWS service.

        This method must be implemented by all concrete collectors.
        It should populate self.records with EvidenceRecord objects.

        Returns:
            List of collected EvidenceRecord objects.
        """
        pass

    @abc.abstractmethod
    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        pass

    def run(self) -> List[EvidenceRecord]:
        """Run the collector and return all evidence records.

        This method orchestrates the collection process, handles errors,
        and returns the collected records.

        Returns:
            List of EvidenceRecord objects collected by this collector.
        """
        logger.info(f"Starting {self.get_collector_name()} collection...")
        try:
            self.records = self.collect()
            logger.info(
                f"{self.get_collector_name()} collected {len(self.records)} records"
            )
            return self.records
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))
            logger.error(
                f"AWS ClientError in {self.get_collector_name()}: {error_code} - {error_message}"
            )
            return []
        except Exception as e:
            logger.error(f"Unexpected error in {self.get_collector_name()}: {e}")
            return []

    def make_record(
        self,
        resource_type: str,
        resource_id: str,
        resource_arn: str = "",
        control_status: str = ControlStatus.UNKNOWN.value,
        priority: str = Priority.INFO.value,
        finding_title: str = "",
        finding_description: str = "",
        compliance_frameworks: Optional[List[str]] = None,
        remediation_available: bool = False,
        remediation_action: str = "",
        raw_data: Optional[Dict[str, Any]] = None,
        ai_analysis: Optional[str] = None,
    ) -> EvidenceRecord:
        """Create an EvidenceRecord with standard fields populated.

        This is a convenience method for creating evidence records with the
        collector's default values for account ID, region, and collector name.

        Args:
            resource_type: AWS resource type.
            resource_id: Resource identifier.
            resource_arn: Full ARN of the resource (optional).
            control_status: Status of the control check.
            priority: Priority level of the finding.
            finding_title: Human-readable title of the finding.
            finding_description: Detailed description of the finding.
            compliance_frameworks: List of compliance frameworks.
            remediation_available: Whether a remediation action is available.
            remediation_action: Description of the remediation action.
            raw_data: Raw data from the AWS API call.
            ai_analysis: AI-generated analysis or recommendations.

        Returns:
            EvidenceRecord object with populated fields.
        """
        return EvidenceRecord(
            collector_name=self.get_collector_name(),
            aws_account_id=self.account_id,
            aws_region=self.region,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
            control_status=control_status,
            priority=priority,
            finding_title=finding_title,
            finding_description=finding_description,
            compliance_frameworks=compliance_frameworks or [],
            remediation_available=remediation_available,
            remediation_action=remediation_action,
            raw_data=raw_data or {},
            ai_analysis=ai_analysis,
        )

    def get_client(self, service_name: str):
        """Get a boto3 client for the specified service.

        Args:
            service_name: Name of the AWS service (e.g., 's3', 'iam', 'rds').

        Returns:
            Boto3 client for the service.
        """
        return self.session.client(service_name, region_name=self.region)

    def get_paginator(self, service_name: str, operation_name: str):
        """Get a paginator for the specified service operation.

        Args:
            service_name: Name of the AWS service.
            operation_name: Name of the operation to paginate.

        Returns:
            Boto3 paginator object.
        """
        client = self.get_client(service_name)
        return client.get_paginator(operation_name)

    def log_colored(self, message: str, level: str = "INFO") -> None:
        """Log a message with colored terminal output.

        Args:
            message: The message to log.
            level: Log level (INFO, WARNING, ERROR, SUCCESS).
        """
        colors = {
            "INFO": "\033[94m",  # Blue
            "WARNING": "\033[93m",  # Yellow
            "ERROR": "\033[91m",  # Red
            "SUCCESS": "\033[92m",  # Green
            "RESET": "\033[0m",  # Reset
        }

        color = colors.get(level, colors["INFO"])
        reset = colors["RESET"]

        if level == "INFO":
            logger.info(f"{color}{message}{reset}")
        elif level == "WARNING":
            logger.warning(f"{color}{message}{reset}")
        elif level == "ERROR":
            logger.error(f"{color}{message}{reset}")
        elif level == "SUCCESS":
            logger.info(f"{color}{message}{reset}")
        else:
            logger.info(message)
