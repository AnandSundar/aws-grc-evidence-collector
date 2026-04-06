"""KMS Evidence Collector.

This collector gathers compliance evidence from AWS KMS service, checking for
key management best practices and compliance requirements.
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

# Maximum age for KMS keys before rotation should be considered (in days)
MAX_KEY_AGE_DAYS = 365


class KMSCollector(BaseCollector):
    """Collector for KMS key management and compliance evidence.

    This collector implements 3 KMS key management checks:
    1. CMK rotation enabled
    2. Keys pending deletion
    3. Key age (keys older than 365 days without rotation)
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "KMSCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all KMS evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting KMS evidence collection...", "INFO")

        # Get all customer managed keys
        keys = self._get_customer_managed_keys()

        # Check 1: CMK rotation enabled
        records.extend(self._check_key_rotation(keys))

        # Check 2: Keys pending deletion
        records.extend(self._check_pending_deletion(keys))

        # Check 3: Key age
        records.extend(self._check_key_age(keys))

        self.log_colored(f"KMS collection complete: {len(records)} records", "SUCCESS")
        return records

    def _get_customer_managed_keys(self) -> List[Dict[str, Any]]:
        """Get all customer managed KMS keys.

        Returns:
            List of key metadata dictionaries.
        """
        keys = []

        try:
            kms_client = self.get_client("kms")
            paginator = self.get_paginator("kms", "list_keys")

            for page in paginator.paginate():
                key_ids = page.get("Keys", [])

                for key_id in key_ids:
                    key_arn = key_id.get("KeyArn", "")
                    key_id_str = key_id.get("KeyId", "")

                    # Get key metadata
                    try:
                        metadata = kms_client.describe_key(KeyId=key_id_str)
                        key_metadata = metadata.get("KeyMetadata", {})

                        # Only include customer managed keys (not AWS managed)
                        if key_metadata.get("KeyManager", "AWS") == "CUSTOMER":
                            keys.append(key_metadata)

                    except ClientError as e:
                        logger.error(f"Error describing key {key_id_str}: {e}")

            logger.info(f"Found {len(keys)} customer managed KMS keys")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error listing KMS keys: {error_code} - {e}")

        return keys

    def _check_key_rotation(self, keys: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Check if KMS keys have rotation enabled.

        Args:
            keys: List of key metadata dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            kms_client = self.get_client("kms")

            for key in keys:
                key_id = key.get("KeyId", "")
                key_arn = key.get("Arn", "")
                key_spec = key.get("KeySpec", "")
                key_usage = key.get("KeyUsage", "")

                # Only check symmetric encryption keys for rotation
                # Asymmetric keys cannot have automatic rotation
                if key_spec != "SYMMETRIC_DEFAULT" or key_usage != "ENCRYPT_DECRYPT":
                    continue

                try:
                    # Get rotation status
                    rotation = kms_client.get_key_rotation_status(KeyId=key_id)
                    rotation_enabled = rotation.get("KeyRotationEnabled", False)

                    if rotation_enabled:
                        record = self.make_record(
                            resource_type="AWS::KMS::Key",
                            resource_id=key_id,
                            resource_arn=key_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"KMS Key {key_id} Rotation Enabled",
                            finding_description=f"KMS key {key_id} has automatic key rotation enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "key_id": key_id,
                                "key_spec": key_spec,
                                "key_usage": key_usage,
                                "rotation_enabled": rotation_enabled,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::KMS::Key",
                            resource_id=key_id,
                            resource_arn=key_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.HIGH.value,
                            finding_title=f"KMS Key {key_id} Rotation Disabled",
                            finding_description=f"KMS key {key_id} does not have automatic key rotation enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable automatic key rotation for KMS key {key_id}.",
                            raw_data={
                                "key_id": key_id,
                                "key_spec": key_spec,
                                "key_usage": key_usage,
                                "rotation_enabled": rotation_enabled,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ KMS key {key_id} rotation disabled", "WARNING"
                        )

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "Unknown")
                    logger.error(
                        f"Error checking rotation for key {key_id}: {error_code} - {e}"
                    )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking KMS key rotation: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::KMS::Key",
                resource_id="all_keys",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="KMS Key Rotation Check Failed",
                finding_description=f"Unable to check KMS key rotation: {error_code}",
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

    def _check_pending_deletion(
        self, keys: List[Dict[str, Any]]
    ) -> List[EvidenceRecord]:
        """Check if KMS keys are pending deletion.

        Args:
            keys: List of key metadata dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            for key in keys:
                key_id = key.get("KeyId", "")
                key_arn = key.get("Arn", "")
                key_state = key.get("KeyState", "")
                deletion_date = key.get("DeletionDate")

                if key_state == "PendingDeletion":
                    # Calculate days until deletion
                    if deletion_date:
                        days_until_deletion = (
                            deletion_date - datetime.now(timezone.utc)
                        ).days
                        deletion_info = (
                            f"Deletion scheduled in {days_until_deletion} days."
                        )
                    else:
                        deletion_info = "Deletion scheduled."

                    record = self.make_record(
                        resource_type="AWS::KMS::Key",
                        resource_id=key_id,
                        resource_arn=key_arn,
                        control_status=ControlStatus.WARNING.value,
                        priority=Priority.HIGH.value,
                        finding_title=f"KMS Key {key_id} Pending Deletion",
                        finding_description=f"KMS key {key_id} is pending deletion. {deletion_info}",
                        compliance_frameworks=["NIST 800-53", "SOC 2", "PCI-DSS"],
                        remediation_available=True,
                        remediation_action=f"Cancel key deletion for KMS key {key_id} if the key is still needed.",
                        raw_data={
                            "key_id": key_id,
                            "key_state": key_state,
                            "deletion_date": (
                                deletion_date.isoformat() if deletion_date else None
                            ),
                        },
                    )
                    records.append(record)
                    self.log_colored(f"⚠ KMS key {key_id} pending deletion", "WARNING")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking pending deletion: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::KMS::Key",
                resource_id="all_keys",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="KMS Pending Deletion Check Failed",
                finding_description=f"Unable to check KMS pending deletion: {error_code}",
                compliance_frameworks=["NIST 800-53", "SOC 2", "PCI-DSS"],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_key_age(self, keys: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Check if KMS keys are old and should be rotated.

        Args:
            keys: List of key metadata dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            kms_client = self.get_client("kms")

            for key in keys:
                key_id = key.get("KeyId", "")
                key_arn = key.get("Arn", "")
                creation_date = key.get("CreationDate")
                key_spec = key.get("KeySpec", "")
                key_usage = key.get("KeyUsage", "")

                # Only check symmetric encryption keys for age
                if key_spec != "SYMMETRIC_DEFAULT" or key_usage != "ENCRYPT_DECRYPT":
                    continue

                if creation_date:
                    # Calculate key age in days
                    age_days = (datetime.now(timezone.utc) - creation_date).days

                    # Check if rotation is enabled
                    try:
                        rotation = kms_client.get_key_rotation_status(KeyId=key_id)
                        rotation_enabled = rotation.get("KeyRotationEnabled", False)

                        if age_days > MAX_KEY_AGE_DAYS and not rotation_enabled:
                            record = self.make_record(
                                resource_type="AWS::KMS::Key",
                                resource_id=key_id,
                                resource_arn=key_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.MEDIUM.value,
                                finding_title=f"KMS Key {key_id} Old Without Rotation",
                                finding_description=f"KMS key {key_id} is {age_days} days old and does not have automatic rotation enabled.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                ],
                                remediation_available=True,
                                remediation_action=f"Enable automatic key rotation for KMS key {key_id} or create a new key.",
                                raw_data={
                                    "key_id": key_id,
                                    "key_spec": key_spec,
                                    "key_usage": key_usage,
                                    "creation_date": creation_date.isoformat(),
                                    "age_days": age_days,
                                    "rotation_enabled": rotation_enabled,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"✗ KMS key {key_id} is {age_days} days old without rotation",
                                "WARNING",
                            )

                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "Unknown")
                        logger.error(
                            f"Error checking rotation for key {key_id}: {error_code} - {e}"
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking KMS key age: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::KMS::Key",
                resource_id="all_keys",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="KMS Key Age Check Failed",
                finding_description=f"Unable to check KMS key age: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records
