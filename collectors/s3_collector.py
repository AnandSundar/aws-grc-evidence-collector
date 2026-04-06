"""S3 Evidence Collector.

This collector gathers compliance evidence from AWS S3 service, checking for
security best practices and compliance requirements.
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


class S3Collector(BaseCollector):
    """Collector for S3 security and compliance evidence.

    This collector implements 7 S3 checks:
    1. S3 buckets with encryption enabled (SSE-S3 or SSE-KMS)
    2. S3 buckets with versioning enabled
    3. S3 buckets with public access blocked
    4. S3 buckets with logging enabled
    5. S3 buckets with lifecycle policies
    6. S3 buckets with MFA delete enabled
    7. S3 buckets with default encryption configured
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "S3Collector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all S3 evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting S3 evidence collection...", "INFO")

        # Get all buckets first
        buckets = self._get_all_buckets()

        # Check 1: S3 buckets with encryption enabled
        records.extend(self._check_encryption(buckets))

        # Check 2: S3 buckets with versioning enabled
        records.extend(self._check_versioning(buckets))

        # Check 3: S3 buckets with public access blocked
        records.extend(self._check_public_access(buckets))

        # Check 4: S3 buckets with logging enabled
        records.extend(self._check_logging(buckets))

        # Check 5: S3 buckets with lifecycle policies
        records.extend(self._check_lifecycle(buckets))

        # Check 6: S3 buckets with MFA delete enabled
        records.extend(self._check_mfa_delete(buckets))

        # Check 7: S3 buckets with default encryption configured
        records.extend(self._check_default_encryption(buckets))

        self.log_colored(f"S3 collection complete: {len(records)} records", "SUCCESS")
        return records

    def _get_all_buckets(self) -> List[Dict[str, Any]]:
        """Get all S3 buckets in the account.

        Returns:
            List of bucket dictionaries.
        """
        buckets = []

        try:
            s3_client = self.get_client("s3")
            paginator = self.get_paginator("s3", "list_buckets")

            for page in paginator.paginate():
                buckets.extend(page.get("Buckets", []))

            logger.info(f"Found {len(buckets)} S3 buckets")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error listing S3 buckets: {error_code} - {e}")

        return buckets

    def _check_encryption(self, buckets: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Check if S3 buckets have encryption enabled.

        Args:
            buckets: List of bucket dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            s3_client = self.get_client("s3")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Get bucket encryption configuration
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    sse_configured = True

                    # Check encryption type
                    rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                        "Rules", []
                    )
                    encryption_types = []
                    for rule in rules:
                        apply_config = rule.get(
                            "ApplyServerSideEncryptionByDefault", {}
                        )
                        sse_algorithm = apply_config.get("SSEAlgorithm", "Unknown")
                        encryption_types.append(sse_algorithm)

                    record = self.make_record(
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        resource_arn=bucket_arn,
                        control_status=ControlStatus.PASS.value,
                        priority=Priority.INFO.value,
                        finding_title=f"S3 Bucket {bucket_name} Encrypted",
                        finding_description=f"S3 bucket {bucket_name} has encryption enabled: {', '.join(encryption_types)}",
                        compliance_frameworks=[
                            "NIST 800-53",
                            "CIS AWS Foundations Benchmark",
                            "SOC 2",
                            "PCI-DSS",
                        ],
                        remediation_available=False,
                        raw_data={
                            "bucket_name": bucket_name,
                            "encryption_configured": sse_configured,
                            "encryption_types": encryption_types,
                        },
                    )
                    records.append(record)

                except ClientError as e:
                    if (
                        e.response.get("Error", {}).get("Code")
                        == "ServerSideEncryptionConfigurationNotFoundError"
                    ):
                        # No encryption configured
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.HIGH.value,
                            finding_title=f"S3 Bucket {bucket_name} Not Encrypted",
                            finding_description=f"S3 bucket {bucket_name} does not have encryption enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable default encryption for S3 bucket {bucket_name} using SSE-S3 or SSE-KMS.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "encryption_configured": False,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ S3 bucket {bucket_name} not encrypted", "WARNING"
                        )
                    else:
                        raise

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking S3 encryption: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::S3::Bucket",
                resource_id="all_buckets",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="S3 Encryption Check Failed",
                finding_description=f"Unable to check S3 encryption: {error_code}",
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

    def _check_versioning(self, buckets: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Check if S3 buckets have versioning enabled.

        Args:
            buckets: List of bucket dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            s3_client = self.get_client("s3")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Get bucket versioning configuration
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    status = versioning.get("Status", "Suspended")
                    mfa_delete = versioning.get("MFADelete", "Disabled")

                    if status == "Enabled":
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"S3 Bucket {bucket_name} Versioning Enabled",
                            finding_description=f"S3 bucket {bucket_name} has versioning enabled. MFA Delete: {mfa_delete}",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=False,
                            raw_data={
                                "bucket_name": bucket_name,
                                "versioning_status": status,
                                "mfa_delete": mfa_delete,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.MEDIUM.value,
                            finding_title=f"S3 Bucket {bucket_name} Versioning Disabled",
                            finding_description=f"S3 bucket {bucket_name} does not have versioning enabled. Status: {status}",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable versioning for S3 bucket {bucket_name} to protect against accidental deletion or overwrites.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "versioning_status": status,
                                "mfa_delete": mfa_delete,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ S3 bucket {bucket_name} versioning disabled", "WARNING"
                        )

                except ClientError as e:
                    logger.error(
                        f"Error checking versioning for bucket {bucket_name}: {e}"
                    )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking S3 versioning: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::S3::Bucket",
                resource_id="all_buckets",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="S3 Versioning Check Failed",
                finding_description=f"Unable to check S3 versioning: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_public_access(
        self, buckets: List[Dict[str, Any]]
    ) -> List[EvidenceRecord]:
        """Check if S3 buckets have public access blocked.

        Args:
            buckets: List of bucket dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            s3_client = self.get_client("s3")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Get bucket public access block configuration
                    public_access = s3_client.get_public_access_block(
                        Bucket=bucket_name
                    )
                    config = public_access.get("PublicAccessBlockConfiguration", {})

                    # Check if all public access settings are enabled (which means public access is blocked)
                    block_public_acls = config.get("BlockPublicAcls", False)
                    ignore_public_acls = config.get("IgnorePublicAcls", False)
                    block_public_policy = config.get("BlockPublicPolicy", False)
                    restrict_public_buckets = config.get("RestrictPublicBuckets", False)

                    if all(
                        [
                            block_public_acls,
                            ignore_public_acls,
                            block_public_policy,
                            restrict_public_buckets,
                        ]
                    ):
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"S3 Bucket {bucket_name} Public Access Blocked",
                            finding_description=f"S3 bucket {bucket_name} has all public access settings enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "bucket_name": bucket_name,
                                "block_public_acls": block_public_acls,
                                "ignore_public_acls": ignore_public_acls,
                                "block_public_policy": block_public_policy,
                                "restrict_public_buckets": restrict_public_buckets,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.CRITICAL.value,
                            finding_title=f"S3 Bucket {bucket_name} Public Access Not Fully Blocked",
                            finding_description=f"S3 bucket {bucket_name} does not have all public access settings enabled. Some settings are disabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable all public access block settings for S3 bucket {bucket_name}.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "block_public_acls": block_public_acls,
                                "ignore_public_acls": ignore_public_acls,
                                "block_public_policy": block_public_policy,
                                "restrict_public_buckets": restrict_public_buckets,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ S3 bucket {bucket_name} public access not fully blocked",
                            "ERROR",
                        )

                except ClientError as e:
                    if (
                        e.response.get("Error", {}).get("Code")
                        == "NoSuchPublicAccessBlockConfiguration"
                    ):
                        # No public access block configuration
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.CRITICAL.value,
                            finding_title=f"S3 Bucket {bucket_name} No Public Access Block",
                            finding_description=f"S3 bucket {bucket_name} does not have public access block configuration.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable public access block for S3 bucket {bucket_name}.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "public_access_block_configured": False,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ S3 bucket {bucket_name} no public access block", "ERROR"
                        )
                    else:
                        raise

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking S3 public access: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::S3::Bucket",
                resource_id="all_buckets",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="S3 Public Access Check Failed",
                finding_description=f"Unable to check S3 public access: {error_code}",
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

    def _check_logging(self, buckets: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Check if S3 buckets have logging enabled.

        Args:
            buckets: List of bucket dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            s3_client = self.get_client("s3")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Get bucket logging configuration
                    logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
                    logging_enabled = "LoggingEnabled" in logging_config

                    if logging_enabled:
                        target_bucket = logging_config["LoggingEnabled"].get(
                            "TargetBucket", ""
                        )
                        target_prefix = logging_config["LoggingEnabled"].get(
                            "TargetPrefix", ""
                        )

                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"S3 Bucket {bucket_name} Logging Enabled",
                            finding_description=f"S3 bucket {bucket_name} has logging enabled. Target: {target_bucket}/{target_prefix}",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "bucket_name": bucket_name,
                                "logging_enabled": logging_enabled,
                                "target_bucket": target_bucket,
                                "target_prefix": target_prefix,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.MEDIUM.value,
                            finding_title=f"S3 Bucket {bucket_name} Logging Disabled",
                            finding_description=f"S3 bucket {bucket_name} does not have logging enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable access logging for S3 bucket {bucket_name} to track access patterns.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "logging_enabled": logging_enabled,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ S3 bucket {bucket_name} logging disabled", "WARNING"
                        )

                except ClientError as e:
                    logger.error(
                        f"Error checking logging for bucket {bucket_name}: {e}"
                    )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking S3 logging: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::S3::Bucket",
                resource_id="all_buckets",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="S3 Logging Check Failed",
                finding_description=f"Unable to check S3 logging: {error_code}",
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

    def _check_lifecycle(self, buckets: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Check if S3 buckets have lifecycle policies configured.

        Args:
            buckets: List of bucket dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            s3_client = self.get_client("s3")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Get bucket lifecycle configuration
                    lifecycle = s3_client.get_bucket_lifecycle_configuration(
                        Bucket=bucket_name
                    )
                    rules = lifecycle.get("Rules", [])

                    if rules:
                        rule_ids = [rule.get("ID", "unnamed") for rule in rules]

                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"S3 Bucket {bucket_name} Has Lifecycle Policy",
                            finding_description=f"S3 bucket {bucket_name} has {len(rules)} lifecycle rule(s): {', '.join(rule_ids)}",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=False,
                            raw_data={
                                "bucket_name": bucket_name,
                                "lifecycle_rules": len(rules),
                                "rule_ids": rule_ids,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.WARNING.value,
                            priority=Priority.LOW.value,
                            finding_title=f"S3 Bucket {bucket_name} No Lifecycle Policy",
                            finding_description=f"S3 bucket {bucket_name} does not have lifecycle policies configured.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=True,
                            remediation_action=f"Consider configuring lifecycle policies for S3 bucket {bucket_name} to manage object lifecycle and reduce costs.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "lifecycle_rules": 0,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"⚠ S3 bucket {bucket_name} no lifecycle policy", "INFO"
                        )

                except ClientError as e:
                    if (
                        e.response.get("Error", {}).get("Code")
                        == "NoSuchLifecycleConfiguration"
                    ):
                        # No lifecycle configuration
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.WARNING.value,
                            priority=Priority.LOW.value,
                            finding_title=f"S3 Bucket {bucket_name} No Lifecycle Policy",
                            finding_description=f"S3 bucket {bucket_name} does not have lifecycle policies configured.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=True,
                            remediation_action=f"Consider configuring lifecycle policies for S3 bucket {bucket_name} to manage object lifecycle and reduce costs.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "lifecycle_configured": False,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"⚠ S3 bucket {bucket_name} no lifecycle policy", "INFO"
                        )
                    else:
                        raise

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking S3 lifecycle: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::S3::Bucket",
                resource_id="all_buckets",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="S3 Lifecycle Check Failed",
                finding_description=f"Unable to check S3 lifecycle: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_mfa_delete(self, buckets: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Check if S3 buckets have MFA delete enabled.

        Args:
            buckets: List of bucket dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            s3_client = self.get_client("s3")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Get bucket versioning configuration to check MFA delete
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    mfa_delete = versioning.get("MFADelete", "Disabled")

                    if mfa_delete == "Enabled":
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"S3 Bucket {bucket_name} MFA Delete Enabled",
                            finding_description=f"S3 bucket {bucket_name} has MFA delete enabled for additional security.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=False,
                            raw_data={
                                "bucket_name": bucket_name,
                                "mfa_delete": mfa_delete,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.MEDIUM.value,
                            finding_title=f"S3 Bucket {bucket_name} MFA Delete Disabled",
                            finding_description=f"S3 bucket {bucket_name} does not have MFA delete enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable MFA delete for S3 bucket {bucket_name} to require MFA for versioning operations.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "mfa_delete": mfa_delete,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ S3 bucket {bucket_name} MFA delete disabled", "WARNING"
                        )

                except ClientError as e:
                    logger.error(
                        f"Error checking MFA delete for bucket {bucket_name}: {e}"
                    )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking S3 MFA delete: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::S3::Bucket",
                resource_id="all_buckets",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="S3 MFA Delete Check Failed",
                finding_description=f"Unable to check S3 MFA delete: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_default_encryption(
        self, buckets: List[Dict[str, Any]]
    ) -> List[EvidenceRecord]:
        """Check if S3 buckets have default encryption configured.

        Args:
            buckets: List of bucket dictionaries.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            s3_client = self.get_client("s3")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Get bucket encryption configuration
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                        "Rules", []
                    )

                    if rules:
                        # Get the first rule's encryption configuration
                        apply_config = rules[0].get(
                            "ApplyServerSideEncryptionByDefault", {}
                        )
                        sse_algorithm = apply_config.get("SSEAlgorithm", "Unknown")
                        kms_key_id = apply_config.get("KMSMasterKeyID", "")

                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"S3 Bucket {bucket_name} Default Encryption Configured",
                            finding_description=f"S3 bucket {bucket_name} has default encryption configured: {sse_algorithm}",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "bucket_name": bucket_name,
                                "sse_algorithm": sse_algorithm,
                                "kms_key_id": kms_key_id,
                            },
                        )
                        records.append(record)

                except ClientError as e:
                    if (
                        e.response.get("Error", {}).get("Code")
                        == "ServerSideEncryptionConfigurationNotFoundError"
                    ):
                        # No default encryption configured
                        record = self.make_record(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.HIGH.value,
                            finding_title=f"S3 Bucket {bucket_name} No Default Encryption",
                            finding_description=f"S3 bucket {bucket_name} does not have default encryption configured.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Configure default encryption for S3 bucket {bucket_name} using SSE-S3 or SSE-KMS.",
                            raw_data={
                                "bucket_name": bucket_name,
                                "default_encryption_configured": False,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ S3 bucket {bucket_name} no default encryption",
                            "WARNING",
                        )
                    else:
                        raise

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking S3 default encryption: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::S3::Bucket",
                resource_id="all_buckets",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="S3 Default Encryption Check Failed",
                finding_description=f"Unable to check S3 default encryption: {error_code}",
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
