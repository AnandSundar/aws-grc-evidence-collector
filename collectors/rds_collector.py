"""RDS Evidence Collector.

This collector gathers compliance evidence from AWS RDS service, checking for
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


class RDSCollector(BaseCollector):
    """Collector for RDS security and compliance evidence.

    This collector implements 9 RDS checks:
    1. RDS instances with encryption at rest enabled
    2. RDS instances with automated backups enabled
    3. RDS instances with multi-AZ deployment
    4. RDS instances with public accessibility disabled
    5. RDS instances with minor version upgrade enabled
    6. RDS instances with deletion protection enabled
    7. RDS instances with enhanced monitoring enabled
    8. RDS instances with performance insights enabled
    9. RDS snapshots encrypted
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "RDSCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all RDS evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting RDS evidence collection...", "INFO")

        # Check 1: RDS instances with encryption at rest enabled
        records.extend(self._check_encryption_at_rest())

        # Check 2: RDS instances with automated backups enabled
        records.extend(self._check_automated_backups())

        # Check 3: RDS instances with multi-AZ deployment
        records.extend(self._check_multi_az())

        # Check 4: RDS instances with public accessibility disabled
        records.extend(self._check_public_accessibility())

        # Check 5: RDS instances with minor version upgrade enabled
        records.extend(self._check_minor_version_upgrade())

        # Check 6: RDS instances with deletion protection enabled
        records.extend(self._check_deletion_protection())

        # Check 7: RDS instances with enhanced monitoring enabled
        records.extend(self._check_enhanced_monitoring())

        # Check 8: RDS instances with performance insights enabled
        records.extend(self._check_performance_insights())

        # Check 9: RDS snapshots encrypted
        records.extend(self._check_snapshot_encryption())

        self.log_colored(f"RDS collection complete: {len(records)} records", "SUCCESS")
        return records

    def _check_encryption_at_rest(self) -> List[EvidenceRecord]:
        """Check if RDS instances have encryption at rest enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")
            paginator = self.get_paginator("rds", "describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance["DBInstanceIdentifier"]
                    db_arn = db_instance["DBInstanceArn"]
                    encrypted = db_instance.get("StorageEncrypted", False)
                    engine = db_instance.get("Engine", "unknown")

                    if encrypted:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Instance {db_id} Encrypted",
                            finding_description=f"RDS instance {db_id} ({engine}) has encryption at rest enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "encrypted": encrypted,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.HIGH.value,
                            finding_title=f"RDS Instance {db_id} Not Encrypted",
                            finding_description=f"RDS instance {db_id} ({engine}) does not have encryption at rest enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable encryption at rest for RDS instance {db_id}. Note: This requires creating a new instance and restoring from snapshot.",
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "encrypted": encrypted,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS instance {db_id} not encrypted", "WARNING"
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking RDS encryption: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::RDS::DBInstance",
                resource_id="all_instances",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Encryption Check Failed",
                finding_description=f"Unable to check RDS encryption: {error_code}",
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

    def _check_automated_backups(self) -> List[EvidenceRecord]:
        """Check if RDS instances have automated backups enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")
            paginator = self.get_paginator("rds", "describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance["DBInstanceIdentifier"]
                    db_arn = db_instance["DBInstanceArn"]
                    backup_retention = db_instance.get("BackupRetentionPeriod", 0)
                    engine = db_instance.get("Engine", "unknown")

                    if backup_retention > 0:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Instance {db_id} Has Backups",
                            finding_description=f"RDS instance {db_id} ({engine}) has automated backups enabled with {backup_retention} day retention.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "backup_retention_period": backup_retention,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.CRITICAL.value,
                            finding_title=f"RDS Instance {db_id} No Backups",
                            finding_description=f"RDS instance {db_id} ({engine}) does not have automated backups enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable automated backups for RDS instance {db_id} with appropriate retention period.",
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "backup_retention_period": backup_retention,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS instance {db_id} has no backups", "ERROR"
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking RDS backups: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::RDS::DBInstance",
                resource_id="all_instances",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Backup Check Failed",
                finding_description=f"Unable to check RDS backups: {error_code}",
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

    def _check_multi_az(self) -> List[EvidenceRecord]:
        """Check if RDS instances have multi-AZ deployment enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")
            paginator = self.get_paginator("rds", "describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance["DBInstanceIdentifier"]
                    db_arn = db_instance["DBInstanceArn"]
                    multi_az = db_instance.get("MultiAZ", False)
                    engine = db_instance.get("Engine", "unknown")

                    if multi_az:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Instance {db_id} Has Multi-AZ",
                            finding_description=f"RDS instance {db_id} ({engine}) has multi-AZ deployment enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "multi_az": multi_az,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.HIGH.value,
                            finding_title=f"RDS Instance {db_id} No Multi-AZ",
                            finding_description=f"RDS instance {db_id} ({engine}) does not have multi-AZ deployment enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable multi-AZ deployment for RDS instance {db_id} for high availability.",
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "multi_az": multi_az,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS instance {db_id} not multi-AZ", "WARNING"
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking RDS multi-AZ: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::RDS::DBInstance",
                resource_id="all_instances",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Multi-AZ Check Failed",
                finding_description=f"Unable to check RDS multi-AZ: {error_code}",
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

    def _check_public_accessibility(self) -> List[EvidenceRecord]:
        """Check if RDS instances have public accessibility disabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")
            paginator = self.get_paginator("rds", "describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance["DBInstanceIdentifier"]
                    db_arn = db_instance["DBInstanceArn"]
                    publicly_accessible = db_instance.get("PubliclyAccessible", False)
                    engine = db_instance.get("Engine", "unknown")

                    if not publicly_accessible:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Instance {db_id} Not Public",
                            finding_description=f"RDS instance {db_id} ({engine}) is not publicly accessible.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "publicly_accessible": publicly_accessible,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.CRITICAL.value,
                            finding_title=f"RDS Instance {db_id} Is Public",
                            finding_description=f"RDS instance {db_id} ({engine}) is publicly accessible. This is a security risk.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Disable public accessibility for RDS instance {db_id} and use VPC endpoints or VPN for access.",
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "publicly_accessible": publicly_accessible,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS instance {db_id} is publicly accessible", "ERROR"
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking RDS public accessibility: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::RDS::DBInstance",
                resource_id="all_instances",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Public Accessibility Check Failed",
                finding_description=f"Unable to check RDS public accessibility: {error_code}",
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

    def _check_minor_version_upgrade(self) -> List[EvidenceRecord]:
        """Check if RDS instances have minor version upgrade enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")
            paginator = self.get_paginator("rds", "describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance["DBInstanceIdentifier"]
                    db_arn = db_instance["DBInstanceArn"]
                    auto_minor_version_upgrade = db_instance.get(
                        "AutoMinorVersionUpgrade", False
                    )
                    engine = db_instance.get("Engine", "unknown")

                    if auto_minor_version_upgrade:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Instance {db_id} Auto Minor Version Upgrade",
                            finding_description=f"RDS instance {db_id} ({engine}) has automatic minor version upgrade enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=False,
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "auto_minor_version_upgrade": auto_minor_version_upgrade,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.MEDIUM.value,
                            finding_title=f"RDS Instance {db_id} No Auto Minor Version Upgrade",
                            finding_description=f"RDS instance {db_id} ({engine}) does not have automatic minor version upgrade enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable automatic minor version upgrade for RDS instance {db_id}.",
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "auto_minor_version_upgrade": auto_minor_version_upgrade,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS instance {db_id} no auto minor version upgrade",
                            "WARNING",
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(
                f"Error checking RDS minor version upgrade: {error_code} - {e}"
            )

            record = self.make_record(
                resource_type="AWS::RDS::DBInstance",
                resource_id="all_instances",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Minor Version Upgrade Check Failed",
                finding_description=f"Unable to check RDS minor version upgrade: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_deletion_protection(self) -> List[EvidenceRecord]:
        """Check if RDS instances have deletion protection enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")
            paginator = self.get_paginator("rds", "describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance["DBInstanceIdentifier"]
                    db_arn = db_instance["DBInstanceArn"]
                    deletion_protection = db_instance.get("DeletionProtection", False)
                    engine = db_instance.get("Engine", "unknown")

                    if deletion_protection:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Instance {db_id} Has Deletion Protection",
                            finding_description=f"RDS instance {db_id} ({engine}) has deletion protection enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=False,
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "deletion_protection": deletion_protection,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.MEDIUM.value,
                            finding_title=f"RDS Instance {db_id} No Deletion Protection",
                            finding_description=f"RDS instance {db_id} ({engine}) does not have deletion protection enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable deletion protection for RDS instance {db_id}.",
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "deletion_protection": deletion_protection,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS instance {db_id} no deletion protection", "WARNING"
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking RDS deletion protection: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::RDS::DBInstance",
                resource_id="all_instances",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Deletion Protection Check Failed",
                finding_description=f"Unable to check RDS deletion protection: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_enhanced_monitoring(self) -> List[EvidenceRecord]:
        """Check if RDS instances have enhanced monitoring enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")
            paginator = self.get_paginator("rds", "describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance["DBInstanceIdentifier"]
                    db_arn = db_instance["DBInstanceArn"]
                    monitoring_interval = db_instance.get("MonitoringInterval", 0)
                    engine = db_instance.get("Engine", "unknown")

                    if monitoring_interval > 0:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Instance {db_id} Has Enhanced Monitoring",
                            finding_description=f"RDS instance {db_id} ({engine}) has enhanced monitoring enabled with {monitoring_interval}s interval.",
                            compliance_frameworks=["NIST 800-53", "SOC 2"],
                            remediation_available=False,
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "monitoring_interval": monitoring_interval,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.LOW.value,
                            finding_title=f"RDS Instance {db_id} No Enhanced Monitoring",
                            finding_description=f"RDS instance {db_id} ({engine}) does not have enhanced monitoring enabled.",
                            compliance_frameworks=["NIST 800-53", "SOC 2"],
                            remediation_available=True,
                            remediation_action=f"Enable enhanced monitoring for RDS instance {db_id}.",
                            raw_data={
                                "db_instance_id": db_id,
                                "engine": engine,
                                "monitoring_interval": monitoring_interval,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS instance {db_id} no enhanced monitoring", "INFO"
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking RDS enhanced monitoring: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::RDS::DBInstance",
                resource_id="all_instances",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Enhanced Monitoring Check Failed",
                finding_description=f"Unable to check RDS enhanced monitoring: {error_code}",
                compliance_frameworks=["NIST 800-53", "SOC 2"],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_performance_insights(self) -> List[EvidenceRecord]:
        """Check if RDS instances have Performance Insights enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")
            paginator = self.get_paginator("rds", "describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance["DBInstanceIdentifier"]
                    db_arn = db_instance["DBInstanceArn"]
                    performance_insights_enabled = db_instance.get(
                        "PerformanceInsightsEnabled", False
                    )
                    engine = db_instance.get("Engine", "unknown")

                    # Performance Insights is only available for certain engines
                    supported_engines = [
                        "mysql",
                        "postgres",
                        "aurora-mysql",
                        "aurora-postgresql",
                    ]

                    if engine in supported_engines:
                        if performance_insights_enabled:
                            record = self.make_record(
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                resource_arn=db_arn,
                                control_status=ControlStatus.PASS.value,
                                priority=Priority.INFO.value,
                                finding_title=f"RDS Instance {db_id} Has Performance Insights",
                                finding_description=f"RDS instance {db_id} ({engine}) has Performance Insights enabled.",
                                compliance_frameworks=["NIST 800-53", "SOC 2"],
                                remediation_available=False,
                                raw_data={
                                    "db_instance_id": db_id,
                                    "engine": engine,
                                    "performance_insights_enabled": performance_insights_enabled,
                                },
                            )
                            records.append(record)
                        else:
                            record = self.make_record(
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                resource_arn=db_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.LOW.value,
                                finding_title=f"RDS Instance {db_id} No Performance Insights",
                                finding_description=f"RDS instance {db_id} ({engine}) does not have Performance Insights enabled.",
                                compliance_frameworks=["NIST 800-53", "SOC 2"],
                                remediation_available=True,
                                remediation_action=f"Enable Performance Insights for RDS instance {db_id}.",
                                raw_data={
                                    "db_instance_id": db_id,
                                    "engine": engine,
                                    "performance_insights_enabled": performance_insights_enabled,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"✗ RDS instance {db_id} no Performance Insights",
                                "INFO",
                            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking RDS Performance Insights: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::RDS::DBInstance",
                resource_id="all_instances",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Performance Insights Check Failed",
                finding_description=f"Unable to check RDS Performance Insights: {error_code}",
                compliance_frameworks=["NIST 800-53", "SOC 2"],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_snapshot_encryption(self) -> List[EvidenceRecord]:
        """Check if RDS snapshots are encrypted.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            rds_client = self.get_client("rds")

            # Check DB snapshots
            snapshot_paginator = self.get_paginator("rds", "describe_db_snapshots")
            for page in snapshot_paginator.paginate():
                for snapshot in page.get("DBSnapshots", []):
                    snapshot_id = snapshot["DBSnapshotIdentifier"]
                    snapshot_arn = snapshot["DBSnapshotArn"]
                    encrypted = snapshot.get("Encrypted", False)
                    snapshot_type = snapshot.get("SnapshotType", "manual")

                    if encrypted:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBSnapshot",
                            resource_id=snapshot_id,
                            resource_arn=snapshot_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Snapshot {snapshot_id} Encrypted",
                            finding_description=f"RDS snapshot {snapshot_id} ({snapshot_type}) is encrypted.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "snapshot_id": snapshot_id,
                                "snapshot_type": snapshot_type,
                                "encrypted": encrypted,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBSnapshot",
                            resource_id=snapshot_id,
                            resource_arn=snapshot_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.HIGH.value,
                            finding_title=f"RDS Snapshot {snapshot_id} Not Encrypted",
                            finding_description=f"RDS snapshot {snapshot_id} ({snapshot_type}) is not encrypted.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Encrypt RDS snapshot {snapshot_id} by copying it to an encrypted snapshot.",
                            raw_data={
                                "snapshot_id": snapshot_id,
                                "snapshot_type": snapshot_type,
                                "encrypted": encrypted,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS snapshot {snapshot_id} not encrypted", "WARNING"
                        )

            # Check cluster snapshots
            cluster_snapshot_paginator = self.get_paginator(
                "rds", "describe_db_cluster_snapshots"
            )
            for page in cluster_snapshot_paginator.paginate():
                for snapshot in page.get("DBClusterSnapshots", []):
                    snapshot_id = snapshot["DBClusterSnapshotIdentifier"]
                    snapshot_arn = snapshot["DBClusterSnapshotArn"]
                    encrypted = snapshot.get("StorageEncrypted", False)
                    snapshot_type = snapshot.get("SnapshotType", "manual")

                    if encrypted:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBClusterSnapshot",
                            resource_id=snapshot_id,
                            resource_arn=snapshot_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"RDS Cluster Snapshot {snapshot_id} Encrypted",
                            finding_description=f"RDS cluster snapshot {snapshot_id} ({snapshot_type}) is encrypted.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=False,
                            raw_data={
                                "snapshot_id": snapshot_id,
                                "snapshot_type": snapshot_type,
                                "encrypted": encrypted,
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::RDS::DBClusterSnapshot",
                            resource_id=snapshot_id,
                            resource_arn=snapshot_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.HIGH.value,
                            finding_title=f"RDS Cluster Snapshot {snapshot_id} Not Encrypted",
                            finding_description=f"RDS cluster snapshot {snapshot_id} ({snapshot_type}) is not encrypted.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                                "PCI-DSS",
                            ],
                            remediation_available=True,
                            remediation_action=f"Encrypt RDS cluster snapshot {snapshot_id} by copying it to an encrypted snapshot.",
                            raw_data={
                                "snapshot_id": snapshot_id,
                                "snapshot_type": snapshot_type,
                                "encrypted": encrypted,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"✗ RDS cluster snapshot {snapshot_id} not encrypted",
                            "WARNING",
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking RDS snapshot encryption: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::RDS::DBSnapshot",
                resource_id="all_snapshots",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="RDS Snapshot Encryption Check Failed",
                finding_description=f"Unable to check RDS snapshot encryption: {error_code}",
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
