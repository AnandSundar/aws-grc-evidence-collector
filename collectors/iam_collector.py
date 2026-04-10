"""IAM Evidence Collector.

This collector gathers compliance evidence from AWS IAM service, checking for
security best practices and compliance requirements.
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


class IAMCollector(BaseCollector):
    """Collector for IAM security and compliance evidence.

    This collector implements 10 IAM checks:
    1. Root account MFA enabled
    2. IAM users with MFA enabled
    3. IAM users without console access (API-only users)
    4. IAM password policy compliance
    5. IAM access keys rotation (older than 90 days)
    6. IAM users with unused access keys (older than 90 days)
    7. IAM users with unused passwords (older than 90 days)
    8. IAM roles with no active usage
    9. IAM policies with overly permissive actions
    10. IAM groups with no users
    """

    def get_collector_name(self) -> str:
        """Get the name of this collector.

        Returns:
            Collector name as string.
        """
        return "IAMCollector"

    def collect(self) -> List[EvidenceRecord]:
        """Collect all IAM evidence records.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        self.log_colored("Starting IAM evidence collection...", "INFO")

        # Check 1: Root account MFA enabled
        records.extend(self._check_root_mfa())

        # Check 2: IAM users with MFA enabled
        records.extend(self._check_user_mfa())

        # Check 3: IAM users without console access
        records.extend(self._check_api_only_users())

        # Check 4: IAM password policy compliance
        records.extend(self._check_password_policy())

        # Check 5: IAM access keys rotation
        records.extend(self._check_access_key_rotation())

        # Check 6: IAM users with unused access keys
        records.extend(self._check_unused_access_keys())

        # Check 7: IAM users with unused passwords
        records.extend(self._check_unused_passwords())

        # Check 8: IAM roles with no active usage
        records.extend(self._check_unused_roles())

        # Check 9: IAM policies with overly permissive actions
        records.extend(self._check_overly_permissive_policies())

        # Check 10: IAM groups with no users
        records.extend(self._check_empty_groups())

        self.log_colored(f"IAM collection complete: {len(records)} records", "SUCCESS")
        return records

    def _check_root_mfa(self) -> List[EvidenceRecord]:
        """Check if root account has MFA enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            iam_client = self.get_client("iam")

            # Get account summary
            summary = iam_client.get_account_summary()
            mfa_devices = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)

            if mfa_devices > 0:
                record = self.make_record(
                    resource_type="AWS::IAM::RootAccount",
                    resource_id="root",
                    resource_arn=f"arn:aws:iam::{self.account_id}:root",
                    control_status=ControlStatus.PASS.value,
                    priority=Priority.INFO.value,
                    finding_title="Root Account MFA Enabled",
                    finding_description="Root account has MFA device enabled, which is a security best practice.",
                    compliance_frameworks=[
                        "NIST 800-53",
                        "CIS AWS Foundations Benchmark",
                        "SOC 2",
                    ],
                    remediation_available=False,
                    raw_data={"mfa_devices": mfa_devices},
                )
                records.append(record)
                self.log_colored("[OK] Root account MFA is enabled", "SUCCESS")
            else:
                record = self.make_record(
                    resource_type="AWS::IAM::RootAccount",
                    resource_id="root",
                    resource_arn=f"arn:aws:iam::{self.account_id}:root",
                    control_status=ControlStatus.FAIL.value,
                    priority=Priority.CRITICAL.value,
                    finding_title="Root Account MFA Not Enabled",
                    finding_description="Root account does not have MFA enabled. This is a critical security risk.",
                    compliance_frameworks=[
                        "NIST 800-53",
                        "CIS AWS Foundations Benchmark",
                        "SOC 2",
                    ],
                    remediation_available=True,
                    remediation_action="Enable MFA on the root account immediately using the AWS Management Console.",
                    raw_data={"mfa_devices": mfa_devices},
                )
                records.append(record)
                self.log_colored("[FAIL] Root account MFA is NOT enabled", "ERROR")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking root MFA: {error_code} - {e}")

            # Create error record
            record = self.make_record(
                resource_type="AWS::IAM::RootAccount",
                resource_id="root",
                resource_arn=f"arn:aws:iam::{self.account_id}:root",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Root MFA Check Failed",
                finding_description=f"Unable to check root MFA status: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_user_mfa(self) -> List[EvidenceRecord]:
        """Check which IAM users have MFA enabled.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            iam_client = self.get_client("iam")
            paginator = self.get_paginator("iam", "list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    # Get MFA devices for this user
                    mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
                    has_mfa = len(mfa_devices.get("MFADevices", [])) > 0

                    if has_mfa:
                        record = self.make_record(
                            resource_type="AWS::IAM::User",
                            resource_id=user_name,
                            resource_arn=user_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"IAM User {user_name} Has MFA",
                            finding_description=f"User {user_name} has MFA device enabled.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=False,
                            raw_data={
                                "has_mfa": True,
                                "mfa_devices": mfa_devices.get("MFADevices", []),
                            },
                        )
                        records.append(record)
                    else:
                        record = self.make_record(
                            resource_type="AWS::IAM::User",
                            resource_id=user_name,
                            resource_arn=user_arn,
                            control_status=ControlStatus.FAIL.value,
                            priority=Priority.HIGH.value,
                            finding_title=f"IAM User {user_name} Lacks MFA",
                            finding_description=f"User {user_name} does not have MFA enabled. This increases security risk.",
                            compliance_frameworks=[
                                "NIST 800-53",
                                "CIS AWS Foundations Benchmark",
                                "SOC 2",
                            ],
                            remediation_available=True,
                            remediation_action=f"Enable MFA for user {user_name} through the AWS Management Console or CLI.",
                            raw_data={"has_mfa": False},
                        )
                        records.append(record)
                        self.log_colored(f"[FAIL] User {user_name} lacks MFA", "WARNING")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking user MFA: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::IAM::User",
                resource_id="all_users",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="User MFA Check Failed",
                finding_description=f"Unable to check user MFA status: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_api_only_users(self) -> List[EvidenceRecord]:
        """Check for IAM users with API-only access (no console password).

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            iam_client = self.get_client("iam")
            paginator = self.get_paginator("iam", "list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    # Get login profile (console access)
                    try:
                        iam_client.get_login_profile(UserName=user_name)
                        has_console_access = True
                    except ClientError as e:
                        if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                            has_console_access = False
                        else:
                            raise

                    # Get access keys
                    access_keys = iam_client.list_access_keys(UserName=user_name)
                    has_access_keys = len(access_keys.get("AccessKeyMetadata", [])) > 0

                    if has_access_keys and not has_console_access:
                        record = self.make_record(
                            resource_type="AWS::IAM::User",
                            resource_id=user_name,
                            resource_arn=user_arn,
                            control_status=ControlStatus.PASS.value,
                            priority=Priority.INFO.value,
                            finding_title=f"API-Only User: {user_name}",
                            finding_description=f"User {user_name} has API access but no console access. This is a valid pattern for service accounts.",
                            compliance_frameworks=["NIST 800-53", "SOC 2"],
                            remediation_available=False,
                            raw_data={
                                "has_console_access": False,
                                "has_access_keys": True,
                            },
                        )
                        records.append(record)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking API-only users: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::IAM::User",
                resource_id="all_users",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="API-Only User Check Failed",
                finding_description=f"Unable to check API-only users: {error_code}",
                compliance_frameworks=["NIST 800-53", "SOC 2"],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_password_policy(self) -> List[EvidenceRecord]:
        """Check IAM password policy compliance.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            iam_client = self.get_client("iam")

            # Get account password policy
            try:
                policy = iam_client.get_account_password_policy().get(
                    "PasswordPolicy", {}
                )

                # Check policy requirements
                issues = []

                if not policy.get("MinimumPasswordLength", 0) >= 14:
                    issues.append("Minimum password length less than 14")

                if not policy.get("RequireSymbols", False):
                    issues.append("Symbols not required in password")

                if not policy.get("RequireNumbers", False):
                    issues.append("Numbers not required in password")

                if not policy.get("RequireUppercaseCharacters", False):
                    issues.append("Uppercase characters not required in password")

                if not policy.get("RequireLowercaseCharacters", False):
                    issues.append("Lowercase characters not required in password")

                if not policy.get("MaxPasswordAge", 0) > 0:
                    issues.append("No maximum password age set")

                if not policy.get("PasswordReusePrevention", 0) >= 5:
                    issues.append("Password reuse prevention less than 5")

                if issues:
                    record = self.make_record(
                        resource_type="AWS::IAM::AccountPasswordPolicy",
                        resource_id="account",
                        resource_arn=f"arn:aws:iam::{self.account_id}:account",
                        control_status=ControlStatus.FAIL.value,
                        priority=Priority.HIGH.value,
                        finding_title="IAM Password Policy Non-Compliant",
                        finding_description=f"Password policy has {len(issues)} issues: {', '.join(issues)}",
                        compliance_frameworks=[
                            "NIST 800-53",
                            "CIS AWS Foundations Benchmark",
                            "SOC 2",
                        ],
                        remediation_available=True,
                        remediation_action="Update the IAM password policy to meet security best practices.",
                        raw_data={"policy": policy, "issues": issues},
                    )
                    records.append(record)
                    self.log_colored(
                        f"[FAIL] Password policy has {len(issues)} issues", "WARNING"
                    )
                else:
                    record = self.make_record(
                        resource_type="AWS::IAM::AccountPasswordPolicy",
                        resource_id="account",
                        resource_arn=f"arn:aws:iam::{self.account_id}:account",
                        control_status=ControlStatus.PASS.value,
                        priority=Priority.INFO.value,
                        finding_title="IAM Password Policy Compliant",
                        finding_description="IAM password policy meets security best practices.",
                        compliance_frameworks=[
                            "NIST 800-53",
                            "CIS AWS Foundations Benchmark",
                            "SOC 2",
                        ],
                        remediation_available=False,
                        raw_data={"policy": policy},
                    )
                    records.append(record)
                    self.log_colored("[OK] Password policy is compliant", "SUCCESS")

            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                    # No password policy set
                    record = self.make_record(
                        resource_type="AWS::IAM::AccountPasswordPolicy",
                        resource_id="account",
                        resource_arn=f"arn:aws:iam::{self.account_id}:account",
                        control_status=ControlStatus.FAIL.value,
                        priority=Priority.CRITICAL.value,
                        finding_title="No IAM Password Policy Set",
                        finding_description="No custom password policy is set. AWS default policy may not meet security requirements.",
                        compliance_frameworks=[
                            "NIST 800-53",
                            "CIS AWS Foundations Benchmark",
                            "SOC 2",
                        ],
                        remediation_available=True,
                        remediation_action="Create and apply a strong IAM password policy.",
                        raw_data={"policy_exists": False},
                    )
                    records.append(record)
                    self.log_colored("[FAIL] No password policy set", "ERROR")
                else:
                    raise

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking password policy: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::IAM::AccountPasswordPolicy",
                resource_id="account",
                resource_arn=f"arn:aws:iam::{self.account_id}:account",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Password Policy Check Failed",
                finding_description=f"Unable to check password policy: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_access_key_rotation(self) -> List[EvidenceRecord]:
        """Check for IAM access keys older than 90 days.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []
        max_age_days = 90

        try:
            iam_client = self.get_client("iam")
            user_paginator = self.get_paginator("iam", "list_users")

            for page in user_paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    # Get access keys for this user
                    key_paginator = self.get_paginator("iam", "list_access_keys")
                    for key_page in key_paginator.paginate(UserName=user_name):
                        for key in key_page.get("AccessKeyMetadata", []):
                            key_id = key["AccessKeyId"]
                            create_date = key["CreateDate"]
                            age_days = (datetime.now(timezone.utc) - create_date).days

                            if age_days > max_age_days:
                                record = self.make_record(
                                    resource_type="AWS::IAM::AccessKey",
                                    resource_id=key_id,
                                    resource_arn=f"arn:aws:iam::{self.account_id}:user/{user_name}",
                                    control_status=ControlStatus.FAIL.value,
                                    priority=Priority.HIGH.value,
                                    finding_title=f"Old Access Key: {key_id}",
                                    finding_description=f"Access key {key_id} for user {user_name} is {age_days} days old (max: {max_age_days} days).",
                                    compliance_frameworks=[
                                        "NIST 800-53",
                                        "CIS AWS Foundations Benchmark",
                                        "SOC 2",
                                    ],
                                    remediation_available=True,
                                    remediation_action=f"Rotate access key {key_id} for user {user_name}.",
                                    raw_data={
                                        "user_name": user_name,
                                        "key_id": key_id,
                                        "create_date": create_date.isoformat(),
                                        "age_days": age_days,
                                        "max_age_days": max_age_days,
                                    },
                                )
                                records.append(record)
                                self.log_colored(
                                    f"[FAIL] Key {key_id} is {age_days} days old", "WARNING"
                                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking access key rotation: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::IAM::AccessKey",
                resource_id="all_keys",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Access Key Rotation Check Failed",
                finding_description=f"Unable to check access key rotation: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_unused_access_keys(self) -> List[EvidenceRecord]:
        """Check for IAM users with unused access keys (older than 90 days).

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []
        max_unused_days = 90

        try:
            iam_client = self.get_client("iam")
            user_paginator = self.get_paginator("iam", "list_users")

            for page in user_paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    # Get access keys for this user
                    key_paginator = self.get_paginator("iam", "list_access_keys")
                    for key_page in key_paginator.paginate(UserName=user_name):
                        for key in key_page.get("AccessKeyMetadata", []):
                            key_id = key["AccessKeyId"]

                            # Get last used date
                            try:
                                last_used = iam_client.get_access_key_last_used(
                                    AccessKeyId=key_id
                                ).get("AccessKeyLastUsed", {})

                                last_used_date = last_used.get("LastUsedDate")

                                if last_used_date:
                                    unused_days = (
                                        datetime.now(timezone.utc) - last_used_date
                                    ).days

                                    if unused_days > max_unused_days:
                                        record = self.make_record(
                                            resource_type="AWS::IAM::AccessKey",
                                            resource_id=key_id,
                                            resource_arn=f"arn:aws:iam::{self.account_id}:user/{user_name}",
                                            control_status=ControlStatus.FAIL.value,
                                            priority=Priority.MEDIUM.value,
                                            finding_title=f"Unused Access Key: {key_id}",
                                            finding_description=f"Access key {key_id} for user {user_name} has not been used for {unused_days} days.",
                                            compliance_frameworks=[
                                                "NIST 800-53",
                                                "CIS AWS Foundations Benchmark",
                                                "SOC 2",
                                            ],
                                            remediation_available=True,
                                            remediation_action=f"Delete or disable unused access key {key_id} for user {user_name}.",
                                            raw_data={
                                                "user_name": user_name,
                                                "key_id": key_id,
                                                "last_used_date": last_used_date.isoformat(),
                                                "unused_days": unused_days,
                                                "max_unused_days": max_unused_days,
                                            },
                                        )
                                        records.append(record)
                                        self.log_colored(
                                            f"[FAIL] Key {key_id} unused for {unused_days} days",
                                            "WARNING",
                                        )
                            except ClientError as e:
                                logger.warning(
                                    f"Could not get last used for key {key_id}: {e}"
                                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking unused access keys: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::IAM::AccessKey",
                resource_id="all_keys",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Unused Access Key Check Failed",
                finding_description=f"Unable to check unused access keys: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_unused_passwords(self) -> List[EvidenceRecord]:
        """Check for IAM users with unused passwords (older than 90 days).

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []
        max_unused_days = 90

        try:
            iam_client = self.get_client("iam")
            paginator = self.get_paginator("iam", "list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    # Check if user has console access
                    try:
                        login_profile = iam_client.get_login_profile(UserName=user_name)
                        password_last_used = user.get("PasswordLastUsed")

                        if password_last_used:
                            unused_days = (
                                datetime.now(timezone.utc) - password_last_used
                            ).days

                            if unused_days > max_unused_days:
                                record = self.make_record(
                                    resource_type="AWS::IAM::User",
                                    resource_id=user_name,
                                    resource_arn=user_arn,
                                    control_status=ControlStatus.FAIL.value,
                                    priority=Priority.MEDIUM.value,
                                    finding_title=f"Unused Password: {user_name}",
                                    finding_description=f"User {user_name} has not used their password for {unused_days} days.",
                                    compliance_frameworks=[
                                        "NIST 800-53",
                                        "CIS AWS Foundations Benchmark",
                                        "SOC 2",
                                    ],
                                    remediation_available=True,
                                    remediation_action=f"Review and potentially disable user {user_name} if no longer needed.",
                                    raw_data={
                                        "user_name": user_name,
                                        "password_last_used": password_last_used.isoformat(),
                                        "unused_days": unused_days,
                                        "max_unused_days": max_unused_days,
                                    },
                                )
                                records.append(record)
                                self.log_colored(
                                    f"[FAIL] User {user_name} password unused for {unused_days} days",
                                    "WARNING",
                                )
                    except ClientError as e:
                        if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                            # No console access, skip
                            pass
                        else:
                            raise

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking unused passwords: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::IAM::User",
                resource_id="all_users",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Unused Password Check Failed",
                finding_description=f"Unable to check unused passwords: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_unused_roles(self) -> List[EvidenceRecord]:
        """Check for IAM roles with no active usage.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            iam_client = self.get_client("iam")
            paginator = self.get_paginator("iam", "list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    role_last_used = role.get("RoleLastUsed", {})
                    last_used_date = role_last_used.get("LastUsedDate")

                    if not last_used_date:
                        # Role has never been used
                        record = self.make_record(
                            resource_type="AWS::IAM::Role",
                            resource_id=role_name,
                            resource_arn=role_arn,
                            control_status=ControlStatus.WARNING.value,
                            priority=Priority.LOW.value,
                            finding_title=f"Unused Role: {role_name}",
                            finding_description=f"Role {role_name} has never been used.",
                            compliance_frameworks=["NIST 800-53", "SOC 2"],
                            remediation_available=True,
                            remediation_action=f"Review and delete role {role_name} if no longer needed.",
                            raw_data={
                                "role_name": role_name,
                                "last_used": None,
                            },
                        )
                        records.append(record)
                        self.log_colored(
                            f"[WARN] Role {role_name} has never been used", "INFO"
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking unused roles: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::IAM::Role",
                resource_id="all_roles",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Unused Role Check Failed",
                finding_description=f"Unable to check unused roles: {error_code}",
                compliance_frameworks=["NIST 800-53", "SOC 2"],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _check_overly_permissive_policies(self) -> List[EvidenceRecord]:
        """Check for IAM policies with overly permissive actions (e.g., "*").

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            iam_client = self.get_client("iam")

            # Check inline policies for users
            user_paginator = self.get_paginator("iam", "list_users")
            for page in user_paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    # Get user policies
                    policy_paginator = self.get_paginator("iam", "list_user_policies")
                    for policy_page in policy_paginator.paginate(UserName=user_name):
                        for policy_name in policy_page.get("PolicyNames", []):
                            policy_doc = iam_client.get_user_policy(
                                UserName=user_name, PolicyName=policy_name
                            ).get("PolicyDocument", {})

                            if self._has_wildcard_action(policy_doc):
                                record = self.make_record(
                                    resource_type="AWS::IAM::Policy",
                                    resource_id=f"{user_name}/{policy_name}",
                                    resource_arn=f"arn:aws:iam::{self.account_id}:user/{user_name}",
                                    control_status=ControlStatus.FAIL.value,
                                    priority=Priority.HIGH.value,
                                    finding_title=f"Overly Permissive Policy: {policy_name}",
                                    finding_description=f"User policy {policy_name} for user {user_name} contains wildcard actions.",
                                    compliance_frameworks=[
                                        "NIST 800-53",
                                        "CIS AWS Foundations Benchmark",
                                        "SOC 2",
                                    ],
                                    remediation_available=True,
                                    remediation_action=f"Review and restrict permissions in policy {policy_name} for user {user_name}.",
                                    raw_data={
                                        "user_name": user_name,
                                        "policy_name": policy_name,
                                        "policy_document": policy_doc,
                                    },
                                )
                                records.append(record)
                                self.log_colored(
                                    f"[FAIL] Policy {policy_name} has wildcard actions",
                                    "WARNING",
                                )

            # Check managed policies
            policy_paginator = self.get_paginator("iam", "list_policies")
            for page in policy_paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_name = policy["PolicyName"]
                    policy_arn = policy["Arn"]

                    # Get policy version
                    version = iam_client.get_policy(PolicyArn=policy_arn).get(
                        "Policy", {}
                    )
                    default_version_id = version.get("DefaultVersionId")

                    if default_version_id:
                        policy_doc = (
                            iam_client.get_policy_version(
                                PolicyArn=policy_arn, VersionId=default_version_id
                            )
                            .get("PolicyVersion", {})
                            .get("Document", {})
                        )

                        if self._has_wildcard_action(policy_doc):
                            record = self.make_record(
                                resource_type="AWS::IAM::Policy",
                                resource_id=policy_name,
                                resource_arn=policy_arn,
                                control_status=ControlStatus.FAIL.value,
                                priority=Priority.HIGH.value,
                                finding_title=f"Overly Permissive Managed Policy: {policy_name}",
                                finding_description=f"Managed policy {policy_name} contains wildcard actions.",
                                compliance_frameworks=[
                                    "NIST 800-53",
                                    "CIS AWS Foundations Benchmark",
                                    "SOC 2",
                                ],
                                remediation_available=True,
                                remediation_action=f"Review and restrict permissions in managed policy {policy_name}.",
                                raw_data={
                                    "policy_name": policy_name,
                                    "policy_arn": policy_arn,
                                    "policy_document": policy_doc,
                                },
                            )
                            records.append(record)
                            self.log_colored(
                                f"[FAIL] Managed policy {policy_name} has wildcard actions",
                                "WARNING",
                            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(
                f"Error checking overly permissive policies: {error_code} - {e}"
            )

            record = self.make_record(
                resource_type="AWS::IAM::Policy",
                resource_id="all_policies",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Overly Permissive Policy Check Failed",
                finding_description=f"Unable to check overly permissive policies: {error_code}",
                compliance_frameworks=[
                    "NIST 800-53",
                    "CIS AWS Foundations Benchmark",
                    "SOC 2",
                ],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records

    def _has_wildcard_action(self, policy_doc: Dict[str, Any]) -> bool:
        """Check if a policy document contains wildcard actions.

        Args:
            policy_doc: IAM policy document.

        Returns:
            True if policy contains wildcard actions, False otherwise.
        """
        statements = policy_doc.get("Statement", [])

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            actions = statement.get("Action", [])

            # Handle both string and list of strings
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if action == "*" or action.endswith(":*"):
                    return True

        return False

    def _check_empty_groups(self) -> List[EvidenceRecord]:
        """Check for IAM groups with no users.

        Returns:
            List of EvidenceRecord objects.
        """
        records: List[EvidenceRecord] = []

        try:
            iam_client = self.get_client("iam")
            paginator = self.get_paginator("iam", "list_groups")

            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    group_name = group["GroupName"]
                    group_arn = group["Arn"]

                    # Get users in group
                    users = iam_client.get_group(GroupName=group_name).get("Users", [])

                    if len(users) == 0:
                        record = self.make_record(
                            resource_type="AWS::IAM::Group",
                            resource_id=group_name,
                            resource_arn=group_arn,
                            control_status=ControlStatus.WARNING.value,
                            priority=Priority.LOW.value,
                            finding_title=f"Empty Group: {group_name}",
                            finding_description=f"IAM group {group_name} has no users.",
                            compliance_frameworks=["NIST 800-53", "SOC 2"],
                            remediation_available=True,
                            remediation_action=f"Review and delete empty group {group_name} if no longer needed.",
                            raw_data={
                                "group_name": group_name,
                                "user_count": 0,
                            },
                        )
                        records.append(record)
                        self.log_colored(f"[WARN] Group {group_name} is empty", "INFO")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Error checking empty groups: {error_code} - {e}")

            record = self.make_record(
                resource_type="AWS::IAM::Group",
                resource_id="all_groups",
                control_status=ControlStatus.UNKNOWN.value,
                priority=Priority.INFO.value,
                finding_title="Empty Group Check Failed",
                finding_description=f"Unable to check empty groups: {error_code}",
                compliance_frameworks=["NIST 800-53", "SOC 2"],
                raw_data={"error": str(e), "error_code": error_code},
            )
            records.append(record)

        return records
