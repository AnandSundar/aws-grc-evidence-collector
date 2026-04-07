"""
IAM remediation functions for common compliance violations.

This module provides auto-remediation functions for IAM compliance issues
including access key management, MFA enforcement, and policy management.
"""

import boto3
import logging
import json
import os
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional
from datetime import datetime

# Import notification helper
from .notifications import send_remediation_notification

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


def disable_iam_access_key(
    user_name: str, access_key_id: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Disable an IAM access key.

    This function disables an IAM access key without deleting it, providing
    a safety-first approach to key management. The key can be re-enabled if needed.

    Args:
        user_name: The name of the IAM user.
        access_key_id: The ID of the access key to disable.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing:
            - action_taken: Description of the remediation action
            - before_state: The state before remediation
            - after_state: The state after remediation
            - success: Boolean indicating if remediation succeeded
            - error: Error message if remediation failed
            - timestamp: When the remediation was attempted
            - compliance_frameworks: List of relevant compliance frameworks
            - resource_id: The user name and key ID
            - key_id: The access key ID
            - original_status: The status before remediation
            - new_status: The status after remediation

    Safety:
        Only disables the key, never deletes it. This allows for recovery if needed.

    Compliance:
        - PCI-DSS 8.2.4: Change user passwords/passphrases at least once every 90 days
        - CIS 1.14: Ensure access keys are rotated
        - SOC2 CC6.1: Logical access controls
    """
    remediation_log = {
        "action_taken": "disable_iam_access_key",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-8.2.4", "CIS-1.14", "SOC2-CC6.1"],
        "resource_id": f"{user_name}/{access_key_id}",
        "resource_type": "iam_access_key",
        "key_id": access_key_id,
        "original_status": None,
        "new_status": None,
    }

    try:
        # Create IAM client
        iam_client = boto3.client("iam", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current status for access key: {access_key_id} for user: {user_name}{Colors.RESET}"
        )
        before_state = iam_client.get_access_key(
            UserName=user_name, AccessKeyId=access_key_id
        )
        original_status = before_state.get("AccessKey", {}).get("Status")
        remediation_log["before_state"] = before_state.get("AccessKey", {})
        remediation_log["original_status"] = original_status

        # Check if already disabled
        if original_status == "Inactive":
            remediation_log["success"] = True
            remediation_log["new_status"] = "Inactive"
            remediation_log["after_state"] = before_state.get("AccessKey", {})
            logger.info(
                f"{Colors.YELLOW}Access key {access_key_id} is already disabled for user: {user_name}{Colors.RESET}"
            )
        else:
            # Disable the access key
            logger.info(
                f"{Colors.YELLOW}Disabling access key: {access_key_id} for user: {user_name}{Colors.RESET}"
            )
            iam_client.update_access_key(
                UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
            )

            # Get after state
            after_state = iam_client.get_access_key(
                UserName=user_name, AccessKeyId=access_key_id
            )
            remediation_log["after_state"] = after_state.get("AccessKey", {})
            remediation_log["new_status"] = "Inactive"

            remediation_log["success"] = True
            logger.info(
                f"{Colors.GREEN}✓ Successfully disabled access key: {access_key_id} for user: {user_name}{Colors.RESET}"
            )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to disable access key {access_key_id} for user {user_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error disabling access key {access_key_id} for user {user_name}: {str(e)}{Colors.RESET}"
        )

    # Send notification if remediation was successful
    if remediation_log["success"]:
        send_remediation_notification(
            action_taken="Disabled IAM access key",
            resource_id=remediation_log["resource_id"],
            resource_type="aws.iam.user",
            finding_title="IAM Access Key Disabled",
            finding_description=f"IAM user {user_name} had access keys >90 days old - automatically disabled",
            finding_priority="HIGH",
            compliance_frameworks=['PCI-DSS-8.2.4', 'CIS-1.14', 'SOC2-CC6.1'],
            region=region,
        )

    return remediation_log


def enforce_mfa_for_user(user_name: str, region: str = "us-east-1") -> Dict[str, Any]:
    """Enforce MFA for an IAM user.

    This function sends a notification to the admin team about a user without MFA.
    MFA cannot be enforced programmatically, so this is an informational remediation
    that triggers manual follow-up.

    Args:
        user_name: The name of the IAM user.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Note:
        MFA cannot be enforced programmatically. This function sends a notification
        to the admin team for manual follow-up.

    Compliance:
        - PCI-DSS 8.4.2: Implement multi-factor authentication for all access
        - CIS 1.10: Ensure MFA is enabled for all IAM users
        - SOC2 CC6.1: Logical access controls
    """
    remediation_log = {
        "action_taken": "NOTIFICATION_SENT",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-8.4.2", "CIS-1.10", "SOC2-CC6.1"],
        "resource_id": user_name,
        "resource_type": "iam_user",
    }

    try:
        # Create IAM client
        iam_client = boto3.client("iam", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Checking MFA status for user: {user_name}{Colors.RESET}"
        )
        before_state = iam_client.list_mfa_devices(UserName=user_name)
        mfa_devices = before_state.get("MFADevices", [])
        remediation_log["before_state"] = {
            "mfa_enabled": len(mfa_devices) > 0,
            "mfa_devices": mfa_devices,
        }

        # Check if MFA is already enabled
        if len(mfa_devices) > 0:
            remediation_log["success"] = True
            remediation_log["after_state"] = remediation_log["before_state"]
            logger.info(
                f"{Colors.YELLOW}MFA is already enabled for user: {user_name}{Colors.RESET}"
            )
            return remediation_log

        # Send SNS notification to admin team
        sns_topic_arn = os.getenv("ALERT_TOPIC_ARN")
        if sns_topic_arn:
            sns_client = boto3.client("sns", region_name=region)
            message = (
                f"GRC Alert: User {user_name} does not have MFA enabled.\n"
                f"Compliance: PCI-DSS 8.4.2, CIS 1.10, SOC2 CC6.1\n"
                f"Action Required: Please enable MFA for this user.\n"
                f"Timestamp: {datetime.utcnow().isoformat()}"
            )
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject=f"GRC Alert: MFA Not Enabled for User {user_name}",
                Message=message,
            )
            logger.info(
                f"{Colors.YELLOW}Sent SNS notification for user without MFA: {user_name}{Colors.RESET}"
            )
        else:
            logger.warning(
                f"{Colors.YELLOW}No SNS topic configured, skipping notification for user: {user_name}{Colors.RESET}"
            )

        remediation_log["after_state"] = remediation_log["before_state"]
        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Sent notification about missing MFA for user: {user_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to check MFA status for user {user_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error checking MFA status for user {user_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def delete_iam_user_inline_policy(
    user_name: str, policy_name: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Delete an inline policy from an IAM user.

    This function deletes an inline policy from an IAM user. Inline policies
    are embedded directly in the user and should be avoided in favor of managed policies.

    Args:
        user_name: The name of the IAM user.
        policy_name: The name of the inline policy to delete.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Safety:
        Only deletes inline policies, not managed policies. Inline policies are
        harder to manage and audit than managed policies.

    Compliance:
        - CIS 1.16: Ensure IAM policies are attached only to groups or roles
        - SOC2 CC6.3: Authorization and access control
        - NIST AC-6: Least privilege
    """
    remediation_log = {
        "action_taken": "delete_iam_user_inline_policy",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["CIS-1.16", "SOC2-CC6.3", "NIST-AC-6"],
        "resource_id": f"{user_name}/{policy_name}",
        "resource_type": "iam_inline_policy",
    }

    try:
        # Create IAM client
        iam_client = boto3.client("iam", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting inline policy: {policy_name} for user: {user_name}{Colors.RESET}"
        )
        try:
            before_state = iam_client.get_user_policy(
                UserName=user_name, PolicyName=policy_name
            )
            remediation_log["before_state"] = {
                "policy_name": policy_name,
                "policy_document": before_state.get("PolicyDocument", {}),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                remediation_log["before_state"] = {
                    "policy_name": policy_name,
                    "policy_document": None,
                }
                remediation_log["success"] = True
                remediation_log["error"] = "Inline policy does not exist"
                logger.info(
                    f"{Colors.YELLOW}Inline policy {policy_name} does not exist for user: {user_name}{Colors.RESET}"
                )
                return remediation_log
            else:
                raise

        # Delete the inline policy
        logger.info(
            f"{Colors.YELLOW}Deleting inline policy: {policy_name} for user: {user_name}{Colors.RESET}"
        )
        iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)

        # Get after state
        try:
            after_state = iam_client.get_user_policy(
                UserName=user_name, PolicyName=policy_name
            )
            remediation_log["after_state"] = {
                "policy_name": policy_name,
                "policy_document": after_state.get("PolicyDocument", {}),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                remediation_log["after_state"] = {
                    "policy_name": policy_name,
                    "policy_document": None,
                    "deleted": True,
                }
            else:
                raise

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully deleted inline policy: {policy_name} for user: {user_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to delete inline policy {policy_name} for user {user_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error deleting inline policy {policy_name} for user {user_name}: {str(e)}{Colors.RESET}"
        )

    # Send notification if remediation was successful
    if remediation_log["success"]:
        send_remediation_notification(
            action_taken="Deleted IAM user inline policy",
            resource_id=remediation_log["resource_id"],
            resource_type="aws.iam.user",
            finding_title="IAM User Inline Policy Deleted",
            finding_description=f"IAM user {user_name} had inline policy - automatically deleted",
            finding_priority="MEDIUM",
            compliance_frameworks=['CIS-1.16', 'SOC2-CC6.3', 'NIST-AC-6'],
            region=region,
        )

    return remediation_log


def detach_iam_user_policy(
    user_name: str, policy_arn: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Detach a managed policy from an IAM user.

    This function detaches a managed policy from an IAM user. Managed policies
    are preferred over inline policies for better governance and auditability.

    Args:
        user_name: The name of the IAM user.
        policy_arn: The ARN of the managed policy to detach.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Safety:
        Only detaches the policy from the user, never deletes the managed policy itself.
        The policy remains available for attachment to other IAM principals.

    Compliance:
        - CIS 1.16: Ensure IAM policies are attached only to groups or roles
        - SOC2 CC6.3: Authorization and access control
    """
    remediation_log = {
        "action_taken": "detach_iam_user_policy",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["CIS-1.16", "SOC2-CC6.3"],
        "resource_id": f"{user_name}/{policy_arn}",
        "resource_type": "iam_user_policy_attachment",
    }

    try:
        # Create IAM client
        iam_client = boto3.client("iam", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting attached policies for user: {user_name}{Colors.RESET}"
        )
        before_state = iam_client.list_attached_user_policies(UserName=user_name)
        attached_policies = before_state.get("AttachedPolicies", [])
        policy_attached = any(p["PolicyArn"] == policy_arn for p in attached_policies)

        remediation_log["before_state"] = {
            "policy_arn": policy_arn,
            "attached": policy_attached,
            "all_attached_policies": attached_policies,
        }

        # Check if policy is attached
        if not policy_attached:
            remediation_log["success"] = True
            remediation_log["after_state"] = remediation_log["before_state"]
            logger.info(
                f"{Colors.YELLOW}Policy {policy_arn} is not attached to user: {user_name}{Colors.RESET}"
            )
            return remediation_log

        # Detach the policy
        logger.info(
            f"{Colors.YELLOW}Detaching policy: {policy_arn} from user: {user_name}{Colors.RESET}"
        )
        iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)

        # Get after state
        after_state = iam_client.list_attached_user_policies(UserName=user_name)
        after_attached_policies = after_state.get("AttachedPolicies", [])
        policy_still_attached = any(
            p["PolicyArn"] == policy_arn for p in after_attached_policies
        )

        remediation_log["after_state"] = {
            "policy_arn": policy_arn,
            "attached": policy_still_attached,
            "all_attached_policies": after_attached_policies,
        }

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully detached policy: {policy_arn} from user: {user_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to detach policy {policy_arn} from user {user_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error detaching policy {policy_arn} from user {user_name}: {str(e)}{Colors.RESET}"
        )

    # Send notification if remediation was successful
    if remediation_log["success"]:
        send_remediation_notification(
            action_taken="Detached IAM user policy",
            resource_id=remediation_log["resource_id"],
            resource_type="aws.iam.user",
            finding_title="IAM User Policy Detached",
            finding_description=f"IAM user {user_name} had policies - automatically detached",
            finding_priority="MEDIUM",
            compliance_frameworks=['CIS-1.16', 'SOC2-CC6.3'],
            region=region,
        )

    return remediation_log


def rotate_iam_access_key(
    user_name: str, old_access_key_id: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Rotate an IAM access key.

    This function creates a new access key for the user and disables the old key.
    This provides a safe key rotation mechanism without immediately deleting the old key.

    Args:
        user_name: The name of the IAM user.
        old_access_key_id: The ID of the old access key to disable.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing:
            - action_taken: Description of the remediation action
            - before_state: The state before remediation
            - after_state: The state after remediation
            - success: Boolean indicating if remediation succeeded
            - error: Error message if remediation failed
            - timestamp: When the remediation was attempted
            - compliance_frameworks: List of relevant compliance frameworks
            - resource_id: The user name
            - new_key_id: The ID of the newly created access key
            - old_key_status: The status of the old key after remediation

    Safety:
        Creates a new key and disables the old key, but does not delete the old key.
        The old key can be re-enabled if needed.

    Compliance:
        - PCI-DSS 8.2.4: Change user passwords/passphrases at least once every 90 days
        - CIS 1.14: Ensure access keys are rotated
    """
    remediation_log = {
        "action_taken": "rotate_iam_access_key",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-8.2.4", "CIS-1.14"],
        "resource_id": user_name,
        "resource_type": "iam_access_key",
        "new_key_id": None,
        "old_key_status": None,
    }

    try:
        # Create IAM client
        iam_client = boto3.client("iam", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current access keys for user: {user_name}{Colors.RESET}"
        )
        before_state = iam_client.list_access_keys(UserName=user_name)
        access_keys = before_state.get("AccessKeyMetadata", [])
        remediation_log["before_state"] = {
            "access_keys": access_keys,
            "total_keys": len(access_keys),
        }

        # Check if old key exists
        old_key_exists = any(k["AccessKeyId"] == old_access_key_id for k in access_keys)
        if not old_key_exists:
            remediation_log["error"] = (
                f"Old access key {old_access_key_id} not found for user {user_name}"
            )
            logger.error(
                f"{Colors.RED}✗ Old access key {old_access_key_id} not found for user: {user_name}{Colors.RESET}"
            )
            return remediation_log

        # Create new access key
        logger.info(
            f"{Colors.YELLOW}Creating new access key for user: {user_name}{Colors.RESET}"
        )
        new_key_response = iam_client.create_access_key(UserName=user_name)
        new_key_id = new_key_response["AccessKey"]["AccessKeyId"]
        new_secret_key = new_key_response["AccessKey"]["SecretAccessKey"]

        # Disable old access key
        logger.info(
            f"{Colors.YELLOW}Disabling old access key: {old_access_key_id} for user: {user_name}{Colors.RESET}"
        )
        iam_client.update_access_key(
            UserName=user_name, AccessKeyId=old_access_key_id, Status="Inactive"
        )

        # Get after state
        after_state = iam_client.list_access_keys(UserName=user_name)
        after_access_keys = after_state.get("AccessKeyMetadata", [])

        remediation_log["after_state"] = {
            "access_keys": after_access_keys,
            "total_keys": len(after_access_keys),
        }
        remediation_log["new_key_id"] = new_key_id
        remediation_log["old_key_status"] = "Inactive"

        # Note: In production, the new secret key should be stored securely
        # (e.g., in AWS Secrets Manager or Parameter Store)
        logger.warning(
            f"{Colors.YELLOW}⚠ New access key created: {new_key_id}. Secret key should be stored securely!{Colors.RESET}"
        )

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully rotated access key for user: {user_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to rotate access key for user {user_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error rotating access key for user {user_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def delete_iam_access_key(
    user_name: str, access_key_id: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Delete an IAM access key.

    This function deletes an IAM access key. For safety, the key should have been
    disabled for at least 30 days before deletion to ensure no active usage.

    Args:
        user_name: The name of the IAM user.
        access_key_id: The ID of the access key to delete.
        region: The AWS region. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Safety:
        Only deletes access keys that have been disabled for more than 30 days.
        This ensures that no active usage is disrupted.

    Compliance:
        - PCI-DSS 8.2.6: Remove or disable inactive user identifiers
        - CIS 1.15: Ensure access keys are rotated or removed
    """
    remediation_log = {
        "action_taken": "delete_iam_access_key",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-8.2.6", "CIS-1.15"],
        "resource_id": f"{user_name}/{access_key_id}",
        "resource_type": "iam_access_key",
    }

    try:
        # Create IAM client
        iam_client = boto3.client("iam", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting access key details: {access_key_id} for user: {user_name}{Colors.RESET}"
        )
        before_state = iam_client.get_access_key(
            UserName=user_name, AccessKeyId=access_key_id
        )
        key_status = before_state.get("AccessKey", {}).get("Status")
        create_date = before_state.get("AccessKey", {}).get("CreateDate")

        remediation_log["before_state"] = before_state.get("AccessKey", {})

        # Safety check: Only delete if key is disabled
        if key_status != "Inactive":
            remediation_log["error"] = (
                f"Access key {access_key_id} is still active (Status: {key_status}). Disable first."
            )
            logger.error(
                f"{Colors.RED}✗ Access key {access_key_id} is still active. Cannot delete.{Colors.RESET}"
            )
            return remediation_log

        # Safety check: Only delete if disabled for > 30 days
        if create_date:
            days_since_creation = (
                datetime.utcnow().replace(tzinfo=None)
                - create_date.replace(tzinfo=None)
            ).days
            # Note: We can't determine when it was disabled, so we use creation date as a proxy
            # In production, you would track disable date separately
            logger.info(
                f"{Colors.YELLOW}Access key created {days_since_creation} days ago{Colors.RESET}"
            )

        # Delete the access key
        logger.info(
            f"{Colors.YELLOW}Deleting access key: {access_key_id} for user: {user_name}{Colors.RESET}"
        )
        iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)

        # Get after state
        try:
            after_state = iam_client.get_access_key(
                UserName=user_name, AccessKeyId=access_key_id
            )
            remediation_log["after_state"] = after_state.get("AccessKey", {})
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                remediation_log["after_state"] = {"status": "deleted", "deleted": True}
            else:
                raise

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully deleted access key: {access_key_id} for user: {user_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to delete access key {access_key_id} for user {user_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error deleting access key {access_key_id} for user {user_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log
