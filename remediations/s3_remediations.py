"""
S3 remediation functions for common compliance violations.

This module provides auto-remediation functions for S3 bucket compliance issues
including public access, encryption, versioning, logging, and ACL/policy violations.
"""

import boto3
import logging
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional
from datetime import datetime
import os

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


def block_s3_public_access(
    bucket_name: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Block public access to an S3 bucket.

    This function enables all four public access block flags on an S3 bucket
    to prevent public access at the bucket and account level.

    Args:
        bucket_name: The name of the S3 bucket to remediate.
        region: The AWS region where the bucket is located. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing:
            - action_taken: Description of the remediation action
            - before_state: The state before remediation
            - after_state: The state after remediation
            - success: Boolean indicating if remediation succeeded
            - error: Error message if remediation failed
            - timestamp: When the remediation was attempted
            - compliance_frameworks: List of relevant compliance frameworks
            - resource_id: The bucket name

    Compliance:
        - PCI-DSS 1.3: Restrict public access to cardholder data
        - SOC2 CC6.6: Logical and physical access controls
        - CIS 2.1.5: S3 bucket public access prohibited
    """
    remediation_log = {
        "action_taken": "block_s3_public_access",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6", "CIS-2.1.5"],
        "resource_id": bucket_name,
        "resource_type": "s3_bucket",
    }

    try:
        # Create S3 client
        s3_client = boto3.client("s3", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current public access block configuration for bucket: {bucket_name}{Colors.RESET}"
        )
        try:
            before_state = s3_client.get_public_access_block(Bucket=bucket_name)
            remediation_log["before_state"] = before_state.get(
                "PublicAccessBlockConfiguration", {}
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                remediation_log["before_state"] = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            else:
                raise

        # Apply public access block
        logger.info(
            f"{Colors.YELLOW}Applying public access block to bucket: {bucket_name}{Colors.RESET}"
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Get after state
        after_state = s3_client.get_public_access_block(Bucket=bucket_name)
        remediation_log["after_state"] = after_state.get(
            "PublicAccessBlockConfiguration", {}
        )

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully blocked public access for bucket: {bucket_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to block public access for bucket {bucket_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error blocking public access for bucket {bucket_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def enable_s3_encryption(
    bucket_name: str,
    encryption_type: str = "AES256",
    kms_key_id: Optional[str] = None,
    region: str = "us-east-1",
) -> Dict[str, Any]:
    """Enable server-side encryption for an S3 bucket.

    This function enables default server-side encryption for objects in an S3 bucket.
    Supports both AES256 (SSE-S3) and KMS (SSE-KMS) encryption methods.

    Args:
        bucket_name: The name of the S3 bucket to remediate.
        encryption_type: Type of encryption to use. Either "AES256" or "KMS". Defaults to "AES256".
        kms_key_id: The KMS key ID to use when encryption_type is "KMS". Optional.
        region: The AWS region where the bucket is located. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Compliance:
        - PCI-DSS 3.4: Render cardholder data unreadable anywhere it is stored
        - SOC2 CC6.7: Encryption of data at rest
    """
    remediation_log = {
        "action_taken": "enable_s3_encryption",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-3.4", "SOC2-CC6.7"],
        "resource_id": bucket_name,
        "resource_type": "s3_bucket",
    }

    try:
        # Create S3 client
        s3_client = boto3.client("s3", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current encryption configuration for bucket: {bucket_name}{Colors.RESET}"
        )
        try:
            before_state = s3_client.get_bucket_encryption(Bucket=bucket_name)
            remediation_log["before_state"] = before_state.get(
                "ServerSideEncryptionConfiguration", {}
            )
        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "ServerSideEncryptionConfigurationNotFoundError"
            ):
                remediation_log["before_state"] = {"status": "not_configured"}
            else:
                raise

        # Configure encryption
        logger.info(
            f"{Colors.YELLOW}Enabling {encryption_type} encryption for bucket: {bucket_name}{Colors.RESET}"
        )

        if encryption_type == "AES256":
            encryption_config = {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            }
        elif encryption_type == "KMS":
            if not kms_key_id:
                raise ValueError("kms_key_id is required when encryption_type is 'KMS'")
            encryption_config = {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_key_id,
                        }
                    }
                ]
            }
        else:
            raise ValueError(
                f"Invalid encryption_type: {encryption_type}. Must be 'AES256' or 'KMS'"
            )

        s3_client.put_bucket_encryption(
            Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_config
        )

        # Get after state
        after_state = s3_client.get_bucket_encryption(Bucket=bucket_name)
        remediation_log["after_state"] = after_state.get(
            "ServerSideEncryptionConfiguration", {}
        )

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully enabled {encryption_type} encryption for bucket: {bucket_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to enable encryption for bucket {bucket_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error enabling encryption for bucket {bucket_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def enable_s3_versioning(bucket_name: str, region: str = "us-east-1") -> Dict[str, Any]:
    """Enable versioning for an S3 bucket.

    This function enables versioning on an S3 bucket to maintain multiple versions
    of an object and provide protection against accidental deletion or overwrites.

    Args:
        bucket_name: The name of the S3 bucket to remediate.
        region: The AWS region where the bucket is located. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Compliance:
        - SOC2 A1.3: Availability of data through versioning
        - PCI-DSS 12.3.4: Maintain security policies and procedures
    """
    remediation_log = {
        "action_taken": "enable_s3_versioning",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["SOC2-A1.3", "PCI-DSS-12.3.4"],
        "resource_id": bucket_name,
        "resource_type": "s3_bucket",
    }

    try:
        # Create S3 client
        s3_client = boto3.client("s3", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current versioning configuration for bucket: {bucket_name}{Colors.RESET}"
        )
        before_state = s3_client.get_bucket_versioning(Bucket=bucket_name)
        remediation_log["before_state"] = before_state

        # Enable versioning
        logger.info(
            f"{Colors.YELLOW}Enabling versioning for bucket: {bucket_name}{Colors.RESET}"
        )
        s3_client.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )

        # Get after state
        after_state = s3_client.get_bucket_versioning(Bucket=bucket_name)
        remediation_log["after_state"] = after_state

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully enabled versioning for bucket: {bucket_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to enable versioning for bucket {bucket_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error enabling versioning for bucket {bucket_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def enable_s3_logging(
    bucket_name: str,
    target_bucket: str,
    target_prefix: str = "logs/",
    region: str = "us-east-1",
) -> Dict[str, Any]:
    """Enable server access logging for an S3 bucket.

    This function enables server access logging for an S3 bucket, logging all
    requests made to the bucket to a target bucket.

    Args:
        bucket_name: The name of the S3 bucket to enable logging for.
        target_bucket: The name of the bucket to store logs in.
        target_prefix: The prefix for log objects in the target bucket. Defaults to "logs/".
        region: The AWS region where the bucket is located. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Compliance:
        - PCI-DSS 10.2: Implement audit trails for all system components
        - SOC2 CC6.8: Logging and monitoring
    """
    remediation_log = {
        "action_taken": "enable_s3_logging",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-10.2", "SOC2-CC6.8"],
        "resource_id": bucket_name,
        "resource_type": "s3_bucket",
    }

    try:
        # Create S3 client
        s3_client = boto3.client("s3", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current logging configuration for bucket: {bucket_name}{Colors.RESET}"
        )
        try:
            before_state = s3_client.get_bucket_logging(Bucket=bucket_name)
            remediation_log["before_state"] = before_state.get("LoggingEnabled", {})
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchLoggingConfiguration":
                remediation_log["before_state"] = {"status": "not_configured"}
            else:
                raise

        # Enable logging
        logger.info(
            f"{Colors.YELLOW}Enabling logging for bucket: {bucket_name} -> {target_bucket}/{target_prefix}{Colors.RESET}"
        )
        logging_config = {"TargetBucket": target_bucket, "TargetPrefix": target_prefix}
        s3_client.put_bucket_logging(
            Bucket=bucket_name, BucketLoggingStatus={"LoggingEnabled": logging_config}
        )

        # Get after state
        after_state = s3_client.get_bucket_logging(Bucket=bucket_name)
        remediation_log["after_state"] = after_state.get("LoggingEnabled", {})

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully enabled logging for bucket: {bucket_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to enable logging for bucket {bucket_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error enabling logging for bucket {bucket_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def remove_s3_public_acl(bucket_name: str, region: str = "us-east-1") -> Dict[str, Any]:
    """Remove public ACL from an S3 bucket.

    This function removes public access control lists from an S3 bucket
    by setting the bucket ACL to private.

    Args:
        bucket_name: The name of the S3 bucket to remediate.
        region: The AWS region where the bucket is located. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Compliance:
        - PCI-DSS 1.3: Restrict public access to cardholder data
        - SOC2 CC6.6: Logical and physical access controls
    """
    remediation_log = {
        "action_taken": "remove_s3_public_acl",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6"],
        "resource_id": bucket_name,
        "resource_type": "s3_bucket",
    }

    try:
        # Create S3 client
        s3_client = boto3.client("s3", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current ACL configuration for bucket: {bucket_name}{Colors.RESET}"
        )
        before_state = s3_client.get_bucket_acl(Bucket=bucket_name)
        remediation_log["before_state"] = {
            "grants": before_state.get("Grants", []),
            "owner": before_state.get("Owner", {}),
        }

        # Remove public ACL by setting to private
        logger.info(
            f"{Colors.YELLOW}Setting bucket ACL to private for bucket: {bucket_name}{Colors.RESET}"
        )
        s3_client.put_bucket_acl(Bucket=bucket_name, ACL="private")

        # Get after state
        after_state = s3_client.get_bucket_acl(Bucket=bucket_name)
        remediation_log["after_state"] = {
            "grants": after_state.get("Grants", []),
            "owner": after_state.get("Owner", {}),
        }

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully removed public ACL for bucket: {bucket_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to remove public ACL for bucket {bucket_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error removing public ACL for bucket {bucket_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log


def delete_s3_public_policy(
    bucket_name: str, region: str = "us-east-1"
) -> Dict[str, Any]:
    """Delete public policy from an S3 bucket.

    This function deletes the bucket policy from an S3 bucket to remove
    any public access granted through policy statements.

    Args:
        bucket_name: The name of the S3 bucket to remediate.
        region: The AWS region where the bucket is located. Defaults to "us-east-1".

    Returns:
        A remediation_log dict containing the remediation details.

    Compliance:
        - PCI-DSS 1.3: Restrict public access to cardholder data
        - SOC2 CC6.6: Logical and physical access controls
    """
    remediation_log = {
        "action_taken": "delete_s3_public_policy",
        "before_state": {},
        "after_state": {},
        "success": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6"],
        "resource_id": bucket_name,
        "resource_type": "s3_bucket",
    }

    try:
        # Create S3 client
        s3_client = boto3.client("s3", region_name=region)

        # Get before state
        logger.info(
            f"{Colors.CYAN}Getting current bucket policy for bucket: {bucket_name}{Colors.RESET}"
        )
        try:
            before_state = s3_client.get_bucket_policy(Bucket=bucket_name)
            remediation_log["before_state"] = {
                "policy_exists": True,
                "policy": before_state.get("Policy", ""),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                remediation_log["before_state"] = {
                    "policy_exists": False,
                    "policy": None,
                }
                remediation_log["success"] = True
                remediation_log["error"] = "No bucket policy exists to delete"
                logger.info(
                    f"{Colors.YELLOW}No bucket policy exists for bucket: {bucket_name}{Colors.RESET}"
                )
                return remediation_log
            else:
                raise

        # Delete bucket policy
        logger.info(
            f"{Colors.YELLOW}Deleting bucket policy for bucket: {bucket_name}{Colors.RESET}"
        )
        s3_client.delete_bucket_policy(Bucket=bucket_name)

        # Get after state
        try:
            after_state = s3_client.get_bucket_policy(Bucket=bucket_name)
            remediation_log["after_state"] = {
                "policy_exists": True,
                "policy": after_state.get("Policy", ""),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                remediation_log["after_state"] = {
                    "policy_exists": False,
                    "policy": None,
                }
            else:
                raise

        remediation_log["success"] = True
        logger.info(
            f"{Colors.GREEN}✓ Successfully deleted bucket policy for bucket: {bucket_name}{Colors.RESET}"
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        remediation_log["error"] = f"{error_code}: {error_message}"
        logger.error(
            f"{Colors.RED}✗ Failed to delete bucket policy for bucket {bucket_name}: {error_code} - {error_message}{Colors.RESET}"
        )
    except Exception as e:
        remediation_log["error"] = str(e)
        logger.error(
            f"{Colors.RED}✗ Unexpected error deleting bucket policy for bucket {bucket_name}: {str(e)}{Colors.RESET}"
        )

    return remediation_log
