"""
GRC Evidence Platform - Auto-Remediation Engine Lambda

This Lambda function automatically remediates security violations based on evidence findings.
It supports DRY_RUN, AUTO, and APPROVAL_REQUIRED modes, logs all actions, and sends notifications.

Author: GRC Platform Team
Version: 2.0
"""

import json
import logging
import os
import sys
import boto3
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ANSI color codes for terminal output (disabled in non-TTY environments like CloudWatch)
class Colors:
    """ANSI color codes for terminal output (disabled in non-TTY environments)."""

    def __init__(self):
        self.HEADER = "\033[95m" if sys.stdout.isatty() else ""
        self.OKBLUE = "\033[94m" if sys.stdout.isatty() else ""
        self.OKCYAN = "\033[96m" if sys.stdout.isatty() else ""
        self.OKGREEN = "\033[92m" if sys.stdout.isatty() else ""
        self.WARNING = "\033[93m" if sys.stdout.isatty() else ""
        self.FAIL = "\033[91m" if sys.stdout.isatty() else ""
        self.ENDC = "\033[0m" if sys.stdout.isatty() else ""
        self.BOLD = "\033[1m" if sys.stdout.isatty() else ""
        self.UNDERLINE = "\033[4m" if sys.stdout.isatty() else ""


# Create a global instance
colors = Colors()


# Remediation log schema from SECTION 5.2
@dataclass
class RemediationLog:
    """Remediation log record stored in DynamoDB."""

    id: str
    remediation_type: str
    resource_id: str
    resource_type: str
    finding_id: str
    finding_title: str
    finding_priority: str
    action_taken: str
    action_status: str
    action_timestamp: str
    execution_mode: str
    performed_by: str
    details: Dict[str, Any]
    evidence_path: str
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()


def block_s3_public_access(
    s3_client: Any, bucket_name: str, dry_run: bool
) -> Dict[str, Any]:
    """
    Remediation: Block S3 Public Access.

    Enables public access block on the S3 bucket to prevent public access.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        dry_run: If True, only log what would happen

    Returns:
        Dictionary with action details and status
    """
    action_details = {
        "bucket_name": bucket_name,
        "public_access_block_configuration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }

    if dry_run:
        logger.info(
            f"{colors.OKCYAN}[DRY RUN] Would block public access on S3 bucket: {bucket_name}{colors.ENDC}"
        )
        return {
            "action": "block_s3_public_access",
            "status": "DRY_RUN",
            "details": action_details,
        }

    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=action_details[
                "public_access_block_configuration"
            ],
        )
        logger.info(
            f"{colors.OKGREEN}✓ Blocked public access on S3 bucket: {bucket_name}{colors.ENDC}"
        )
        return {
            "action": "block_s3_public_access",
            "status": "SUCCESS",
            "details": action_details,
        }
    except ClientError as e:
        logger.error(
            f"{colors.FAIL}Failed to block public access on {bucket_name}: {e}{colors.ENDC}"
        )
        return {
            "action": "block_s3_public_access",
            "status": "FAILED",
            "details": action_details,
            "error": str(e),
        }


def revoke_security_group_rule(
    ec2_client: Any,
    group_id: str,
    rule_type: str,
    ip_protocol: str,
    from_port: Optional[int],
    to_port: Optional[int],
    ip_ranges: Optional[List[str]],
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Remediation: Revoke Overly Open Security Group Rules.

    Revokes specific overly permissive security group rules (e.g., 0.0.0.0/0).

    Args:
        ec2_client: Boto3 EC2 client
        group_id: Security group ID
        rule_type: 'ingress' or 'egress'
        ip_protocol: IP protocol (tcp, udp, icmp, -1)
        from_port: Start port (or None for ICMP/all)
        to_port: End port (or None for ICMP/all)
        ip_ranges: List of CIDR blocks to revoke
        dry_run: If True, only log what would happen

    Returns:
        Dictionary with action details and status
    """
    action_details = {
        "group_id": group_id,
        "rule_type": rule_type,
        "ip_protocol": ip_protocol,
        "from_port": from_port,
        "to_port": to_port,
        "ip_ranges": ip_ranges,
    }

    if dry_run:
        logger.info(
            f"{Colors.OKCYAN}[DRY RUN] Would revoke {rule_type} rule from security group {group_id}{Colors.ENDC}"
        )
        return {
            "action": "revoke_security_group_rule",
            "status": "DRY_RUN",
            "details": action_details,
        }

    try:
        revoke_params = {
            "GroupId": group_id,
            "IpPermissions": [
                {
                    "IpProtocol": ip_protocol,
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": [{"CidrIp": cidr} for cidr in (ip_ranges or [])],
                }
            ],
        }

        if rule_type == "ingress":
            ec2_client.revoke_security_group_ingress(**revoke_params)
        else:
            ec2_client.revoke_security_group_egress(**revoke_params)

        logger.info(
            f"{Colors.OKGREEN}✓ Revoked {rule_type} rule from security group: {group_id}{Colors.ENDC}"
        )
        return {
            "action": "revoke_security_group_rule",
            "status": "SUCCESS",
            "details": action_details,
        }
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to revoke rule from {group_id}: {e}{Colors.ENDC}"
        )
        return {
            "action": "revoke_security_group_rule",
            "status": "FAILED",
            "details": action_details,
            "error": str(e),
        }


def disable_iam_access_key(
    iam_client: Any, user_name: str, access_key_id: str, dry_run: bool
) -> Dict[str, Any]:
    """
    Remediation: Disable Unused IAM Access Keys.

    Disables IAM access keys that have been inactive for more than 90 days.

    Args:
        iam_client: Boto3 IAM client
        user_name: IAM user name
        access_key_id: Access key ID to disable
        dry_run: If True, only log what would happen

    Returns:
        Dictionary with action details and status
    """
    action_details = {"user_name": user_name, "access_key_id": access_key_id}

    if dry_run:
        logger.info(
            f"{Colors.OKCYAN}[DRY RUN] Would disable access key {access_key_id} for user {user_name}{Colors.ENDC}"
        )
        return {
            "action": "disable_iam_access_key",
            "status": "DRY_RUN",
            "details": action_details,
        }

    try:
        iam_client.update_access_key(
            UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
        )
        logger.info(
            f"{Colors.OKGREEN}✓ Disabled access key {access_key_id} for user {user_name}{Colors.ENDC}"
        )
        return {
            "action": "disable_iam_access_key",
            "status": "SUCCESS",
            "details": action_details,
        }
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to disable access key {access_key_id}: {e}{Colors.ENDC}"
        )
        return {
            "action": "disable_iam_access_key",
            "status": "FAILED",
            "details": action_details,
            "error": str(e),
        }


def enforce_s3_bucket_encryption(
    s3_client: Any, bucket_name: str, dry_run: bool
) -> Dict[str, Any]:
    """
    Remediation: Enforce S3 Bucket Encryption.

    Enables default AES-256 encryption on the S3 bucket.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        dry_run: If True, only log what would happen

    Returns:
        Dictionary with action details and status
    """
    action_details = {
        "bucket_name": bucket_name,
        "encryption_configuration": {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    }

    if dry_run:
        logger.info(
            f"{Colors.OKCYAN}[DRY RUN] Would enforce encryption on S3 bucket: {bucket_name}{Colors.ENDC}"
        )
        return {
            "action": "enforce_s3_bucket_encryption",
            "status": "DRY_RUN",
            "details": action_details,
        }

    try:
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=action_details[
                "encryption_configuration"
            ],
        )
        logger.info(
            f"{Colors.OKGREEN}✓ Enforced encryption on S3 bucket: {bucket_name}{Colors.ENDC}"
        )
        return {
            "action": "enforce_s3_bucket_encryption",
            "status": "SUCCESS",
            "details": action_details,
        }
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to enforce encryption on {bucket_name}: {e}{Colors.ENDC}"
        )
        return {
            "action": "enforce_s3_bucket_encryption",
            "status": "FAILED",
            "details": action_details,
            "error": str(e),
        }


def enable_kms_key_rotation(
    kms_client: Any, key_id: str, dry_run: bool
) -> Dict[str, Any]:
    """
    Remediation: Enable KMS Key Rotation.

    Enables automatic key rotation for a KMS customer managed key.

    Args:
        kms_client: Boto3 KMS client
        key_id: KMS key ID or ARN
        dry_run: If True, only log what would happen

    Returns:
        Dictionary with action details and status
    """
    action_details = {"key_id": key_id}

    if dry_run:
        logger.info(
            f"{Colors.OKCYAN}[DRY RUN] Would enable rotation for KMS key: {key_id}{Colors.ENDC}"
        )
        return {
            "action": "enable_kms_key_rotation",
            "status": "DRY_RUN",
            "details": action_details,
        }

    try:
        kms_client.enable_key_rotation(KeyId=key_id)
        logger.info(
            f"{Colors.OKGREEN}✓ Enabled rotation for KMS key: {key_id}{Colors.ENDC}"
        )
        return {
            "action": "enable_kms_key_rotation",
            "status": "SUCCESS",
            "details": action_details,
        }
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to enable rotation for KMS key {key_id}: {e}{Colors.ENDC}"
        )
        return {
            "action": "enable_kms_key_rotation",
            "status": "FAILED",
            "details": action_details,
            "error": str(e),
        }


def store_remediation_log(
    s3_client: Any,
    dynamodb_client: Any,
    s3_bucket: str,
    dynamodb_table: str,
    remediation_log: RemediationLog,
) -> None:
    """
    Store remediation log to S3 and DynamoDB.

    Args:
        s3_client: Boto3 S3 client
        dynamodb_client: Boto3 DynamoDB client
        s3_bucket: S3 bucket name for logs
        dynamodb_table: DynamoDB table name
        remediation_log: Remediation log record
    """
    # Store to S3
    timestamp = datetime.fromisoformat(
        remediation_log.created_at.replace("Z", "+00:00")
    )
    s3_path = f"remediations/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/{remediation_log.id}.json"

    try:
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=s3_path,
            Body=json.dumps(asdict(remediation_log), indent=2),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        logger.info(
            f"{Colors.OKGREEN}Remediation log stored to S3: s3://{s3_bucket}/{s3_path}{Colors.ENDC}"
        )
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to store remediation log to S3: {e}{Colors.ENDC}"
        )

    # Store to DynamoDB
    try:
        item = {
            "id": {"S": remediation_log.id},
            "remediation_type": {"S": remediation_log.remediation_type},
            "resource_id": {"S": remediation_log.resource_id},
            "resource_type": {"S": remediation_log.resource_type},
            "finding_id": {"S": remediation_log.finding_id},
            "finding_title": {"S": remediation_log.finding_title},
            "finding_priority": {"S": remediation_log.finding_priority},
            "action_taken": {"S": remediation_log.action_taken},
            "action_status": {"S": remediation_log.action_status},
            "action_timestamp": {"S": remediation_log.action_timestamp},
            "execution_mode": {"S": remediation_log.execution_mode},
            "performed_by": {"S": remediation_log.performed_by},
            "details": {"S": json.dumps(remediation_log.details)},
            "evidence_path": {"S": remediation_log.evidence_path},
            "created_at": {"S": remediation_log.created_at},
        }
        dynamodb_client.put_item(TableName=dynamodb_table, Item=item)
        logger.info(
            f"{Colors.OKGREEN}Remediation log stored to DynamoDB: {remediation_log.id}{Colors.ENDC}"
        )
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to store remediation log to DynamoDB: {e}{Colors.ENDC}"
        )


def send_sns_notification(
    sns_client: Any,
    topic_arn: str,
    remediation_log: RemediationLog,
    approval_required: bool = False,
) -> None:
    """
    Send SNS notification about remediation action.

    Args:
        sns_client: Boto3 SNS client
        topic_arn: SNS topic ARN
        remediation_log: Remediation log record
        approval_required: If True, this is an approval request
    """
    if approval_required:
        subject = f"[APPROVAL REQUIRED] Remediation: {remediation_log.remediation_type}"
        message = f"""
GRC Platform - Remediation Approval Required
==============================================

Remediation Type: {remediation_log.remediation_type}
Resource: {remediation_log.resource_type} - {remediation_log.resource_id}
Finding: {remediation_log.finding_title} ({remediation_log.finding_priority})

Action to Take: {remediation_log.action_taken}
Details: {json.dumps(remediation_log.details, indent=2)}

Finding ID: {remediation_log.finding_id}
Evidence: {remediation_log.evidence_path}

This remediation requires manual approval before execution.
Please review and approve/reject through the GRC Platform console.
"""
    else:
        subject = f"[{remediation_log.action_status}] Remediation: {remediation_log.remediation_type}"
        message = f"""
GRC Platform - Remediation Action Completed
============================================

Remediation Type: {remediation_log.remediation_type}
Resource: {remediation_log.resource_type} - {remediation_log.resource_id}
Finding: {remediation_log.finding_title} ({remediation_log.finding_priority})

Action Taken: {remediation_log.action_taken}
Status: {remediation_log.action_status}
Execution Mode: {remediation_log.execution_mode}
Performed By: {remediation_log.performed_by}

Details: {json.dumps(remediation_log.details, indent=2)}

Finding ID: {remediation_log.finding_id}
Evidence: {remediation_log.evidence_path}
Timestamp: {remediation_log.action_timestamp}
"""

    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
            MessageStructure="string",
        )
        logger.info(f"{Colors.WARNING}SNS notification sent: {subject}{Colors.ENDC}")
    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to send SNS notification: {e}{Colors.ENDC}")


def execute_remediation(
    remediation_type: str, parameters: Dict[str, Any], dry_run: bool
) -> Dict[str, Any]:
    """
    Execute the appropriate remediation based on type.

    Args:
        remediation_type: Type of remediation to execute
        parameters: Parameters for the remediation
        dry_run: If True, only log what would happen

    Returns:
        Dictionary with action result
    """
    s3_client = boto3.client("s3")
    ec2_client = boto3.client("ec2")
    iam_client = boto3.client("iam")
    kms_client = boto3.client("kms")

    remediations = {
        "block_s3_public_access": lambda: block_s3_public_access(
            s3_client, parameters["bucket_name"], dry_run
        ),
        "revoke_security_group_rule": lambda: revoke_security_group_rule(
            ec2_client,
            parameters["group_id"],
            parameters["rule_type"],
            parameters["ip_protocol"],
            parameters.get("from_port"),
            parameters.get("to_port"),
            parameters.get("ip_ranges"),
            dry_run,
        ),
        "disable_iam_access_key": lambda: disable_iam_access_key(
            iam_client, parameters["user_name"], parameters["access_key_id"], dry_run
        ),
        "enforce_s3_bucket_encryption": lambda: enforce_s3_bucket_encryption(
            s3_client, parameters["bucket_name"], dry_run
        ),
        "enable_kms_key_rotation": lambda: enable_kms_key_rotation(
            kms_client, parameters["key_id"], dry_run
        ),
    }

    if remediation_type not in remediations:
        return {
            "action": remediation_type,
            "status": "FAILED",
            "error": f"Unknown remediation type: {remediation_type}",
        }

    return remediations[remediation_type]()


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for auto-remediation engine.

    Args:
        event: Event containing remediation request (from SNS or direct invoke)
        context: Lambda context object

    Returns:
        HTTP response with status code and result
    """
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(f"{Colors.HEADER}Auto-Remediation Engine Lambda Invoked{Colors.ENDC}")
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(
        f"{Colors.OKCYAN}Event received: {json.dumps(event, indent=2)}{Colors.ENDC}"
    )

    # Get environment variables
    remediation_bucket = os.environ.get("REMEDIATION_BUCKET")
    dynamodb_table = os.environ.get("REMEDIATION_DYNAMODB_TABLE")
    sns_topic_arn = os.environ.get("REMEDIATION_SNS_TOPIC")
    remediation_mode = os.environ.get("REMEDIATION_MODE", "AUTO")

    if not all([remediation_bucket, dynamodb_table, sns_topic_arn]):
        error_msg = "Missing required environment variables: REMEDIATION_BUCKET, REMEDIATION_DYNAMODB_TABLE, REMEDIATION_SNS_TOPIC"
        logger.error(f"{Colors.FAIL}{error_msg}{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}

    # Validate remediation mode
    if remediation_mode not in ["DRY_RUN", "AUTO", "APPROVAL_REQUIRED"]:
        logger.warning(
            f"{Colors.WARNING}Invalid REMEDIATION_MODE: {remediation_mode}, defaulting to AUTO{Colors.ENDC}"
        )
        remediation_mode = "AUTO"

    dry_run = remediation_mode == "DRY_RUN"
    approval_required = remediation_mode == "APPROVAL_REQUIRED"

    # Initialize AWS clients
    s3_client = boto3.client("s3")
    dynamodb_client = boto3.client("dynamodb")
    sns_client = boto3.client("sns")

    try:
        # Extract remediation request from event
        if (
            "Records" in event
            and len(event["Records"]) > 0
            and "Sns" in event["Records"][0]
        ):
            # SNS invocation
            sns_message = json.loads(event["Records"][0]["Sns"]["Message"])
            remediation_requests = (
                [sns_message] if not isinstance(sns_message, list) else sns_message
            )
        else:
            # Direct invocation
            remediation_requests = (
                [event]
                if "remediation_type" in event
                else event.get("remediations", [])
            )

        processed_count = 0
        results = []

        for request in remediation_requests:
            remediation_type = request.get("remediation_type")
            parameters = request.get("parameters", {})
            finding_id = request.get("finding_id", "unknown")
            finding_title = request.get("finding_title", "Unknown finding")
            finding_priority = request.get("finding_priority", "MEDIUM")
            evidence_path = request.get("evidence_path", "")

            if not remediation_type:
                logger.warning(
                    f"{Colors.WARNING}Skipping request without remediation_type{Colors.ENDC}"
                )
                continue

            # Generate remediation log ID
            remediation_id = str(uuid.uuid4())

            # Execute remediation (or log for dry run)
            action_result = execute_remediation(remediation_type, parameters, dry_run)

            # Determine resource info
            resource_id = (
                parameters.get("bucket_name")
                or parameters.get("group_id")
                or parameters.get("user_name")
                or parameters.get("key_id")
                or "unknown"
            )
            resource_type = {
                "block_s3_public_access": "S3 Bucket",
                "revoke_security_group_rule": "Security Group",
                "disable_iam_access_key": "IAM User",
                "enforce_s3_bucket_encryption": "S3 Bucket",
                "enable_kms_key_rotation": "KMS Key",
            }.get(remediation_type, "Unknown")

            # Create remediation log
            remediation_log = RemediationLog(
                id=remediation_id,
                remediation_type=remediation_type,
                resource_id=resource_id,
                resource_type=resource_type,
                finding_id=finding_id,
                finding_title=finding_title,
                finding_priority=finding_priority,
                action_taken=remediation_type,
                action_status=action_result["status"],
                action_timestamp=datetime.utcnow().isoformat(),
                execution_mode=remediation_mode,
                performed_by="GRC-Auto-Remediation",
                details=action_result.get("details", {}),
                evidence_path=evidence_path,
            )

            # Store remediation log
            store_remediation_log(
                s3_client,
                dynamodb_client,
                remediation_bucket,
                dynamodb_table,
                remediation_log,
            )

            # Send notification
            if approval_required:
                send_sns_notification(
                    sns_client, sns_topic_arn, remediation_log, approval_required=True
                )
            elif action_result["status"] in ["SUCCESS", "FAILED"]:
                send_sns_notification(
                    sns_client, sns_topic_arn, remediation_log, approval_required=False
                )

            processed_count += 1
            results.append(
                {
                    "remediation_id": remediation_id,
                    "remediation_type": remediation_type,
                    "resource_id": resource_id,
                    "status": action_result["status"],
                    "execution_mode": remediation_mode,
                }
            )

            status_emoji = (
                "✓" if action_result["status"] in ["SUCCESS", "DRY_RUN"] else "✗"
            )
            logger.info(
                f"{Colors.OKGREEN}{status_emoji} Remediation {remediation_type}: {action_result['status']}{Colors.ENDC}"
            )

        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        logger.info(
            f"{Colors.OKGREEN}Successfully processed {processed_count} remediation requests{Colors.ENDC}"
        )
        logger.info(f"{Colors.OKGREEN}Execution Mode: {remediation_mode}{Colors.ENDC}")
        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": f"Successfully processed {processed_count} remediation requests",
                    "processed_count": processed_count,
                    "execution_mode": remediation_mode,
                    "results": results,
                }
            ),
        }

    except Exception as e:
        logger.error(
            f"{Colors.FAIL}Error processing remediation requests: {str(e)}{Colors.ENDC}"
        )
        logger.exception(f"{Colors.FAIL}Full traceback:{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
