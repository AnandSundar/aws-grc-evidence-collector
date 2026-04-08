"""
GRC Evidence Platform - Evidence Processor Lambda

This Lambda function processes CloudTrail events, classifies them by priority,
stores evidence to S3 and DynamoDB, and sends alerts for critical/high priority events.

Author: GRC Platform Team
Version: 2.0
"""

import json
import logging
import os
import boto3
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ANSI color codes for terminal output (disabled in non-TTY environments like CloudWatch)
import sys


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


# Priority classification tables from SECTION 5.1
CRITICAL_EVENTS = {
    # Security Group Changes
    "AuthorizeSecurityGroupIngress": "Security group rule added allowing public access",
    "AuthorizeSecurityGroupEgress": "Security group rule added allowing unrestricted egress",
    # S3 Bucket Policy Changes
    "PutBucketPolicy": "S3 bucket policy modified - potential public access",
    "DeleteBucketPolicy": "S3 bucket policy removed - potential security gap",
    # IAM Changes
    "CreateAccessKey": "New IAM access key created",
    "UpdateAccessKey": "IAM access key status changed",
    "AttachRolePolicy": "Policy attached to IAM role",
    "AttachUserPolicy": "Policy attached to IAM user",
    "AttachGroupPolicy": "Policy attached to IAM group",
    "PutUserPolicy": "Inline policy added to IAM user",
    "PutRolePolicy": "Inline policy added to IAM role",
    "PutGroupPolicy": "Inline policy added to IAM group",
    # KMS Key Changes
    "DisableKey": "KMS key disabled",
    "ScheduleKeyDeletion": "KMS key scheduled for deletion",
    # GuardDuty
    "DisableGuardDuty": "GuardDuty disabled",
    # CloudTrail
    "StopLogging": "CloudTrail logging stopped",
    "DeleteTrail": "CloudTrail trail deleted",
}

HIGH_EVENTS = {
    # Security Group Changes
    "RevokeSecurityGroupIngress": "Security group rule revoked",
    "RevokeSecurityGroupEgress": "Security group egress rule revoked",
    # S3 Changes
    "PutBucketAcl": "S3 bucket ACL modified",
    "PutObjectAcl": "S3 object ACL modified",
    "CreateBucket": "New S3 bucket created",
    "DeleteBucket": "S3 bucket deleted",
    # IAM Changes
    "CreateUser": "New IAM user created",
    "DeleteUser": "IAM user deleted",
    "CreateRole": "New IAM role created",
    "DeleteRole": "IAM role deleted",
    "CreateGroup": "New IAM group created",
    "DeleteGroup": "IAM group deleted",
    "AddUserToGroup": "User added to IAM group",
    "RemoveUserFromGroup": "User removed from IAM group",
    # KMS Changes
    "CreateKey": "New KMS key created",
    "EnableKey": "KMS key enabled",
    "EnableKeyRotation": "KMS key rotation enabled",
    "DisableKeyRotation": "KMS key rotation disabled",
    # EC2 Changes
    "RunInstances": "EC2 instances launched",
    "TerminateInstances": "EC2 instances terminated",
    # RDS Changes
    "CreateDBInstance": "RDS instance created",
    "DeleteDBInstance": "RDS instance deleted",
    "ModifyDBInstance": "RDS instance modified",
}

MEDIUM_EVENTS = {
    # S3 Changes
    "PutObject": "Object uploaded to S3",
    "DeleteObject": "Object deleted from S3",
    "GetObject": "Object retrieved from S3",
    # EC2 Changes
    "StartInstances": "EC2 instances started",
    "StopInstances": "EC2 instances stopped",
    "RebootInstances": "EC2 instances rebooted",
    # RDS Changes
    "StartDBInstance": "RDS instance started",
    "StopDBInstance": "RDS instance stopped",
    "RebootDBInstance": "RDS instance rebooted",
    # CloudWatch
    "PutMetricData": "CloudWatch metric published",
    "PutMetricAlarm": "CloudWatch alarm created/modified",
    # Lambda
    "CreateFunction": "Lambda function created",
    "UpdateFunctionCode": "Lambda function code updated",
    "DeleteFunction": "Lambda function deleted",
}


# Evidence record schema from SECTION 5.1
@dataclass
class EvidenceRecord:
    """Evidence record stored in DynamoDB."""

    event_id: str
    event_name: str
    event_time: str
    event_source: str
    aws_region: str
    user_identity: Dict[str, Any]
    source_ip_address: str
    resources: List[Dict[str, Any]]
    priority: str
    finding_title: str
    description: str
    control_status: str
    compliance_frameworks: List[str]
    evidence_path: str
    collector_name: str
    ai_risk_score: Optional[float] = None
    ai_analysis: Optional[Dict[str, Any]] = None
    remediation_status: str = "PENDING"
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()


def classify_event(event_name: str) -> tuple[str, str]:
    """
    Classify a CloudTrail event by priority and generate finding title.

    Args:
        event_name: The CloudTrail event name

    Returns:
        Tuple of (priority, finding_title)
    """
    if event_name in CRITICAL_EVENTS:
        return "CRITICAL", CRITICAL_EVENTS[event_name]
    elif event_name in HIGH_EVENTS:
        return "HIGH", HIGH_EVENTS[event_name]
    elif event_name in MEDIUM_EVENTS:
        return "MEDIUM", MEDIUM_EVENTS[event_name]
    else:
        return "LOW", f"CloudTrail event: {event_name}"


def get_compliance_frameworks(event_name: str) -> List[str]:
    """
    Map events to relevant compliance frameworks.

    Args:
        event_name: The CloudTrail event name

    Returns:
        List of compliance framework names
    """
    frameworks = []

    # PCI-DSS relevant events
    pci_events = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "CreateAccessKey",
        "UpdateAccessKey",
        "AttachRolePolicy",
        "AttachUserPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "DisableKey",
        "ScheduleKeyDeletion",
        "StopLogging",
        "DeleteTrail",
        "PutBucketAcl",
        "PutObjectAcl",
        "CreateUser",
        "DeleteUser",
        "CreateRole",
        "DeleteRole",
    ]

    # SOC2 relevant events
    soc2_events = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "PutBucketPolicy",
        "CreateAccessKey",
        "UpdateAccessKey",
        "AttachRolePolicy",
        "AttachUserPolicy",
        "DisableKey",
        "StopLogging",
        "DeleteTrail",
        "CreateUser",
        "DeleteUser",
        "CreateRole",
        "DeleteRole",
        "RunInstances",
        "TerminateInstances",
    ]

    # CIS AWS Foundations Benchmark relevant events
    cis_events = [
        "AuthorizeSecurityGroupIngress",
        "PutBucketPolicy",
        "CreateAccessKey",
        "UpdateAccessKey",
        "AttachRolePolicy",
        "AttachUserPolicy",
        "DisableKey",
        "StopLogging",
        "DeleteTrail",
        "PutBucketAcl",
        "CreateUser",
        "DeleteUser",
        "CreateRole",
        "DeleteRole",
        "RunInstances",
        "CreateDBInstance",
        "DeleteDBInstance",
    ]

    if event_name in pci_events:
        frameworks.append("PCI-DSS")
    if event_name in soc2_events:
        frameworks.append("SOC2")
    if event_name in cis_events:
        frameworks.append("CIS")

    return frameworks if frameworks else ["GENERAL"]


def store_evidence_to_s3(
    s3_client: Any,
    bucket_name: str,
    event_id: str,
    event_data: Dict[str, Any],
    event_time: datetime,
) -> str:
    """
    Store evidence to S3 with date-partitioned path.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: S3 bucket name
        event_id: Unique event identifier
        event_data: CloudTrail event data
        event_time: Event timestamp

    Returns:
        S3 object path
    """
    s3_path = f"evidence/cloudtrail/{event_time.year}/{event_time.month:02d}/{event_time.day:02d}/{event_id}.json"

    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=s3_path,
            Body=json.dumps(event_data, indent=2),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        logger.info(
            f"{colors.OKGREEN}Evidence stored to S3: s3://{bucket_name}/{s3_path}{colors.ENDC}"
        )
        return s3_path
    except ClientError as e:
        logger.error(f"{colors.FAIL}Failed to store evidence to S3: {e}{colors.ENDC}")
        raise


def store_metadata_to_dynamodb(
    dynamodb_resource: Any, table_name: str, evidence_record: EvidenceRecord
) -> None:
    """
    Store evidence metadata to DynamoDB using Table resource.

    Args:
        dynamodb_resource: Boto3 DynamoDB resource
        table_name: DynamoDB table name
        evidence_record: Evidence record to store
    """
    try:
        table = dynamodb_resource.Table(table_name)

        # Build item with automatic type conversion
        item = {
            "event_id": evidence_record.event_id,
            "event_name": evidence_record.event_name,
            "event_time": evidence_record.event_time,
            "event_source": evidence_record.event_source,
            "aws_region": evidence_record.aws_region,
            "user_identity": evidence_record.user_identity,
            "source_ip_address": evidence_record.source_ip_address,
            "resources": evidence_record.resources,
            "priority": evidence_record.priority,
            "finding_title": evidence_record.finding_title,
            "description": evidence_record.description,
            "control_status": evidence_record.control_status,
            "compliance_frameworks": evidence_record.compliance_frameworks,
            "evidence_path": evidence_record.evidence_path,
            "collector_name": evidence_record.collector_name,
            "remediation_status": evidence_record.remediation_status,
            "timestamp": evidence_record.created_at,
        }

        # Add optional fields
        if evidence_record.ai_risk_score is not None:
            item["ai_risk_score"] = evidence_record.ai_risk_score
        if evidence_record.ai_analysis is not None:
            item["ai_analysis"] = evidence_record.ai_analysis

        table.put_item(Item=item)
        logger.info(
            f"{colors.OKGREEN}Metadata stored to DynamoDB: {evidence_record.event_id}{colors.ENDC}"
        )
    except ClientError as e:
        logger.error(
            f"{colors.FAIL}Failed to store metadata to DynamoDB: {e}{colors.ENDC}"
        )
        raise


def send_sns_alert(
    sns_client: Any, topic_arn: str, evidence_record: EvidenceRecord
) -> None:
    """
    Send SNS alert for critical/high priority events.

    Args:
        sns_client: Boto3 SNS client
        topic_arn: SNS topic ARN
        evidence_record: Evidence record to alert about
    """
    if evidence_record.priority not in ["CRITICAL", "HIGH"]:
        return

    subject = f"[{evidence_record.priority}] {evidence_record.finding_title}"

    message = f"""
GRC Evidence Platform Alert
============================

Priority: {evidence_record.priority}
Event: {evidence_record.event_name}
Time: {evidence_record.event_time}
Region: {evidence_record.aws_region}
User: {evidence_record.user_identity.get('userName', 'N/A')}
Source IP: {evidence_record.source_ip_address}

Finding: {evidence_record.finding_title}
Description: {evidence_record.description}

Compliance Frameworks: {', '.join(evidence_record.compliance_frameworks)}
Evidence Path: {evidence_record.evidence_path}

Event ID: {evidence_record.event_id}

This alert requires attention from the security team.
"""

    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
            MessageStructure="string",
        )
        logger.info(
            f"{colors.WARNING}SNS alert sent for {evidence_record.priority} event: {evidence_record.event_id}{colors.ENDC}"
        )
    except ClientError as e:
        logger.error(f"{colors.FAIL}Failed to send SNS alert: {e}{colors.ENDC}")
        # Don't raise - alert failure shouldn't fail the entire process


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing CloudTrail events.

    Args:
        event: EventBridge event containing CloudTrail data
        context: Lambda context object

    Returns:
        HTTP response with status code and result
    """
    logger.info(f"{colors.HEADER}{'='*60}{colors.ENDC}")
    logger.info(f"{colors.HEADER}Evidence Processor Lambda Invoked{colors.ENDC}")
    logger.info(f"{colors.HEADER}{'='*60}{colors.ENDC}")
    logger.info(
        f"{colors.OKCYAN}Event received: {json.dumps(event, indent=2)}{colors.ENDC}"
    )

    # Get environment variables
    evidence_bucket = os.environ.get("EVIDENCE_BUCKET")
    dynamodb_table = os.environ.get("DYNAMODB_TABLE")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")

    # Validate environment variables
    if not evidence_bucket or not evidence_bucket.strip():
        error_msg = "Invalid or missing EVIDENCE_BUCKET environment variable"
        logger.error(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}

    if not dynamodb_table or not dynamodb_table.strip():
        error_msg = "Invalid or missing DYNAMODB_TABLE environment variable"
        logger.error(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}

    if not sns_topic_arn or not sns_topic_arn.startswith("arn:aws:sns:"):
        error_msg = "Invalid or missing SNS_TOPIC_ARN environment variable (must be valid SNS ARN)"
        logger.error(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}

    # Initialize AWS clients
    s3_client = boto3.client("s3")
    dynamodb_resource = boto3.resource("dynamodb")
    sns_client = boto3.client("sns")

    try:
        # Extract CloudTrail event from EventBridge event
        records = event.get("Records", [])
        if not records:
            # Direct invocation with event data
            cloudtrail_events = [event]
        else:
            # S3 or EventBridge invocation
            cloudtrail_events = []
            for record in records:
                if "Sns" in record:
                    # SNS invocation
                    sns_message = json.loads(record["Sns"]["Message"])
                    if isinstance(sns_message, list):
                        cloudtrail_events.extend(sns_message)
                    else:
                        cloudtrail_events.append(sns_message)
                elif "s3" in record:
                    # S3 invocation - read the file
                    s3_info = record["s3"]
                    bucket = s3_info["bucket"]["name"]
                    key = s3_info["object"]["key"]
                    response = s3_client.get_object(Bucket=bucket, Key=key)
                    content = response["Body"].read().decode("utf-8")
                    cloudtrail_events.extend(json.loads(content))
                else:
                    # Direct EventBridge invocation
                    cloudtrail_events.append(record)

        processed_count = 0
        results = []

        for cloudtrail_event in cloudtrail_events:
            # Extract event details
            event_name = cloudtrail_event.get("eventName", "Unknown")
            event_time_str = cloudtrail_event.get(
                "eventTime", datetime.utcnow().isoformat()
            )
            event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
            event_source = cloudtrail_event.get("eventSource", "Unknown")
            aws_region = cloudtrail_event.get("awsRegion", "Unknown")
            user_identity = cloudtrail_event.get("userIdentity", {})
            source_ip = cloudtrail_event.get("sourceIPAddress", "N/A")
            resources = cloudtrail_event.get("resources", [])

            # Generate event ID
            event_id = f"{event_name}-{event_time.strftime('%Y%m%d%H%M%S')}-{hash(str(cloudtrail_event)) % 10000:04d}"

            # Classify event
            priority, finding_title = classify_event(event_name)

            # Get compliance frameworks
            compliance_frameworks = get_compliance_frameworks(event_name)

            # Determine control status
            control_status = "FAIL" if priority in ["CRITICAL", "HIGH"] else "PASS"

            # Create evidence record
            evidence_record = EvidenceRecord(
                event_id=event_id,
                event_name=event_name,
                event_time=event_time_str,
                event_source=event_source,
                aws_region=aws_region,
                user_identity=user_identity,
                source_ip_address=source_ip,
                resources=resources,
                priority=priority,
                finding_title=finding_title,
                description=f"CloudTrail event detected: {finding_title}",
                control_status=control_status,
                compliance_frameworks=compliance_frameworks,
                evidence_path="",
                collector_name="cloudtrail-processor",
            )

            # Store evidence to S3
            s3_path = store_evidence_to_s3(
                s3_client, evidence_bucket, event_id, cloudtrail_event, event_time
            )
            evidence_record.evidence_path = f"s3://{evidence_bucket}/{s3_path}"

            # Store metadata to DynamoDB
            store_metadata_to_dynamodb(
                dynamodb_resource, dynamodb_table, evidence_record
            )

            # Send SNS alert for critical/high priority
            send_sns_alert(sns_client, sns_topic_arn, evidence_record)

            processed_count += 1
            results.append(
                {
                    "event_id": event_id,
                    "event_name": event_name,
                    "priority": priority,
                    "status": "processed",
                }
            )

            logger.info(
                f"{colors.OKGREEN}✓ Processed event: {event_name} ({priority}){colors.ENDC}"
            )

        logger.info(f"{colors.OKGREEN}{'='*60}{colors.ENDC}")
        logger.info(
            f"{colors.OKGREEN}Successfully processed {processed_count} events{colors.ENDC}"
        )
        logger.info(f"{colors.OKGREEN}{'='*60}{colors.ENDC}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": f"Successfully processed {processed_count} events",
                    "processed_count": processed_count,
                    "results": results,
                }
            ),
        }

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_msg = f"AWS API error ({error_code}): {str(e)}"
        logger.error(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        logger.exception(f"{colors.FAIL}Full traceback:{colors.ENDC}")
        return {
            "statusCode": 503,
            "body": json.dumps({"error": error_msg, "type": "AWS_API_ERROR"}),
        }
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        error_msg = f"Data parsing error: {str(e)}"
        logger.error(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": error_msg, "type": "PARSING_ERROR"}),
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(f"{colors.FAIL}{error_msg}{colors.ENDC}")
        logger.exception(f"{colors.FAIL}Full traceback:{colors.ENDC}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": error_msg, "type": "INTERNAL_ERROR"}),
        }
