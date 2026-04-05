import json
import uuid
import os
import logging
from datetime import datetime
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
dynamodb = boto3.client("dynamodb")
sns = boto3.client("sns")

EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET")
METADATA_TABLE = os.environ.get("METADATA_TABLE")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN")

# Batching configuration
PENDING_EVENTS_TABLE = os.environ.get("PENDING_EVENTS_TABLE")
USE_BATCHING = os.environ.get("USE_BATCHING", "true").lower() == "true"
ENABLE_MEDIUM_ALERTS = os.environ.get("ENABLE_MEDIUM_ALERTS", "true").lower() == "true"
ENABLE_LOW_ALERTS = os.environ.get("ENABLE_LOW_ALERTS", "true").lower() == "true"

HIGH_PRIORITY_EVENTS = {
    "CreateUser",
    "DeleteUser",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "CreateRole",
    "DeleteRole",
    "AttachRolePolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
    "CreateSecurityGroup",
    "DeleteSecurityGroup",
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "PutBucketEncryption",
    "DeleteBucketEncryption",
    "CreateKey",
    "DisableKey",
    "ScheduleKeyDeletion",
}

MEDIUM_PRIORITY_EVENTS = {
    "StartInstances",
    "StopInstances",
    "TerminateInstances",
    "RunInstances",
    "CreateTag",
    "DeleteTag",
    "CreateSnapshot",
    "DeleteSnapshot",
    "ModifyInstanceAttribute",
    "ModifyNetworkInterfaceAttribute",
}


def get_priority(event_name: str, user_identity: dict) -> str:
    if event_name in HIGH_PRIORITY_EVENTS:
        return "HIGH"
    if event_name == "ConsoleLogin" and user_identity.get("type") == "Root":
        return "HIGH"
    if event_name in MEDIUM_PRIORITY_EVENTS:
        return "MEDIUM"
    return "LOW"


def derive_compliance_tags(event_name: str) -> list:
    if any(x in event_name for x in ["User", "Role", "Policy", "AccessKey", "Login"]):
        return ["PCI-DSS-8.3", "SOC2-CC6.1", "NIST-AC-2", "ISO27001-A.9"]
    if any(x in event_name for x in ["Bucket"]):
        return ["PCI-DSS-3.4", "SOC2-CC6.7"]
    if any(x in event_name for x in ["SecurityGroup", "Network"]):
        return ["PCI-DSS-1.3", "SOC2-CC6.6"]
    if any(x in event_name for x in ["Instance", "Snapshot", "Tag"]):
        return ["PCI-DSS-6.4", "SOC2-CC7.1", "NIST-CM-3"]
    return ["SOC2-CC6.8"]


def lambda_handler(event, context):
    try:
        detail = event.get("detail", event)

        event_name = detail.get("eventName", "Unknown")
        user_identity = detail.get("userIdentity", {})

        priority = get_priority(event_name, user_identity)

        evidence_id = str(uuid.uuid4())
        now = datetime.utcnow()

        evidence = {
            "evidence_id": evidence_id,
            "collected_at": now.isoformat(),
            "event_id": detail.get("eventID"),
            "event_name": event_name,
            "event_source": detail.get("eventSource"),
            "event_time": detail.get("eventTime"),
            "user_identity": user_identity,
            "source_ip": detail.get("sourceIPAddress"),
            "aws_region": detail.get("awsRegion"),
            "request_parameters": detail.get("requestParameters", {}),
            "response_elements": detail.get("responseElements", {}),
            "priority": priority,
            "compliance_tags": derive_compliance_tags(event_name),
            "raw_event": detail,
        }

        s3_key = f"evidence/{now.year}/{now.month:02d}/{now.day:02d}/{evidence_id}.json"
        if EVIDENCE_BUCKET:
            s3.put_object(
                Bucket=EVIDENCE_BUCKET,
                Key=s3_key,
                Body=json.dumps(evidence, default=str),
                ContentType="application/json",
            )

        ttl = int(now.timestamp()) + (90 * 24 * 60 * 60)
        if METADATA_TABLE:
            dynamodb.put_item(
                TableName=METADATA_TABLE,
                Item={
                    "evidence_id": {"S": evidence_id},
                    "timestamp": {"S": now.isoformat()},
                    "event_type": {"S": event_name},
                    "priority": {"S": priority},
                    "s3_key": {"S": s3_key},
                    "ttl": {"N": str(ttl)},
                },
            )

        # Store MEDIUM/LOW priority events in pending events table for batch processing
        if USE_BATCHING and PENDING_EVENTS_TABLE and priority in ["MEDIUM", "LOW"]:
            should_store = False
            if priority == "MEDIUM" and ENABLE_MEDIUM_ALERTS:
                should_store = True
            elif priority == "LOW" and ENABLE_LOW_ALERTS:
                should_store = True

            if should_store:
                try:
                    # Set expiry time: 2x the batch interval to ensure events don't expire before being processed
                    batch_interval = 15 if priority == "MEDIUM" else 60
                    expiry_time = int(now.timestamp()) + (batch_interval * 2 * 60)

                    dynamodb.put_item(
                        TableName=PENDING_EVENTS_TABLE,
                        Item={
                            "event_id": {"S": evidence_id},
                            "timestamp": {"S": now.isoformat()},
                            "priority": {"S": priority},
                            "processed": {"BOOL": False},
                            "event_name": {"S": event_name},
                            "event_time": {"S": detail.get("eventTime", "")},
                            "user_identity": {
                                "S": json.dumps(user_identity, default=str)
                            },
                            "source_ip": {"S": detail.get("sourceIPAddress", "")},
                            "aws_region": {"S": detail.get("awsRegion", "")},
                            "compliance_tags": {
                                "SS": derive_compliance_tags(event_name)
                            },
                            "evidence_id": {"S": evidence_id},
                            "s3_key": {"S": s3_key},
                            "expiry_time": {"N": str(expiry_time)},
                        },
                    )
                    logger.info(
                        f"Stored {priority} priority event in pending events table: {evidence_id}"
                    )
                except Exception as e:
                    logger.error(
                        f"Error storing event in pending events table: {str(e)}"
                    )

        if priority == "HIGH" and ALERT_TOPIC_ARN:
            sns.publish(
                TopicArn=ALERT_TOPIC_ARN,
                Subject=f"HIGH Priority GRC Alert: {event_name}",
                Message=json.dumps(evidence, indent=2, default=str),
            )

        return {
            "statusCode": 200,
            "evidence_id": evidence_id,
            "priority": priority,
            "s3_key": s3_key,
        }

    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        raise
