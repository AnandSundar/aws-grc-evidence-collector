"""
GRC Evidence Platform - Remediation Engine Lambda Handler

This Lambda function serves as the entry point for remediation execution,
integrating with the comprehensive remediation registry to support 24+
remediation functions across S3, IAM, RDS, and Security Groups.

Author: GRC Platform Team
Version: 2.0
"""

import json
import logging
import os
import sys
import boto3
import uuid
from datetime import datetime
from typing import Dict, Any
from botocore.exceptions import ClientError

# Add remediations directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'remediations'))

# Import remediation registry
from remediations.remediation_registry import execute_remediation, REMEDIATION_REGISTRY

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize AWS clients
s3 = boto3.client("s3")
dynamodb = boto3.client("dynamodb")
sns = boto3.client("sns")

# Environment variables
REMEDIATION_MODE = os.environ.get("REMEDIATION_MODE", "DRY_RUN")
EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET")
REMEDIATION_LOG_TABLE = os.environ.get("REMEDIATION_LOG_TABLE")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")

# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""
    def __init__(self):
        self.HEADER = "\033[95m" if sys.stdout.isatty() else ""
        self.OKBLUE = "\033[94m" if sys.stdout.isatty() else ""
        self.OKCYAN = "\033[96m" if sys.stdout.isatty() else ""
        self.OKGREEN = "\033[92m" if sys.stdout.isatty() else ""
        self.WARNING = "\033[93m" if sys.stdout.isatty() else ""
        self.FAIL = "\033[91m" if sys.stdout.isatty() else ""
        self.ENDC = "\033[0m" if sys.stdout.isatty() else ""
        self.BOLD = "\033[1m" if sys.stdout.isatty() else ""

colors = Colors()


def store_remediation_log(remediation_log: Dict[str, Any]) -> None:
    """Store remediation log to S3 and DynamoDB.

    Args:
        remediation_log: Remediation log record to store
    """
    try:
        # Store in S3 for long-term retention
        if EVIDENCE_BUCKET:
            timestamp = datetime.fromisoformat(
                remediation_log["created_at"].replace("Z", "+00:00")
            )
            s3_path = f"remediations/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/{remediation_log['id']}.json"

            s3.put_object(
                Bucket=EVIDENCE_BUCKET,
                Key=s3_path,
                Body=json.dumps(remediation_log, indent=2),
                ContentType="application/json",
                ServerSideEncryption="AES256"
            )
            logger.info(f"Remediation log stored to S3: s3://{EVIDENCE_BUCKET}/{s3_path}")

    except ClientError as e:
        logger.error(f"Failed to store remediation log in S3: {e}")

    try:
        # Store in DynamoDB for quick lookup
        if REMEDIATION_LOG_TABLE:
            item = {
                "id": {"S": remediation_log["id"]},
                "remediation_type": {"S": remediation_log["remediation_type"]},
                "resource_id": {"S": remediation_log["resource_id"]},
                "resource_type": {"S": remediation_log["resource_type"]},
                "finding_id": {"S": remediation_log["finding_id"]},
                "finding_title": {"S": remediation_log["finding_title"]},
                "finding_priority": {"S": remediation_log["finding_priority"]},
                "action_taken": {"S": remediation_log["action_taken"]},
                "action_status": {"S": remediation_log["action_status"]},
                "action_timestamp": {"S": remediation_log["action_timestamp"]},
                "execution_mode": {"S": remediation_log["execution_mode"]},
                "performed_by": {"S": remediation_log["performed_by"]},
                "details": {"S": json.dumps(remediation_log.get("details", {}))},
                "evidence_path": {"S": remediation_log["evidence_path"]},
                "created_at": {"S": remediation_log["created_at"]}
            }

            dynamodb.put_item(TableName=REMEDIATION_LOG_TABLE, Item=item)
            logger.info(f"Remediation log stored to DynamoDB: {remediation_log['id']}")

    except ClientError as e:
        logger.error(f"Failed to store remediation log in DynamoDB: {e}")


def send_sns_notification(remediation_log: Dict[str, Any]) -> None:
    """Send SNS notification about remediation completion.

    Args:
        remediation_log: Remediation log record to notify about
    """
    if not ALERT_TOPIC_ARN:
        return

    try:
        subject = f"[{remediation_log['action_status']}] Remediation: {remediation_log['remediation_type']}"

        message = f"""GRC Platform - Remediation Action Completed

Remediation Type: {remediation_log['remediation_type']}
Resource: {remediation_log['resource_type']} - {remediation_log['resource_id']}
Finding: {remediation_log['finding_title']} ({remediation_log['finding_priority']})
Action Taken: {remediation_log['action_taken']}
Status: {remediation_log['action_status']}
Execution Mode: {remediation_log['execution_mode']}
Details: {json.dumps(remediation_log.get('details', {}), indent=2)}
Finding ID: {remediation_log['finding_id']}
Evidence: {remediation_log['evidence_path']}
Timestamp: {remediation_log['action_timestamp']}"""

        sns.publish(
            TopicArn=ALERT_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        logger.info(f"SNS notification sent for remediation: {remediation_log['id']}")

    except ClientError as e:
        logger.error(f"Failed to send SNS notification: {e}")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """Lambda handler for remediation engine.

    This handler processes remediation requests and uses the remediation
    registry to execute the appropriate remediation function.

    Args:
        event: Lambda event containing remediation request
        context: Lambda context

    Returns:
        Response with remediation ID and status
    """
    logger.info(f"Remediation Engine invoked with event: {json.dumps(event)}")
    logger.info(f"REMEDIATION_MODE env var: {REMEDIATION_MODE}")
    logger.info(f"EVIDENCE_BUCKET env var: {EVIDENCE_BUCKET}")
    logger.info(f"ALERT_TOPIC_ARN env var: {ALERT_TOPIC_ARN}")

    # Generate remediation ID
    remediation_id = str(uuid.uuid4())
    now = datetime.utcnow()

    # Extract event parameters
    remediation_type = event.get("remediation_type", "unknown")
    resource_id = event.get("resource_id", "unknown")
    resource_type = event.get("resource_type", "unknown")
    finding_id = event.get("finding_id", "unknown")
    finding_title = event.get("finding_title", "Unknown")
    finding_priority = event.get("finding_priority", "MEDIUM")
    trigger = event.get("trigger", remediation_type)  # Config rule or EventBridge pattern

    logger.info(f"{colors.OKCYAN}Processing remediation request:{colors.ENDC}")
    logger.info(f"  Type: {remediation_type}")
    logger.info(f"  Trigger: {trigger}")
    logger.info(f"  Resource: {resource_type}/{resource_id}")
    logger.info(f"  Priority: {finding_priority}")
    logger.info(f"  Mode: {REMEDIATION_MODE}")

    # Validate trigger exists in registry
    if trigger not in REMEDIATION_REGISTRY:
        logger.warning(f"{colors.WARNING}Trigger '{trigger}' not found in registry, attempting remediation anyway{colors.ENDC}")

    # Execute remediation using registry
    try:
        logger.info(f"{colors.OKBLUE}Executing remediation via registry...{colors.ENDC}")
        logger.info(f"  Trigger: {trigger}, Resource: {resource_id}")

        result = execute_remediation(
            trigger=trigger,
            resource_id=resource_id,
            region=event.get("region", "us-east-1"),
            dry_run=(REMEDIATION_MODE == "DRY_RUN"),
            **event.get("parameters", {})
        )

        logger.info(f"{colors.OKGREEN}✓ Remediation execution completed{colors.ENDC}")
        logger.info(f"  Action: {result.get('action_taken', 'unknown')}")
        logger.info(f"  Status: {result.get('success', False)}")
        logger.info(f"  Result keys: {list(result.keys())}")

        # Build remediation log
        remediation_log = {
            "id": remediation_id,
            "remediation_type": remediation_type,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "finding_id": finding_id,
            "finding_title": finding_title,
            "finding_priority": finding_priority,
            "action_taken": result.get("action_taken", remediation_type),
            "action_status": "SUCCESS" if result.get("success") else "FAILED",
            "action_timestamp": now.isoformat(),
            "execution_mode": REMEDIATION_MODE,
            "performed_by": "remediation-engine",
            "details": result,
            "evidence_path": f"remediations/{now.year}/{now.month:02d}/{now.day:02d}/{remediation_id}.json",
            "created_at": now.isoformat(),
        }

        # Store log and send notification
        store_remediation_log(remediation_log)
        send_sns_notification(remediation_log)

        return {
            "statusCode": 200,
            "remediation_id": remediation_id,
            "action_status": remediation_log["action_status"],
            "action_taken": remediation_log["action_taken"],
            "success": result.get("success", False)
        }

    except Exception as e:
        logger.error(f"{colors.FAIL}✗ Error executing remediation: {str(e)}{colors.ENDC}")

        # Build failure remediation log
        remediation_log = {
            "id": remediation_id,
            "remediation_type": remediation_type,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "finding_id": finding_id,
            "finding_title": finding_title,
            "finding_priority": finding_priority,
            "action_taken": remediation_type,
            "action_status": "FAILED",
            "action_timestamp": now.isoformat(),
            "execution_mode": REMEDIATION_MODE,
            "performed_by": "remediation-engine",
            "details": {"error": str(e), "trigger": trigger},
            "evidence_path": f"remediations/{now.year}/{now.month:02d}/{now.day:02d}/{remediation_id}.json",
            "created_at": now.isoformat(),
        }

        # Store failure log
        store_remediation_log(remediation_log)
        send_sns_notification(remediation_log)

        return {
            "statusCode": 500,
            "remediation_id": remediation_id,
            "action_status": "FAILED",
            "error": str(e)
        }


# List all available remediations for debugging
def list_available_remediations() -> Dict[str, Any]:
    """List all available remediation functions in the registry.

    Returns:
        Dictionary of all remediation triggers and their metadata
    """
    return {
        "count": len(REMEDIATION_REGISTRY),
        "remediations": {
            trigger: {
                "function": metadata.get("function").__name__,
                "trigger_type": metadata.get("trigger_type"),
                "priority": metadata.get("priority"),
                "compliance_frameworks": metadata.get("compliance_frameworks"),
                "safety_mode": metadata.get("safety_mode"),
            }
            for trigger, metadata in REMEDIATION_REGISTRY.items()
        }
    }


if __name__ == "__main__":
    # For local testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Test listing available remediations
    print("\n=== Available Remediations ===")
    available = list_available_remediations()
    print(f"Total: {available['count']} remediations\n")

    for trigger, info in available['remediations'].items():
        print(f"Trigger: {trigger}")
        print(f"  Function: {info['function']}")
        print(f"  Type: {info['trigger_type']}")
        print(f"  Priority: {info['priority']}")
        print(f"  Compliance: {', '.join(info['compliance_frameworks'])}")
        print(f"  Safety: {info['safety_mode']}")
        print()