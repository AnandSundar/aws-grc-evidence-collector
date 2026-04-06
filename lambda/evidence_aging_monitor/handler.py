"""
GRC Evidence Platform - Evidence Aging Monitor Lambda

This Lambda function monitors evidence collection SLAs and alerts when evidence
becomes stale, indicating potential compliance gaps.

Author: GRC Platform Team
Version: 2.0
"""

import json
import logging
import os
import boto3
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ANSI color codes for terminal output
class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


# Evidence collection SLA from SECTION 5.4
EVIDENCE_COLLECTION_SLA = {
    # Security evidence collectors - high frequency
    "cloudtrail-processor": {"max_age_hours": 1, "description": "CloudTrail events"},
    "cloudtrail-processor-ai": {
        "max_age_hours": 1,
        "description": "CloudTrail events (AI)",
    },
    "guardduty-collector": {"max_age_hours": 1, "description": "GuardDuty findings"},
    "securityhub-collector": {
        "max_age_hours": 1,
        "description": "Security Hub findings",
    },
    # Configuration collectors - medium frequency
    "iam-collector": {"max_age_hours": 4, "description": "IAM configuration"},
    "s3-collector": {"max_age_hours": 4, "description": "S3 bucket configuration"},
    "ec2-collector": {"max_age_hours": 4, "description": "EC2 configuration"},
    "vpc-collector": {"max_age_hours": 4, "description": "VPC configuration"},
    "rds-collector": {"max_age_hours": 4, "description": "RDS configuration"},
    "kms-collector": {"max_age_hours": 4, "description": "KMS configuration"},
    "lambda-collector": {"max_age_hours": 4, "description": "Lambda configuration"},
    # Compliance collectors - lower frequency
    "config-collector": {"max_age_hours": 6, "description": "AWS Config rules"},
    "inspector-collector": {"max_age_hours": 6, "description": "Inspector findings"},
    "macie-collector": {"max_age_hours": 6, "description": "Macie findings"},
    "acm-collector": {"max_age_hours": 12, "description": "ACM certificates"},
}


@dataclass
class StaleEvidenceRecord:
    """Stale evidence record created when SLA is violated."""

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


def get_most_recent_evidence(
    dynamodb_client: Any, table_name: str, collector_name: str, gsi_name: str
) -> Optional[Dict[str, Any]]:
    """
    Query DynamoDB for the most recent evidence from a specific collector.

    Args:
        dynamodb_client: Boto3 DynamoDB client
        table_name: DynamoDB table name
        collector_name: Name of the evidence collector
        gsi_name: Global secondary index name for collector queries

    Returns:
        Most recent evidence record or None if not found
    """
    try:
        paginator = dynamodb_client.get_paginator("query")

        query_params = {
            "TableName": table_name,
            "IndexName": gsi_name,
            "KeyConditionExpression": "collector_name = :collector_name",
            "ExpressionAttributeValues": {":collector_name": {"S": collector_name}},
            "ScanIndexForward": False,  # Descending order (most recent first)
            "Limit": 1,
        }

        for page in paginator.paginate(**query_params):
            items = page.get("Items", [])
            if items:
                # Unmarshal the first (most recent) item
                item = items[0]
                evidence = {}
                for key, value in item.items():
                    if "S" in value:
                        evidence[key] = value["S"]
                    elif "N" in value:
                        evidence[key] = float(value["N"])
                    elif "L" in value:
                        evidence[key] = [v["S"] for v in value["L"]]
                    elif "M" in value:
                        evidence[key] = json.loads(value["M"])
                return evidence

        return None

    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to query most recent evidence for {collector_name}: {e}{Colors.ENDC}"
        )
        return None


def calculate_evidence_age(evidence: Dict[str, Any]) -> float:
    """
    Calculate the age of evidence in hours.

    Args:
        evidence: Evidence record with created_at timestamp

    Returns:
        Age in hours
    """
    try:
        created_at_str = evidence.get("created_at", "")
        if not created_at_str:
            return float("inf")

        created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        now = datetime.utcnow()

        age_hours = (now - created_at).total_seconds() / 3600
        return age_hours

    except (ValueError, AttributeError) as e:
        logger.warning(
            f"{Colors.WARNING}Could not calculate evidence age: {e}{Colors.ENDC}"
        )
        return float("inf")


def create_stale_evidence_record(
    collector_name: str,
    sla_info: Dict[str, Any],
    last_evidence: Optional[Dict[str, Any]],
    age_hours: float,
) -> StaleEvidenceRecord:
    """
    Create a stale evidence record for SLA violation.

    Args:
        collector_name: Name of the collector with stale evidence
        sla_info: SLA configuration for this collector
        last_evidence: Last evidence record (may be None)
        age_hours: Current age of the evidence

    Returns:
        Stale evidence record
    """
    timestamp = datetime.utcnow().isoformat()
    event_id = f"STALE-{collector_name}-{timestamp.replace(':', '-')}"

    # Determine severity based on how far past SLA
    age_multiplier = age_hours / sla_info["max_age_hours"]
    if age_multiplier >= 3.0:
        priority = "CRITICAL"
    elif age_multiplier >= 2.0:
        priority = "HIGH"
    else:
        priority = "MEDIUM"

    # Build description
    if last_evidence:
        last_evidence_time = last_evidence.get("created_at", "unknown")
        description = (
            f"Evidence from {sla_info['description']} collector is stale. "
            f"Last evidence collected at {last_evidence_time} "
            f"({age_hours:.1f} hours ago, exceeding SLA of {sla_info['max_age_hours']} hours). "
            f"This indicates a potential compliance gap."
        )
    else:
        description = (
            f"No evidence has been collected from {sla_info['description']} collector. "
            f"This exceeds the SLA of {sla_info['max_age_hours']} hours. "
            f"This indicates a potential compliance gap and collector failure."
        )

    return StaleEvidenceRecord(
        event_id=event_id,
        event_name="StaleEvidenceDetected",
        event_time=timestamp,
        event_source="grc-evidence-aging-monitor",
        aws_region=os.environ.get("AWS_REGION", "us-east-1"),
        user_identity={"type": "System", "principalId": "evidence-aging-monitor"},
        source_ip_address="N/A",
        resources=[
            {
                "type": "EvidenceCollector",
                "ARN": f"arn:aws:grc:collector:{collector_name}",
            }
        ],
        priority=priority,
        finding_title=f'Stale Evidence: {sla_info["description"]}',
        description=description,
        control_status="FAIL",
        compliance_frameworks=["PCI-DSS", "SOC2", "CIS"],
        evidence_path=f"sla-violation/{collector_name}",
        collector_name="evidence-aging-monitor",
        ai_risk_score=75.0 if priority == "HIGH" else 50.0,
        ai_analysis={
            "risk_score": 75.0 if priority == "HIGH" else 50.0,
            "risk_level": priority,
            "analysis": f"Evidence collection SLA violation for {collector_name}. Stale evidence may indicate collector failure or configuration issues.",
            "affected_resources": [collector_name],
            "recommended_actions": [
                "Verify collector is running and healthy",
                "Check collector logs for errors",
                "Verify IAM permissions",
                "Review EventBridge schedule rules",
                "Manually trigger collector if needed",
            ],
            "compliance_impact": ["PCI-DSS", "SOC2", "CIS"],
        },
    )


def store_stale_evidence(
    dynamodb_client: Any, table_name: str, stale_record: StaleEvidenceRecord
) -> None:
    """
    Store stale evidence record to DynamoDB.

    Args:
        dynamodb_client: Boto3 DynamoDB client
        table_name: DynamoDB table name
        stale_record: Stale evidence record to store
    """
    try:
        # Build DynamoDB item with proper type marshalling
        item = {
            "event_id": {"S": stale_record.event_id},
            "event_name": {"S": stale_record.event_name},
            "event_time": {"S": stale_record.event_time},
            "event_source": {"S": stale_record.event_source},
            "aws_region": {"S": stale_record.aws_region},
            "user_identity": {"S": json.dumps(stale_record.user_identity)},
            "source_ip_address": {"S": stale_record.source_ip_address},
            "resources": {"S": json.dumps(stale_record.resources)},
            "priority": {"S": stale_record.priority},
            "finding_title": {"S": stale_record.finding_title},
            "description": {"S": stale_record.description},
            "control_status": {"S": stale_record.control_status},
            "compliance_frameworks": {
                "S": json.dumps(stale_record.compliance_frameworks)
            },
            "evidence_path": {"S": stale_record.evidence_path},
            "collector_name": {"S": stale_record.collector_name},
            "remediation_status": {"S": stale_record.remediation_status},
            "created_at": {"S": stale_record.created_at},
        }

        # Add optional fields
        if stale_record.ai_risk_score is not None:
            item["ai_risk_score"] = {"N": str(stale_record.ai_risk_score)}
        if stale_record.ai_analysis is not None:
            item["ai_analysis"] = {"S": json.dumps(stale_record.ai_analysis)}

        dynamodb_client.put_item(TableName=table_name, Item=item)
        logger.info(
            f"{Colors.OKGREEN}Stale evidence record stored: {stale_record.event_id}{Colors.ENDC}"
        )

    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to store stale evidence: {e}{Colors.ENDC}")


def send_stale_evidence_alert(
    sns_client: Any,
    topic_arn: str,
    stale_record: StaleEvidenceRecord,
    collector_name: str,
    age_hours: float,
    sla_hours: int,
) -> None:
    """
    Send SNS alert for stale evidence.

    Args:
        sns_client: Boto3 SNS client
        topic_arn: SNS topic ARN
        stale_record: Stale evidence record
        collector_name: Name of the collector
        age_hours: Current age of the evidence
        sla_hours: SLA threshold in hours
    """
    # Only send alerts for HIGH and CRITICAL priority
    if stale_record.priority not in ["HIGH", "CRITICAL"]:
        return

    subject = f"[{stale_record.priority}] Stale Evidence Alert: {collector_name}"

    message = f"""
GRC Platform - Stale Evidence Alert
====================================

Priority: {stale_record.priority}
Collector: {collector_name}
Finding: {stale_record.finding_title}

Current Age: {age_hours:.1f} hours
SLA Threshold: {sla_hours} hours
SLA Violation: {age_hours - sla_hours:.1f} hours overdue

Description:
{stale_record.description}

AI Risk Score: {stale_record.ai_risk_score}/100
AI Analysis: {stale_record.ai_analysis.get('analysis', 'N/A') if stale_record.ai_analysis else 'N/A'}

Recommended Actions:
{chr(10).join(f"  • {action}" for action in (stale_record.ai_analysis.get('recommended_actions', []) if stale_record.ai_analysis else []))}

Compliance Impact: {', '.join(stale_record.compliance_frameworks)}

Event ID: {stale_record.event_id}
Timestamp: {stale_record.created_at}

This alert requires immediate attention from the GRC operations team.
"""

    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
            MessageStructure="string",
        )
        logger.info(
            f"{Colors.WARNING}SNS alert sent for stale evidence: {collector_name} ({stale_record.priority}){Colors.ENDC}"
        )

    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to send SNS alert: {e}{Colors.ENDC}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for evidence aging monitor.

    Args:
        event: EventBridge schedule event
        context: Lambda context object

    Returns:
        HTTP response with status code and result
    """
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(f"{Colors.HEADER}Evidence Aging Monitor Lambda Invoked{Colors.ENDC}")
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(
        f"{Colors.OKCYAN}Event received: {json.dumps(event, indent=2)}{Colors.ENDC}"
    )

    # Get environment variables
    evidence_table = os.environ.get("EVIDENCE_DYNAMODB_TABLE")
    sns_topic_arn = os.environ.get("AGING_MONITOR_SNS_TOPIC")
    collector_gsi = os.environ.get("COLLECTOR_NAME_GSI", "collector_name-index")

    if not all([evidence_table, sns_topic_arn]):
        error_msg = "Missing required environment variables: EVIDENCE_DYNAMODB_TABLE, AGING_MONITOR_SNS_TOPIC"
        logger.error(f"{Colors.FAIL}{error_msg}{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}

    # Initialize AWS clients
    dynamodb_client = boto3.client("dynamodb")
    sns_client = boto3.client("sns")

    try:
        stale_evidence_count = 0
        alerts_sent = 0
        results = []

        logger.info(
            f"{Colors.OKCYAN}Checking {len(EVIDENCE_COLLECTION_SLA)} collectors for stale evidence...{Colors.ENDC}"
        )

        # Check each collector for stale evidence
        for collector_name, sla_info in EVIDENCE_COLLECTION_SLA.items():
            max_age_hours = sla_info["max_age_hours"]
            description = sla_info["description"]

            logger.info(
                f"{Colors.OKCYAN}Checking collector: {collector_name} (SLA: {max_age_hours}h){Colors.ENDC}"
            )

            # Get most recent evidence for this collector
            last_evidence = get_most_recent_evidence(
                dynamodb_client, evidence_table, collector_name, collector_gsi
            )

            # Calculate age
            if last_evidence:
                age_hours = calculate_evidence_age(last_evidence)
                logger.info(
                    f"{Colors.OKCYAN}  Last evidence: {age_hours:.1f} hours ago{Colors.ENDC}"
                )
            else:
                age_hours = float("inf")
                logger.warning(
                    f"{Colors.WARNING}  No evidence found for collector{Colors.ENDC}"
                )

            # Check if evidence is stale
            if age_hours > max_age_hours:
                logger.warning(
                    f"{Colors.WARNING}  ⚠ STALE EVIDENCE DETECTED! ({age_hours:.1f}h > {max_age_hours}h){Colors.ENDC}"
                )

                # Create stale evidence record
                stale_record = create_stale_evidence_record(
                    collector_name, sla_info, last_evidence, age_hours
                )

                # Store stale evidence record
                store_stale_evidence(dynamodb_client, evidence_table, stale_record)
                stale_evidence_count += 1

                # Send alert if priority is HIGH or CRITICAL
                if stale_record.priority in ["HIGH", "CRITICAL"]:
                    send_stale_evidence_alert(
                        sns_client,
                        sns_topic_arn,
                        stale_record,
                        collector_name,
                        age_hours,
                        max_age_hours,
                    )
                    alerts_sent += 1

                results.append(
                    {
                        "collector_name": collector_name,
                        "status": "STALE",
                        "age_hours": round(age_hours, 2),
                        "sla_hours": max_age_hours,
                        "priority": stale_record.priority,
                        "alert_sent": stale_record.priority in ["HIGH", "CRITICAL"],
                    }
                )
            else:
                logger.info(f"{Colors.OKGREEN}  ✓ Evidence within SLA{Colors.ENDC}")
                results.append(
                    {
                        "collector_name": collector_name,
                        "status": "OK",
                        "age_hours": round(age_hours, 2) if last_evidence else None,
                        "sla_hours": max_age_hours,
                        "priority": None,
                        "alert_sent": False,
                    }
                )

        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        logger.info(f"{Colors.OKGREEN}Evidence aging check completed{Colors.ENDC}")
        logger.info(
            f"{Colors.OKGREEN}Collectors checked: {len(EVIDENCE_COLLECTION_SLA)}{Colors.ENDC}"
        )
        logger.info(
            f"{Colors.OKGREEN}Stale evidence found: {stale_evidence_count}{Colors.ENDC}"
        )
        logger.info(f"{Colors.OKGREEN}Alerts sent: {alerts_sent}{Colors.ENDC}")
        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Evidence aging check completed",
                    "collectors_checked": len(EVIDENCE_COLLECTION_SLA),
                    "stale_evidence_count": stale_evidence_count,
                    "alerts_sent": alerts_sent,
                    "results": results,
                }
            ),
        }

    except Exception as e:
        logger.error(
            f"{Colors.FAIL}Error in evidence aging monitor: {str(e)}{Colors.ENDC}"
        )
        logger.exception(f"{Colors.FAIL}Full traceback:{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
