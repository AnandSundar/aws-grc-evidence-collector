"""
GRC Evidence Platform - Daily Compliance Scorecard Generator Lambda

This Lambda function generates daily compliance scorecards by analyzing evidence
from the last 24 hours, calculating framework scores, and identifying top risks.

Author: GRC Platform Team
Version: 2.0
"""

import json
import logging
import os
import boto3
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
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


# Dataclasses from SECTION 5.3
@dataclass
class FrameworkScore:
    """Compliance framework score."""

    framework_name: str
    total_tested: int
    passing: int
    failing: int
    score: float
    trend: Optional[str] = None  # 'UP', 'DOWN', 'STABLE'


@dataclass
class ComplianceScorecard:
    """Daily compliance scorecard."""

    scorecard_date: str
    generated_at: str
    account_id: str
    overall_score: float
    overall_trend: Optional[str]
    framework_scores: List[FrameworkScore]
    total_evidence_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_5_risks: List[Dict[str, Any]]
    evidence_by_collector: Dict[str, int]
    remediation_summary: Dict[str, int]
    sla_adherence: float


def query_evidence_last_24h(
    dynamodb_client: Any, table_name: str, gsi_name: str
) -> List[Dict[str, Any]]:
    """
    Query evidence from the last 24 hours using timestamp GSI.

    Args:
        dynamodb_client: Boto3 DynamoDB client
        table_name: DynamoDB table name
        gsi_name: Global secondary index name for timestamp queries

    Returns:
        List of evidence records
    """
    evidence_list = []

    try:
        # Calculate time range (last 24 hours)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        # Query using the timestamp GSI
        paginator = dynamodb_client.get_paginator("query")

        query_params = {
            "TableName": table_name,
            "IndexName": gsi_name,
            "KeyConditionExpression": "created_at BETWEEN :start_time AND :end_time",
            "ExpressionAttributeValues": {
                ":start_time": {"S": start_time.isoformat()},
                ":end_time": {"S": end_time.isoformat()},
            },
        }

        for page in paginator.paginate(**query_params):
            for item in page.get("Items", []):
                # Unmarshal DynamoDB item
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
                evidence_list.append(evidence)

        logger.info(
            f"{Colors.OKCYAN}Queried {len(evidence_list)} evidence records from last 24h{Colors.ENDC}"
        )

    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to query evidence: {e}{Colors.ENDC}")

    return evidence_list


def get_yesterday_scorecard(
    s3_client: Any, bucket_name: str, yesterday_date: str
) -> Optional[Dict[str, Any]]:
    """
    Retrieve yesterday's scorecard for trend calculation.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: S3 bucket name
        yesterday_date: Date string in YYYY-MM-DD format

    Returns:
        Yesterday's scorecard data or None if not found
    """
    try:
        s3_key = f"scorecards/{yesterday_date}/scorecard.json"
        response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
        content = response["Body"].read().decode("utf-8")
        return json.loads(content)
    except ClientError as e:
        logger.warning(
            f"{Colors.WARNING}Could not retrieve yesterday's scorecard: {e}{Colors.ENDC}"
        )
        return None


def calculate_framework_scores(
    evidence_list: List[Dict[str, Any]],
) -> List[FrameworkScore]:
    """
    Calculate compliance scores for each framework.

    Args:
        evidence_list: List of evidence records

    Returns:
        List of framework scores
    """
    framework_data = {}

    for evidence in evidence_list:
        compliance_frameworks = evidence.get("compliance_frameworks", "[]")
        if isinstance(compliance_frameworks, str):
            try:
                frameworks = json.loads(compliance_frameworks)
            except json.JSONDecodeError:
                frameworks = [compliance_frameworks]
        else:
            frameworks = compliance_frameworks

        control_status = evidence.get("control_status", "UNKNOWN")

        for framework in frameworks:
            if framework not in framework_data:
                framework_data[framework] = {
                    "total_tested": 0,
                    "passing": 0,
                    "failing": 0,
                }

            framework_data[framework]["total_tested"] += 1
            if control_status == "PASS":
                framework_data[framework]["passing"] += 1
            else:
                framework_data[framework]["failing"] += 1

    framework_scores = []
    for framework_name, data in framework_data.items():
        score = (
            (data["passing"] / data["total_tested"] * 100)
            if data["total_tested"] > 0
            else 0.0
        )
        framework_scores.append(
            FrameworkScore(
                framework_name=framework_name,
                total_tested=data["total_tested"],
                passing=data["passing"],
                failing=data["failing"],
                score=round(score, 2),
            )
        )

    return framework_scores


def calculate_trend(current_score: float, previous_score: Optional[float]) -> str:
    """
    Calculate trend direction between current and previous scores.

    Args:
        current_score: Current score value
        previous_score: Previous score value (may be None)

    Returns:
        Trend string: 'UP', 'DOWN', or 'STABLE'
    """
    if previous_score is None:
        return "STABLE"

    if current_score > previous_score + 1.0:
        return "UP"
    elif current_score < previous_score - 1.0:
        return "DOWN"
    else:
        return "STABLE"


def generate_top_5_risks(evidence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generate top 5 risks from CRITICAL and HIGH evidence.

    Args:
        evidence_list: List of evidence records

    Returns:
        List of top 5 risk items sorted by AI risk score
    """
    # Filter for CRITICAL and HIGH priority
    high_priority_evidence = [
        e for e in evidence_list if e.get("priority") in ["CRITICAL", "HIGH"]
    ]

    # Sort by AI risk score (descending), then by priority (CRITICAL first)
    def sort_key(evidence):
        ai_score = evidence.get("ai_risk_score", 0)
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        priority = priority_order.get(evidence.get("priority", "LOW"), 99)
        return (-ai_score, priority)

    high_priority_evidence.sort(key=sort_key)

    # Take top 5
    top_risks = []
    for evidence in high_priority_evidence[:5]:
        risk_item = {
            "event_id": evidence.get("event_id", "unknown"),
            "event_name": evidence.get("event_name", "unknown"),
            "priority": evidence.get("priority", "UNKNOWN"),
            "finding_title": evidence.get("finding_title", "Unknown"),
            "ai_risk_score": evidence.get("ai_risk_score"),
            "event_time": evidence.get("event_time"),
            "aws_region": evidence.get("aws_region"),
            "remediation_status": evidence.get("remediation_status", "PENDING"),
        }
        top_risks.append(risk_item)

    return top_risks


def aggregate_evidence_by_collector(
    evidence_list: List[Dict[str, Any]],
) -> Dict[str, int]:
    """
    Aggregate evidence count by collector name.

    Args:
        evidence_list: List of evidence records

    Returns:
        Dictionary mapping collector names to counts
    """
    collector_counts = {}
    for evidence in evidence_list:
        collector = evidence.get("collector_name", "unknown")
        collector_counts[collector] = collector_counts.get(collector, 0) + 1
    return collector_counts


def query_remediation_summary(
    dynamodb_client: Any, table_name: str, start_time: datetime, end_time: datetime
) -> Dict[str, int]:
    """
    Query remediation actions from the last 24 hours.

    Args:
        dynamodb_client: Boto3 DynamoDB client
        table_name: Remediation log table name
        start_time: Start of time range
        end_time: End of time range

    Returns:
        Dictionary with remediation summary counts
    """
    summary = {"total": 0, "successful": 0, "failed": 0, "pending": 0}

    try:
        paginator = dynamodb_client.get_paginator("scan")

        scan_params = {
            "TableName": table_name,
            "FilterExpression": "created_at BETWEEN :start_time AND :end_time",
            "ExpressionAttributeValues": {
                ":start_time": {"S": start_time.isoformat()},
                ":end_time": {"S": end_time.isoformat()},
            },
        }

        for page in paginator.paginate(**scan_params):
            for item in page.get("Items", []):
                action_status = item.get("action_status", {}).get("S", "UNKNOWN")
                summary["total"] += 1
                if action_status == "SUCCESS":
                    summary["successful"] += 1
                elif action_status == "FAILED":
                    summary["failed"] += 1
                else:
                    summary["pending"] += 1

        logger.info(
            f"{Colors.OKCYAN}Queried {summary['total']} remediation records{Colors.ENDC}"
        )

    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to query remediation summary: {e}{Colors.ENDC}"
        )

    return summary


def calculate_sla_adherence(
    evidence_list: List[Dict[str, Any]], sla_threshold_hours: int = 24
) -> float:
    """
    Calculate SLA adherence percentage for evidence collection.

    Args:
        evidence_list: List of evidence records
        sla_threshold_hours: SLA threshold in hours

    Returns:
        SLA adherence percentage (0-100)
    """
    if not evidence_list:
        return 100.0

    within_sla = 0
    total = len(evidence_list)

    for evidence in evidence_list:
        # Check if evidence was collected within SLA
        # This is a simplified check - in production, you'd compare event_time vs created_at
        event_time_str = evidence.get("event_time", "")
        created_at_str = evidence.get("created_at", "")

        if event_time_str and created_at_str:
            try:
                event_time = datetime.fromisoformat(
                    event_time_str.replace("Z", "+00:00")
                )
                created_at = datetime.fromisoformat(
                    created_at_str.replace("Z", "+00:00")
                )
                delay_hours = (created_at - event_time).total_seconds() / 3600

                if delay_hours <= sla_threshold_hours:
                    within_sla += 1
            except (ValueError, AttributeError):
                # If we can't parse times, assume within SLA
                within_sla += 1

    return round((within_sla / total * 100), 2) if total > 0 else 100.0


def store_scorecard(
    s3_client: Any,
    dynamodb_client: Any,
    s3_bucket: str,
    dynamodb_table: str,
    scorecard: ComplianceScorecard,
) -> None:
    """
    Store scorecard to S3 and DynamoDB.

    Args:
        s3_client: Boto3 S3 client
        dynamodb_client: Boto3 DynamoDB client
        s3_bucket: S3 bucket name
        dynamodb_table: DynamoDB table name
        scorecard: Compliance scorecard to store
    """
    # Store to S3
    date_str = scorecard.scorecard_date
    s3_key = f"scorecards/{date_str}/scorecard.json"

    try:
        scorecard_dict = asdict(scorecard)
        # Get KMS key from environment
        kms_key = os.environ.get("KMS_KEY")

        # Prepare S3 put parameters
        s3_params = {
            "Bucket": s3_bucket,
            "Key": s3_key,
            "Body": json.dumps(scorecard_dict, indent=2),
            "ContentType": "application/json",
        }

        # Add KMS encryption if key is available
        if kms_key:
            s3_params["ServerSideEncryption"] = "aws:kms"
            s3_params["SSEKeyId"] = kms_key

        s3_client.put_object(**s3_params)
        logger.info(
            f"{Colors.OKGREEN}Scorecard stored to S3: s3://{s3_bucket}/{s3_key}{Colors.ENDC}"
        )
    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to store scorecard to S3: {e}{Colors.ENDC}")

    # Store to DynamoDB
    try:
        item = {
            "scorecard_date": {"S": scorecard.scorecard_date},
            "generated_at": {"S": scorecard.generated_at},
            "account_id": {"S": scorecard.account_id},
            "overall_score": {"N": str(scorecard.overall_score)},
            "overall_trend": {"S": scorecard.overall_trend or "STABLE"},
            "framework_scores": {
                "S": json.dumps([asdict(fs) for fs in scorecard.framework_scores])
            },
            "total_evidence_count": {"N": str(scorecard.total_evidence_count)},
            "critical_count": {"N": str(scorecard.critical_count)},
            "high_count": {"N": str(scorecard.high_count)},
            "medium_count": {"N": str(scorecard.medium_count)},
            "low_count": {"N": str(scorecard.low_count)},
            "top_5_risks": {"S": json.dumps(scorecard.top_5_risks)},
            "evidence_by_collector": {"S": json.dumps(scorecard.evidence_by_collector)},
            "remediation_summary": {"S": json.dumps(scorecard.remediation_summary)},
            "sla_adherence": {"N": str(scorecard.sla_adherence)},
        }
        dynamodb_client.put_item(TableName=dynamodb_table, Item=item)
        logger.info(
            f"{Colors.OKGREEN}Scorecard stored to DynamoDB: {scorecard.scorecard_date}{Colors.ENDC}"
        )
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to store scorecard to DynamoDB: {e}{Colors.ENDC}"
        )


def send_daily_digest(
    sns_client: Any, topic_arn: str, scorecard: ComplianceScorecard
) -> None:
    """
    Send daily summary digest via SNS.

    Args:
        sns_client: Boto3 SNS client
        topic_arn: SNS topic ARN
        scorecard: Compliance scorecard
    """
    subject = f"[GRC Daily Digest] Compliance Scorecard - {scorecard.scorecard_date}"

    # Build framework scores section
    framework_section = "\n".join(
        [
            f"  • {fs.framework_name}: {fs.score}% ({fs.passing}/{fs.total_tested} passing) [{fs.trend or 'STABLE'}]"
            for fs in scorecard.framework_scores
        ]
    )

    # Build top risks section
    risks_section = "\n".join(
        [
            f"  {i+1}. [{risk['priority']}] {risk['finding_title']} "
            f"(Risk Score: {risk['ai_risk_score'] or 'N/A'}) - {risk['remediation_status']}"
            for i, risk in enumerate(scorecard.top_5_risks)
        ]
    )

    # Build collector section
    collector_section = "\n".join(
        [
            f"  • {collector}: {count} records"
            for collector, count in sorted(
                scorecard.evidence_by_collector.items(),
                key=lambda x: x[1],
                reverse=True,
            )
        ]
    )

    message = f"""
GRC Platform - Daily Compliance Digest
=======================================

Date: {scorecard.scorecard_date}
Generated: {scorecard.generated_at}
Account: {scorecard.account_id}

OVERALL COMPLIANCE SCORE
------------------------
Score: {scorecard.overall_score}%
Trend: {scorecard.overall_trend or 'STABLE'}

FRAMEWORK SCORES
----------------
{framework_section}

EVIDENCE SUMMARY
----------------
Total Evidence: {scorecard.total_evidence_count}
  • CRITICAL: {scorecard.critical_count}
  • HIGH: {scorecard.high_count}
  • MEDIUM: {scorecard.medium_count}
  • LOW: {scorecard.low_count}

TOP 5 RISKS
-----------
{risks_section if risks_section else "  No high-priority risks detected."}

EVIDENCE BY COLLECTOR
---------------------
{collector_section}

REMEDIATION SUMMARY
-------------------
Total Actions: {scorecard.remediation_summary.get('total', 0)}
  • Successful: {scorecard.remediation_summary.get('successful', 0)}
  • Failed: {scorecard.remediation_summary.get('failed', 0)}
  • Pending: {scorecard.remediation_summary.get('pending', 0)}

SLA ADHERENCE
-------------
{scorecard.sla_adherence}% of evidence collected within SLA

View detailed scorecard in the GRC Platform console.
"""

    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
            MessageStructure="string",
        )
        logger.info(f"{Colors.WARNING}Daily digest sent via SNS{Colors.ENDC}")
    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to send daily digest: {e}{Colors.ENDC}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for daily compliance scorecard generation.

    Args:
        event: EventBridge schedule event
        context: Lambda context object

    Returns:
        HTTP response with status code and result
    """
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(
        f"{Colors.HEADER}Daily Compliance Scorecard Generator Invoked{Colors.ENDC}"
    )
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(
        f"{Colors.OKCYAN}Event received: {json.dumps(event, indent=2)}{Colors.ENDC}"
    )

    # Get environment variables
    scorecard_bucket = os.environ.get("SCORECARD_BUCKET")
    evidence_table = os.environ.get("EVIDENCE_DYNAMODB_TABLE")
    scorecard_table = os.environ.get("SCORECARD_DYNAMODB_TABLE")
    remediation_table = os.environ.get("REMEDIATION_DYNAMODB_TABLE")
    sns_topic_arn = os.environ.get("SCORECARD_SNS_TOPIC")
    evidence_gsi = os.environ.get("EVIDENCE_TIMESTAMP_GSI", "created_at-index")
    account_id = os.environ.get(
        "AWS_ACCOUNT_ID", boto3.client("sts").get_caller_identity()["Account"]
    )

    if not all([scorecard_bucket, evidence_table, scorecard_table, sns_topic_arn]):
        error_msg = "Missing required environment variables: SCORECARD_BUCKET, EVIDENCE_DYNAMODB_TABLE, SCORECARD_DYNAMODB_TABLE, SCORECARD_SNS_TOPIC"
        logger.error(f"{Colors.FAIL}{error_msg}{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}

    # Initialize AWS clients
    s3_client = boto3.client("s3")
    dynamodb_client = boto3.client("dynamodb")
    sns_client = boto3.client("sns")

    try:
        # Calculate date ranges
        today = datetime.utcnow().date()
        yesterday = today - timedelta(days=1)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        logger.info(
            f"{Colors.OKCYAN}Generating scorecard for date: {today}{Colors.ENDC}"
        )

        # Query evidence from last 24 hours
        evidence_list = query_evidence_last_24h(
            dynamodb_client, evidence_table, evidence_gsi
        )

        # Get yesterday's scorecard for trend calculation
        yesterday_scorecard = get_yesterday_scorecard(
            s3_client, scorecard_bucket, yesterday.isoformat()
        )

        # Calculate framework scores
        framework_scores = calculate_framework_scores(evidence_list)

        # Calculate overall score
        total_tested = sum(fs.total_tested for fs in framework_scores)
        total_passing = sum(fs.passing for fs in framework_scores)
        overall_score = (
            (total_passing / total_tested * 100) if total_tested > 0 else 100.0
        )

        # Calculate overall trend
        previous_overall_score = (
            yesterday_scorecard.get("overall_score") if yesterday_scorecard else None
        )
        overall_trend = calculate_trend(overall_score, previous_overall_score)

        # Calculate framework trends
        if yesterday_scorecard:
            yesterday_frameworks = {
                fs["framework_name"]: fs["score"]
                for fs in yesterday_scorecard.get("framework_scores", [])
            }
            for fs in framework_scores:
                fs.trend = calculate_trend(
                    fs.score, yesterday_frameworks.get(fs.framework_name)
                )

        # Count evidence by priority
        priority_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for evidence in evidence_list:
            priority = evidence.get("priority", "LOW")
            if priority in priority_counts:
                priority_counts[priority] += 1

        # Generate top 5 risks
        top_5_risks = generate_top_5_risks(evidence_list)

        # Aggregate evidence by collector
        evidence_by_collector = aggregate_evidence_by_collector(evidence_list)

        # Query remediation summary
        remediation_summary = query_remediation_summary(
            dynamodb_client, remediation_table, start_time, end_time
        )

        # Calculate SLA adherence
        sla_adherence = calculate_sla_adherence(evidence_list)

        # Create scorecard
        scorecard = ComplianceScorecard(
            scorecard_date=today.isoformat(),
            generated_at=datetime.utcnow().isoformat(),
            account_id=account_id,
            overall_score=round(overall_score, 2),
            overall_trend=overall_trend,
            framework_scores=framework_scores,
            total_evidence_count=len(evidence_list),
            critical_count=priority_counts["CRITICAL"],
            high_count=priority_counts["HIGH"],
            medium_count=priority_counts["MEDIUM"],
            low_count=priority_counts["LOW"],
            top_5_risks=top_5_risks,
            evidence_by_collector=evidence_by_collector,
            remediation_summary=remediation_summary,
            sla_adherence=sla_adherence,
        )

        # Store scorecard
        store_scorecard(
            s3_client, dynamodb_client, scorecard_bucket, scorecard_table, scorecard
        )

        # Send daily digest
        send_daily_digest(sns_client, sns_topic_arn, scorecard)

        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        logger.info(f"{Colors.OKGREEN}Scorecard generated successfully{Colors.ENDC}")
        logger.info(
            f"{Colors.OKGREEN}Overall Score: {scorecard.overall_score}% ({overall_trend}){Colors.ENDC}"
        )
        logger.info(
            f"{Colors.OKGREEN}Total Evidence: {scorecard.total_evidence_count}{Colors.ENDC}"
        )
        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Scorecard generated successfully",
                    "scorecard_date": scorecard.scorecard_date,
                    "overall_score": scorecard.overall_score,
                    "overall_trend": overall_trend,
                    "total_evidence": scorecard.total_evidence_count,
                    "framework_count": len(framework_scores),
                    "top_risks_count": len(top_5_risks),
                }
            ),
        }

    except Exception as e:
        logger.error(f"{Colors.FAIL}Error generating scorecard: {str(e)}{Colors.ENDC}")
        logger.exception(f"{Colors.FAIL}Full traceback:{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
