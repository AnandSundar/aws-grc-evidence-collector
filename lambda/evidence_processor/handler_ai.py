"""
GRC Evidence Platform - AI-Augmented Evidence Processor Lambda

This Lambda function processes CloudTrail events with AI risk scoring using AWS Bedrock
and Claude 3 Sonnet. It classifies events by priority, stores evidence to S3 and DynamoDB,
and sends alerts for critical/high priority events.

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


def analyze_with_bedrock(
    bedrock_runtime: Any, event_name: str, event_data: Dict[str, Any], priority: str
) -> Optional[Dict[str, Any]]:
    """
    Analyze CloudTrail event using AWS Bedrock and Claude 3 Sonnet.

    Only analyzes HIGH and CRITICAL events for cost optimization.

    Args:
        bedrock_runtime: Boto3 Bedrock runtime client
        event_name: The CloudTrail event name
        event_data: Full CloudTrail event data
        priority: Event priority level

    Returns:
        AI analysis results with risk score and insights, or None if analysis fails
    """
    # Skip AI analysis for LOW and MEDIUM priority events
    if priority not in ["CRITICAL", "HIGH"]:
        logger.info(
            f"{Colors.OKCYAN}Skipping AI analysis for {priority} event: {event_name}{Colors.ENDC}"
        )
        return None

    try:
        # Exact prompt template from SECTION 5.1
        prompt = f"""You are a security analyst for AWS cloud infrastructure. Analyze the following CloudTrail event and provide a risk assessment.

Event Name: {event_name}
Event Time: {event_data.get('eventTime', 'N/A')}
AWS Region: {event_data.get('awsRegion', 'N/A')}
User Identity: {json.dumps(event_data.get('userIdentity', {}), indent=2)}
Source IP: {event_data.get('sourceIPAddress', 'N/A')}
Resources: {json.dumps(event_data.get('resources', []), indent=2)}
Request Parameters: {json.dumps(event_data.get('requestParameters', {}), indent=2)}

Please provide:
1. Risk Score (0-100): A numerical score indicating the security risk level
2. Risk Level: LOW, MEDIUM, HIGH, or CRITICAL
3. Analysis: A detailed explanation of why this event poses a risk
4. Affected Resources: List of AWS resources impacted by this event
5. Recommended Actions: Specific steps to remediate or mitigate the risk
6. Compliance Impact: Which compliance frameworks (PCI-DSS, SOC2, CIS) are affected

Respond in JSON format with the following structure:
{{
    "risk_score": <number 0-100>,
    "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
    "analysis": "<detailed explanation>",
    "affected_resources": ["<resource1>", "<resource2>"],
    "recommended_actions": ["<action1>", "<action2>"],
    "compliance_impact": ["<framework1>", "<framework2>"]
 }}"""

        # Invoke Nemotron Nano 12B v2 model
        model_id = "nvidia.nemotron-nano-12b-v2"

        response = bedrock_runtime.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "prompt": prompt,
                    "max_gen_len": 2048,
                    "temperature": 0.1,
                    "top_p": 0.9,
                }
            ),
        )

        # Parse response (Nemotron format: results[0].sequence)
        response_body = json.loads(response["body"].read().decode("utf-8"))
        content = response_body.get("results", [{}])[0].get("sequence", "")

        # Extract JSON from the response
        try:
            # Find JSON in the response
            start_idx = content.find("{")
            end_idx = content.rfind("}") + 1
            if start_idx >= 0 and end_idx > start_idx:
                json_str = content[start_idx:end_idx]
                analysis_result = json.loads(json_str)

                logger.info(
                    f"{Colors.OKGREEN}AI analysis completed for {event_name}: risk_score={analysis_result.get('risk_score', 'N/A')}{Colors.ENDC}"
                )
                return analysis_result
            else:
                logger.warning(
                    f"{Colors.WARNING}Could not extract JSON from AI response for {event_name}{Colors.ENDC}"
                )
                return None
        except json.JSONDecodeError as e:
            logger.warning(
                f"{Colors.WARNING}Failed to parse AI response JSON for {event_name}: {e}{Colors.ENDC}"
            )
            return None

    except ClientError as e:
        logger.warning(
            f"{Colors.WARNING}Bedrock API error for {event_name}: {e}{Colors.ENDC}"
        )
        return None
    except Exception as e:
        logger.warning(
            f"{Colors.WARNING}Unexpected error during AI analysis for {event_name}: {e}{Colors.ENDC}"
        )
        return None


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
            f"{Colors.OKGREEN}Evidence stored to S3: s3://{bucket_name}/{s3_path}{Colors.ENDC}"
        )
        return s3_path
    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to store evidence to S3: {e}{Colors.ENDC}")
        raise


def store_metadata_to_dynamodb(
    dynamodb_client: Any, table_name: str, evidence_record: EvidenceRecord
) -> None:
    """
    Store evidence metadata to DynamoDB.

    Args:
        dynamodb_client: Boto3 DynamoDB client
        table_name: DynamoDB table name
        evidence_record: Evidence record to store
    """
    try:
        # Build DynamoDB item with proper type marshalling
        item = {
            "event_id": {"S": evidence_record.event_id},
            "event_name": {"S": evidence_record.event_name},
            "event_time": {"S": evidence_record.event_time},
            "event_source": {"S": evidence_record.event_source},
            "aws_region": {"S": evidence_record.aws_region},
            "user_identity": {"S": json.dumps(evidence_record.user_identity)},
            "source_ip_address": {"S": evidence_record.source_ip_address},
            "resources": {"S": json.dumps(evidence_record.resources)},
            "priority": {"S": evidence_record.priority},
            "finding_title": {"S": evidence_record.finding_title},
            "description": {"S": evidence_record.description},
            "control_status": {"S": evidence_record.control_status},
            "compliance_frameworks": {
                "S": json.dumps(evidence_record.compliance_frameworks)
            },
            "evidence_path": {"S": evidence_record.evidence_path},
            "collector_name": {"S": evidence_record.collector_name},
            "remediation_status": {"S": evidence_record.remediation_status},
            "created_at": {"S": evidence_record.created_at},
        }

        # Add optional fields
        if evidence_record.ai_risk_score is not None:
            item["ai_risk_score"] = {"N": str(evidence_record.ai_risk_score)}
        if evidence_record.ai_analysis is not None:
            item["ai_analysis"] = {"S": json.dumps(evidence_record.ai_analysis)}

        dynamodb_client.put_item(TableName=table_name, Item=item)
        logger.info(
            f"{Colors.OKGREEN}Metadata stored to DynamoDB: {evidence_record.event_id}{Colors.ENDC}"
        )
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to store metadata to DynamoDB: {e}{Colors.ENDC}"
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

    # Build message with AI analysis if available
    ai_section = ""
    if evidence_record.ai_analysis:
        ai_section = f"""

AI Analysis:
- Risk Score: {evidence_record.ai_analysis.get('risk_score', 'N/A')}/100
- Risk Level: {evidence_record.ai_analysis.get('risk_level', 'N/A')}
- Analysis: {evidence_record.ai_analysis.get('analysis', 'N/A')}
- Affected Resources: {', '.join(evidence_record.ai_analysis.get('affected_resources', []))}
- Recommended Actions: {'; '.join(evidence_record.ai_analysis.get('recommended_actions', []))}
- Compliance Impact: {', '.join(evidence_record.ai_analysis.get('compliance_impact', []))}
"""

    message = f"""
GRC Evidence Platform Alert (AI-Enhanced)
=========================================

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
{ai_section}
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
            f"{Colors.WARNING}SNS alert sent for {evidence_record.priority} event: {evidence_record.event_id}{Colors.ENDC}"
        )
    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to send SNS alert: {e}{Colors.ENDC}")
        # Don't raise - alert failure shouldn't fail the entire process


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing CloudTrail events with AI analysis.

    Args:
        event: EventBridge event containing CloudTrail data
        context: Lambda context object

    Returns:
        HTTP response with status code and result
    """
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(
        f"{Colors.HEADER}AI-Augmented Evidence Processor Lambda Invoked{Colors.ENDC}"
    )
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(
        f"{Colors.OKCYAN}Event received: {json.dumps(event, indent=2)}{Colors.ENDC}"
    )

    # Get environment variables
    evidence_bucket = os.environ.get("EVIDENCE_BUCKET")
    dynamodb_table = os.environ.get("DYNAMODB_TABLE")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")
    bedrock_region = os.environ.get("BEDROCK_REGION", "us-east-1")

    if not all([evidence_bucket, dynamodb_table, sns_topic_arn]):
        error_msg = "Missing required environment variables: EVIDENCE_BUCKET, DYNAMODB_TABLE, SNS_TOPIC_ARN"
        logger.error(f"{Colors.FAIL}{error_msg}{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}

    # Initialize AWS clients
    s3_client = boto3.client("s3")
    dynamodb_client = boto3.client("dynamodb")
    sns_client = boto3.client("sns")
    bedrock_runtime = boto3.client("bedrock-runtime", region_name=bedrock_region)

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
        ai_analyzed_count = 0
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

            # Perform AI analysis for HIGH and CRITICAL events
            ai_risk_score = None
            ai_analysis = None
            if priority in ["CRITICAL", "HIGH"]:
                ai_analysis = analyze_with_bedrock(
                    bedrock_runtime, event_name, cloudtrail_event, priority
                )
                if ai_analysis:
                    ai_risk_score = ai_analysis.get("risk_score")
                    ai_analyzed_count += 1
                    logger.info(
                        f"{Colors.OKGREEN}✓ AI analysis completed for {event_name}: risk_score={ai_risk_score}{Colors.ENDC}"
                    )
                else:
                    logger.warning(
                        f"{Colors.WARNING}AI analysis failed for {event_name}, continuing without AI{Colors.ENDC}"
                    )

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
                collector_name="cloudtrail-processor-ai",
                ai_risk_score=ai_risk_score,
                ai_analysis=ai_analysis,
            )

            # Store evidence to S3
            s3_path = store_evidence_to_s3(
                s3_client, evidence_bucket, event_id, cloudtrail_event, event_time
            )
            evidence_record.evidence_path = f"s3://{evidence_bucket}/{s3_path}"

            # Store metadata to DynamoDB
            store_metadata_to_dynamodb(dynamodb_client, dynamodb_table, evidence_record)

            # Send SNS alert for critical/high priority
            send_sns_alert(sns_client, sns_topic_arn, evidence_record)

            processed_count += 1
            results.append(
                {
                    "event_id": event_id,
                    "event_name": event_name,
                    "priority": priority,
                    "ai_analyzed": ai_analysis is not None,
                    "ai_risk_score": ai_risk_score,
                    "status": "processed",
                }
            )

            logger.info(
                f"{Colors.OKGREEN}✓ Processed event: {event_name} ({priority}){Colors.ENDC}"
            )

        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        logger.info(
            f"{Colors.OKGREEN}Successfully processed {processed_count} events ({ai_analyzed_count} with AI analysis){Colors.ENDC}"
        )
        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": f"Successfully processed {processed_count} events ({ai_analyzed_count} with AI analysis)",
                    "processed_count": processed_count,
                    "ai_analyzed_count": ai_analyzed_count,
                    "results": results,
                }
            ),
        }

    except Exception as e:
        logger.error(f"{Colors.FAIL}Error processing events: {str(e)}{Colors.ENDC}")
        logger.exception(f"{Colors.FAIL}Full traceback:{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
