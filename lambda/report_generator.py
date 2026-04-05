#!/usr/bin/env python3
"""
AWS GRC Evidence Collector - Scheduled Report Generator Lambda

This Lambda function generates and sends scheduled email reports of GRC events.
It's triggered by EventBridge on a configurable schedule (e.g., daily, weekly).

Environment Variables:
- REPORT_EMAIL: Recipient email address (required)
- REPORT_DAYS: Number of days to look back (default: 1)
- DYNAMODB_TABLE: DynamoDB table name (required)
- S3_BUCKET: S3 bucket name (optional, for full event data)
- FROM_EMAIL: Sender email address (default: no-reply@aws-grc.local)
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize AWS clients
dynamodb = boto3.client("dynamodb")
s3 = boto3.client("s3")
ses = boto3.client("ses")

# Get configuration from environment variables
REPORT_EMAIL = os.environ.get("REPORT_EMAIL")
REPORT_DAYS = int(os.environ.get("REPORT_DAYS", "1"))
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
S3_BUCKET = os.environ.get("S3_BUCKET")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "no-reply@aws-grc.local")


def dynamodb_item_to_dict(item: Dict) -> Dict:
    """
    Convert DynamoDB item format to regular dictionary.

    Args:
        item: DynamoDB item with type descriptors

    Returns:
        Regular dictionary
    """
    result = {}
    for key, value in item.items():
        if "S" in value:
            result[key] = value["S"]
        elif "N" in value:
            result[key] = int(value["N"])
        elif "BOOL" in value:
            result[key] = value["BOOL"]
        elif "M" in value:
            result[key] = dynamodb_item_to_dict(value["M"])
        elif "L" in value:
            result[key] = [
                (dynamodb_item_to_dict(v) if "M" in v else v.get("S", v.get("N", v)))
                for v in value["L"]
            ]
        elif "SS" in value:
            result[key] = value["SS"]
        elif "NS" in value:
            result[key] = [int(n) for n in value["NS"]]
    return result


def fetch_event_from_s3(s3_key: str) -> Optional[Dict]:
    """
    Fetch full event data from S3.

    Args:
        s3_key: S3 key for the event

    Returns:
        Event dictionary or None if not found
    """
    if not S3_BUCKET:
        return None

    try:
        response = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
        event_data = json.loads(response["Body"].read().decode("utf-8"))
        return event_data
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            logger.warning(f"Event not found in S3: {s3_key}")
        else:
            logger.warning(f"Error fetching event from S3: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error fetching event from S3: {e}")
        return None


def query_events(days: int = 1) -> List[Dict]:
    """
    Query DynamoDB for events in the specified time period.

    Args:
        days: Number of days to look back

    Returns:
        List of event dictionaries
    """
    logger.info(f"Querying DynamoDB for events in the last {days} day(s)")

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)

    logger.info(f"Time range: {start_time.isoformat()} to {end_time.isoformat()}")

    events = []

    try:
        # Scan all events and filter by time
        response = dynamodb.scan(
            TableName=DYNAMODB_TABLE,
            FilterExpression="#ts BETWEEN :start AND :end",
            ExpressionAttributeNames={"#ts": "timestamp"},
            ExpressionAttributeValues={
                ":start": {"S": start_time.isoformat()},
                ":end": {"S": end_time.isoformat()},
            },
        )

        items = response.get("Items", [])
        logger.info(f"Found {len(items)} events in DynamoDB")

        # Fetch full event data from S3
        for item in items:
            event = dynamodb_item_to_dict(item)

            # Try to fetch full event data from S3
            if S3_BUCKET and "s3_key" in event:
                full_event = fetch_event_from_s3(event["s3_key"])
                if full_event:
                    event.update(full_event)

            events.append(event)

        # Sort by timestamp descending
        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    except ClientError as e:
        logger.error(f"Error querying DynamoDB: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error querying events: {e}")
        raise

    return events


def aggregate_events(events: List[Dict]) -> Dict:
    """
    Aggregate events by priority and calculate statistics.

    Args:
        events: List of event dictionaries

    Returns:
        Dictionary with aggregated statistics and grouped events
    """
    logger.info("Aggregating events by priority")

    # Initialize groups
    aggregated = {
        "total": len(events),
        "by_priority": {"HIGH": [], "MEDIUM": [], "LOW": []},
        "statistics": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "compliance_frameworks": set(),
        "event_types": {},
    }

    for event in events:
        priority = event.get("priority", "LOW")
        if priority in aggregated["by_priority"]:
            aggregated["by_priority"][priority].append(event)
            aggregated["statistics"][priority] += 1

        # Collect compliance frameworks
        if "compliance_tags" in event:
            for tag in event["compliance_tags"]:
                aggregated["compliance_frameworks"].add(tag)

        # Count event types
        event_type = event.get("event_type", event.get("event_name", "Unknown"))
        aggregated["event_types"][event_type] = (
            aggregated["event_types"].get(event_type, 0) + 1
        )

    # Convert sets to lists for JSON serialization
    aggregated["compliance_frameworks"] = sorted(
        list(aggregated["compliance_frameworks"])
    )

    logger.info(f"Aggregated {aggregated['total']} events:")
    logger.info(f"  - HIGH: {aggregated['statistics']['HIGH']}")
    logger.info(f"  - MEDIUM: {aggregated['statistics']['MEDIUM']}")
    logger.info(f"  - LOW: {aggregated['statistics']['LOW']}")

    return aggregated


def generate_html_report(aggregated: Dict, time_range: str) -> str:
    """
    Generate HTML email report.

    Args:
        aggregated: Aggregated event data
        time_range: Description of time range

    Returns:
        HTML string
    """
    logger.info("Generating HTML report")

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS GRC Evidence Collector Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px 8px 0 0;
            margin: -30px -30px 30px -30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
        }}
        .header p {{
            margin: 5px 0 0 0;
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        .summary-card.high {{
            border-left-color: #dc3545;
        }}
        .summary-card.medium {{
            border-left-color: #ffc107;
        }}
        .summary-card.low {{
            border-left-color: #28a745;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
        }}
        .summary-card .count {{
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .section h2 {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .event-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .event-item {{
            background: #f8f9fa;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }}
        .event-item.high {{
            border-left-color: #dc3545;
        }}
        .event-item.medium {{
            border-left-color: #ffc107;
        }}
        .event-item.low {{
            border-left-color: #28a745;
        }}
        .event-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .event-name {{
            font-weight: bold;
            font-size: 16px;
        }}
        .event-time {{
            color: #666;
            font-size: 12px;
        }}
        .event-details {{
            margin-top: 10px;
            font-size: 14px;
        }}
        .event-details p {{
            margin: 5px 0;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 5px;
        }}
        .badge.high {{
            background-color: #dc3545;
            color: white;
        }}
        .badge.medium {{
            background-color: #ffc107;
            color: #333;
        }}
        .badge.low {{
            background-color: #28a745;
            color: white;
        }}
        .compliance-tags {{
            margin-top: 10px;
        }}
        .compliance-tag {{
            display: inline-block;
            background-color: #e9ecef;
            color: #495057;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            margin-right: 5px;
            margin-bottom: 5px;
        }}
        .ai-analysis {{
            background-color: #e3f2fd;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
            border-left: 4px solid #2196f3;
        }}
        .ai-analysis h4 {{
            margin: 0 0 10px 0;
            color: #1976d2;
        }}
        .ai-analysis p {{
            margin: 5px 0;
        }}
        .risk-indicator {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
        }}
        .risk-critical {{
            background-color: #dc3545;
            color: white;
        }}
        .risk-high {{
            background-color: #fd7e14;
            color: white;
        }}
        .risk-medium {{
            background-color: #ffc107;
            color: #333;
        }}
        .risk-low {{
            background-color: #28a745;
            color: white;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
            font-size: 12px;
        }}
        .no-events {{
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AWS GRC Evidence Collector Report</h1>
            <p>Compliance and Security Event Summary</p>
            <p><strong>Time Range:</strong> {time_range}</p>
            <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Events</h3>
                <div class="count">{aggregated['total']}</div>
            </div>
            <div class="summary-card high">
                <h3>High Priority</h3>
                <div class="count">{aggregated['statistics']['HIGH']}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Priority</h3>
                <div class="count">{aggregated['statistics']['MEDIUM']}</div>
            </div>
            <div class="summary-card low">
                <h3>Low Priority</h3>
                <div class="count">{aggregated['statistics']['LOW']}</div>
            </div>
        </div>
        
        {_generate_compliance_section(aggregated)}
        
        {_generate_events_section('HIGH', aggregated['by_priority']['HIGH'], 'Critical Security Events')}
        {_generate_events_section('MEDIUM', aggregated['by_priority']['MEDIUM'], 'Medium Priority Events')}
        {_generate_events_section('LOW', aggregated['by_priority']['LOW'], 'Low Priority Events')}
        
        <div class="footer">
            <p>This report was automatically generated by AWS GRC Evidence Collector</p>
            <p>For questions or concerns, contact your security team</p>
        </div>
    </div>
</body>
</html>
"""
    logger.info("HTML report generated")
    return html


def _generate_compliance_section(aggregated: Dict) -> str:
    """Generate compliance frameworks section."""
    if not aggregated["compliance_frameworks"]:
        return ""

    frameworks_html = " ".join(
        [
            f'<span class="compliance-tag">{fw}</span>'
            for fw in aggregated["compliance_frameworks"]
        ]
    )

    return f"""
        <div class="section">
            <h2>📋 Compliance Frameworks</h2>
            <div class="compliance-tags">
                {frameworks_html}
            </div>
        </div>
        """


def _generate_events_section(priority: str, events: List[Dict], title: str) -> str:
    """Generate events section for a specific priority."""
    if not events:
        return f"""
        <div class="section">
            <h2>{title}</h2>
            <div class="no-events">No {priority.lower()} priority events found in this time range.</div>
        </div>
        """

    events_html = ""
    for event in events:
        events_html += _generate_event_item(event, priority)

    return f"""
        <div class="section">
            <h2>{title} ({len(events)})</h2>
            <ul class="event-list">
                {events_html}
            </ul>
        </div>
        """


def _generate_event_item(event: Dict, priority: str) -> str:
    """Generate HTML for a single event item."""
    event_name = event.get("event_name", event.get("event_type", "Unknown"))
    event_time = event.get("event_time", event.get("timestamp", "Unknown"))
    user_identity = event.get("user_identity", {})
    username = user_identity.get(
        "userName", user_identity.get("principalId", "Unknown")
    )
    source_ip = event.get("source_ip", event.get("sourceIPAddress", "N/A"))
    aws_region = event.get("aws_region", event.get("awsRegion", "N/A"))

    # Format timestamp
    try:
        if isinstance(event_time, str):
            dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            formatted_time = str(event_time)
    except:
        formatted_time = str(event_time)

    # Compliance tags
    compliance_tags = event.get("compliance_tags", [])
    tags_html = ""
    if compliance_tags:
        tags_html = (
            '<div class="compliance-tags">'
            + " ".join(
                [
                    f'<span class="compliance-tag">{tag}</span>'
                    for tag in compliance_tags[:5]  # Limit to 5 tags
                ]
            )
            + "</div>"
        )
        if len(compliance_tags) > 5:
            tags_html += f'<p style="font-size: 11px; color: #666; margin-top: 5px;">+ {len(compliance_tags) - 5} more tags</p>'

    # AI Analysis
    ai_html = ""
    ai_analysis = event.get("ai_analysis", {})
    if ai_analysis and ai_analysis.get("ai_analyzed"):
        risk_level = ai_analysis.get("risk_level", "UNKNOWN").upper()
        risk_class = f"risk-{risk_level.lower()}"

        ai_html = f"""
            <div class="ai-analysis">
                <h4>🤖 AI Analysis</h4>
                <p><strong>Summary:</strong> {ai_analysis.get('summary', 'N/A')}</p>
                <p><strong>Risk Level:</strong> <span class="risk-indicator {risk_class}">{risk_level}</span></p>
                <p><strong>Recommended Action:</strong> {ai_analysis.get('recommended_action', 'N/A')}</p>
                {f'<p><strong>Investigation Priority:</strong> {ai_analysis.get("investigation_priority", "N/A")}</p>' if ai_analysis.get('investigation_priority') else ''}
                {f'<p><strong>Model:</strong> {ai_analysis.get("model", "N/A")}</p>' if ai_analysis.get('model') else ''}
            </div>
            """

    return f"""
                <li class="event-item {priority.lower()}">
                    <div class="event-header">
                        <span class="event-name">{event_name}</span>
                        <span class="badge {priority.lower()}">{priority}</span>
                    </div>
                    <div class="event-details">
                        <p><strong>Time:</strong> {formatted_time}</p>
                        <p><strong>User:</strong> {username}</p>
                        <p><strong>Source IP:</strong> {source_ip}</p>
                        <p><strong>Region:</strong> {aws_region}</p>
                        <p><strong>Evidence ID:</strong> {event.get('evidence_id', 'N/A')}</p>
                        {tags_html}
                        {ai_html}
                    </div>
                </li>
        """


def generate_text_report(aggregated: Dict, time_range: str) -> str:
    """
    Generate plain text email report.

    Args:
        aggregated: Aggregated event data
        time_range: Description of time range

    Returns:
        Plain text string
    """
    logger.info("Generating text report")

    lines = [
        "=" * 70,
        "AWS GRC EVIDENCE COLLECTOR REPORT",
        "=" * 70,
        "",
        f"Time Range: {time_range}",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "-" * 70,
        "SUMMARY",
        "-" * 70,
        f"Total Events: {aggregated['total']}",
        f"  - HIGH Priority: {aggregated['statistics']['HIGH']}",
        f"  - MEDIUM Priority: {aggregated['statistics']['MEDIUM']}",
        f"  - LOW Priority: {aggregated['statistics']['LOW']}",
        "",
    ]

    if aggregated["compliance_frameworks"]:
        lines.extend(
            [
                "-" * 70,
                "COMPLIANCE FRAMEWORKS",
                "-" * 70,
            ]
        )
        for fw in aggregated["compliance_frameworks"]:
            lines.append(f"  - {fw}")
        lines.append("")

    # Add events by priority
    for priority in ["HIGH", "MEDIUM", "LOW"]:
        events = aggregated["by_priority"][priority]
        if events:
            lines.extend(
                [
                    "-" * 70,
                    f"{priority} PRIORITY EVENTS ({len(events)})",
                    "-" * 70,
                    "",
                ]
            )

            for i, event in enumerate(events, 1):
                lines.append(
                    f"{i}. {event.get('event_name', event.get('event_type', 'Unknown'))}"
                )
                lines.append(
                    f"   Time: {event.get('event_time', event.get('timestamp', 'Unknown'))}"
                )
                lines.append(
                    f"   User: {event.get('user_identity', {}).get('userName', event.get('user_identity', {}).get('principalId', 'Unknown'))}"
                )
                lines.append(
                    f"   Source IP: {event.get('source_ip', event.get('sourceIPAddress', 'N/A'))}"
                )
                lines.append(
                    f"   Region: {event.get('aws_region', event.get('awsRegion', 'N/A'))}"
                )
                lines.append(f"   Evidence ID: {event.get('evidence_id', 'N/A')}")

                # Compliance tags
                compliance_tags = event.get("compliance_tags", [])
                if compliance_tags:
                    lines.append(
                        f"   Compliance Tags: {', '.join(compliance_tags[:5])}"
                    )
                    if len(compliance_tags) > 5:
                        lines.append(f"   (+ {len(compliance_tags) - 5} more tags)")

                # AI Analysis
                ai_analysis = event.get("ai_analysis", {})
                if ai_analysis and ai_analysis.get("ai_analyzed"):
                    lines.append(f"   AI Analysis:")
                    lines.append(f"     - Summary: {ai_analysis.get('summary', 'N/A')}")
                    lines.append(
                        f"     - Risk Level: {ai_analysis.get('risk_level', 'N/A')}"
                    )
                    lines.append(
                        f"     - Recommended Action: {ai_analysis.get('recommended_action', 'N/A')}"
                    )

                lines.append("")

    lines.extend(
        [
            "=" * 70,
            "END OF REPORT",
            "=" * 70,
            "",
            "This report was automatically generated by AWS GRC Evidence Collector",
            "For questions or concerns, contact your security team",
        ]
    )

    text = "\n".join(lines)
    logger.info("Text report generated")
    return text


def send_email(
    to_email: str,
    from_email: str,
    subject: str,
    html_body: str,
    text_body: str,
) -> bool:
    """
    Send email via AWS SES.

    Args:
        to_email: Recipient email address
        from_email: Sender email address
        subject: Email subject
        html_body: HTML email body
        text_body: Plain text email body

    Returns:
        True if email sent successfully, False otherwise
    """
    logger.info(f"Sending email to {to_email}")

    try:
        response = ses.send_email(
            Source=from_email,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Html": {"Data": html_body, "Charset": "UTF-8"},
                    "Text": {"Data": text_body, "Charset": "UTF-8"},
                },
            },
        )

        message_id = response["MessageId"]
        logger.info(f"Email sent successfully! Message ID: {message_id}")
        return True

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "MessageRejected":
            logger.error(
                "Email rejected. Ensure sender and recipient emails are verified in SES (sandbox mode)."
            )
        elif error_code == "AccessDenied":
            logger.error(
                "Access denied. Ensure your AWS credentials have SES permissions."
            )
        else:
            logger.error(f"Error sending email: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email: {e}")
        return False


def lambda_handler(event, context):
    """
    Lambda handler for scheduled report generation.

    Args:
        event: EventBridge event (not used, but required for Lambda)
        context: Lambda context (not used, but required for Lambda)

    Returns:
        Dictionary with status code and message
    """
    logger.info("Starting scheduled report generation")

    # Validate required environment variables
    if not REPORT_EMAIL:
        logger.error("REPORT_EMAIL environment variable is not set")
        return {
            "statusCode": 500,
            "body": json.dumps(
                {"error": "REPORT_EMAIL environment variable is not set"}
            ),
        }

    if not DYNAMODB_TABLE:
        logger.error("DYNAMODB_TABLE environment variable is not set")
        return {
            "statusCode": 500,
            "body": json.dumps(
                {"error": "DYNAMODB_TABLE environment variable is not set"}
            ),
        }

    try:
        # Determine time range description
        time_range = f"Last {REPORT_DAYS} day(s)"

        # Query events
        events = query_events(days=REPORT_DAYS)

        if not events:
            logger.info("No events found for the specified criteria")
            # Still send a report indicating no events
            aggregated = {
                "total": 0,
                "by_priority": {"HIGH": [], "MEDIUM": [], "LOW": []},
                "statistics": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "compliance_frameworks": [],
                "event_types": {},
            }
        else:
            # Aggregate events
            aggregated = aggregate_events(events)

        # Generate reports
        html_report = generate_html_report(aggregated, time_range)
        text_report = generate_text_report(aggregated, time_range)

        # Create email subject
        high_count = aggregated["statistics"]["HIGH"]
        medium_count = aggregated["statistics"]["MEDIUM"]
        total_count = aggregated["total"]

        if high_count > 0:
            subject = f"🚨 GRC Report: {high_count} HIGH, {medium_count} MEDIUM, {total_count} Total Events"
        else:
            subject = f"📊 GRC Report: {total_count} Events ({time_range})"

        # Send email
        success = send_email(
            REPORT_EMAIL, FROM_EMAIL, subject, html_report, text_report
        )

        if success:
            logger.info("Report generation completed successfully")
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": "Report sent successfully",
                        "total_events": total_count,
                        "high_priority": high_count,
                        "medium_priority": medium_count,
                        "low_priority": aggregated["statistics"]["LOW"],
                    }
                ),
            }
        else:
            logger.error("Failed to send report")
            return {
                "statusCode": 500,
                "body": json.dumps({"error": "Failed to send report"}),
            }

    except Exception as e:
        logger.error(f"Error generating report: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
