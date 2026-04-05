import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.client("dynamodb")
ses = boto3.client("ses")

# Environment variables with defaults
PENDING_EVENTS_TABLE = os.environ.get("PENDING_EVENTS_TABLE")
ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "no-reply@aws-grc.local")
ENABLE_MEDIUM_ALERTS = os.environ.get("ENABLE_MEDIUM_ALERTS", "true").lower() == "true"
ENABLE_LOW_ALERTS = os.environ.get("ENABLE_LOW_ALERTS", "true").lower() == "true"
MEDIUM_BATCH_SIZE = int(os.environ.get("MEDIUM_BATCH_SIZE", "10"))
LOW_BATCH_SIZE = int(os.environ.get("LOW_BATCH_SIZE", "10"))
MEDIUM_BATCH_INTERVAL = int(os.environ.get("MEDIUM_BATCH_INTERVAL", "15"))
LOW_BATCH_INTERVAL = int(os.environ.get("LOW_BATCH_INTERVAL", "60"))
MAX_EMAILS_PER_HOUR = int(os.environ.get("MAX_EMAILS_PER_HOUR", "10"))
USE_BATCHING = os.environ.get("USE_BATCHING", "true").lower() == "true"

# Rate limiting tracking table
RATE_LIMIT_TABLE = os.environ.get("RATE_LIMIT_TABLE")


def dynamodb_item_to_dict(item: Dict) -> Dict:
    """Convert DynamoDB item format to regular Python dict."""
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


def check_rate_limit() -> bool:
    """Check if we can send an email based on rate limiting."""
    if not RATE_LIMIT_TABLE or MAX_EMAILS_PER_HOUR <= 0:
        return True  # No rate limiting

    try:
        now = datetime.utcnow()
        hour_start = now.replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)

        # Get current count for this hour
        response = dynamodb.get_item(
            TableName=RATE_LIMIT_TABLE, Key={"hour": {"S": hour_start.isoformat()}}
        )

        if "Item" in response:
            current_count = int(response["Item"]["count"]["N"])
        else:
            current_count = 0

        if current_count >= MAX_EMAILS_PER_HOUR:
            logger.warning(
                f"Rate limit exceeded: {current_count} emails sent this hour (max: {MAX_EMAILS_PER_HOUR})"
            )
            return False

        # Increment count
        dynamodb.put_item(
            TableName=RATE_LIMIT_TABLE,
            Item={
                "hour": {"S": hour_start.isoformat()},
                "count": {"N": str(current_count + 1)},
                "ttl": {"N": str(int(hour_end.timestamp()))},
            },
        )

        return True
    except ClientError as e:
        logger.error(f"Error checking rate limit: {e}")
        return True  # Fail open - allow email if rate limit check fails


def query_pending_events(
    priority: str, batch_size: int, batch_interval_minutes: int
) -> List[Dict]:
    """Query pending events for a given priority."""
    if not PENDING_EVENTS_TABLE:
        logger.error("PENDING_EVENTS_TABLE environment variable not set")
        return []

    try:
        now = datetime.utcnow()
        cutoff_time = now - timedelta(minutes=batch_interval_minutes)

        # Query for pending events of this priority
        response = dynamodb.query(
            TableName=PENDING_EVENTS_TABLE,
            IndexName="PriorityTimestampIndex",
            KeyConditionExpression="priority = :priority AND timestamp <= :cutoff",
            FilterExpression="processed = :processed",
            ExpressionAttributeValues={
                ":priority": {"S": priority},
                ":cutoff": {"S": cutoff_time.isoformat()},
                ":processed": {"BOOL": False},
            },
            Limit=batch_size,
            ConsistentRead=False,
        )

        items = response.get("Items", [])
        events = [dynamodb_item_to_dict(item) for item in items]
        logger.info(f"Found {len(events)} pending {priority} priority events")
        return events
    except ClientError as e:
        logger.error(f"Error querying pending events for {priority} priority: {e}")
        return []


def mark_events_processed(event_ids: List[str]) -> int:
    """Mark events as processed."""
    if not PENDING_EVENTS_TABLE or not event_ids:
        return 0

    marked_count = 0
    for event_id in event_ids:
        try:
            dynamodb.update_item(
                TableName=PENDING_EVENTS_TABLE,
                Key={"event_id": {"S": event_id}},
                UpdateExpression="SET processed = :processed, processed_at = :processed_at",
                ExpressionAttributeValues={
                    ":processed": {"BOOL": True},
                    ":processed_at": {"S": datetime.utcnow().isoformat()},
                },
            )
            marked_count += 1
        except ClientError as e:
            logger.error(f"Error marking event {event_id} as processed: {e}")

    return marked_count


def generate_batch_email(events: List[Dict], priority: str) -> tuple[str, str]:
    """Generate HTML and text email body for batched events."""
    event_count = len(events)

    # Generate HTML
    events_html = ""
    for i, event in enumerate(events, 1):
        event_name = event.get("event_name", "Unknown")
        event_time = event.get("event_time", event.get("timestamp", "Unknown"))
        user_identity = event.get("user_identity", {})
        username = user_identity.get(
            "userName", user_identity.get("principalId", "Unknown")
        )
        source_ip = event.get("source_ip", event.get("sourceIPAddress", "N/A"))
        aws_region = event.get("aws_region", event.get("awsRegion", "N/A"))
        evidence_id = event.get("evidence_id", "N/A")
        compliance_tags = event.get("compliance_tags", [])

        # AI analysis if available
        ai_summary = ""
        if "ai_analysis" in event and event["ai_analysis"].get("ai_analyzed"):
            ai = event["ai_analysis"]
            ai_summary = f"""
            <div style="background:#f0f4ff;padding:10px;margin:5px 0;border-radius:4px;border-left:3px solid #667eea;">
                <strong>🤖 AI Analysis:</strong><br>
                <em>{ai.get('summary', 'N/A')}</em><br>
                <small>Risk Level: {ai.get('risk_level', 'N/A')} | Recommended: {ai.get('recommended_action', 'N/A')}</small>
            </div>
            """

        tags_html = ", ".join(compliance_tags) if compliance_tags else "N/A"

        events_html += f"""
        <div style="background:#f8f9fa;padding:15px;margin:10px 0;border-radius:4px;border-left:4px solid {'#dc3545' if priority == 'HIGH' else '#ffc107' if priority == 'MEDIUM' else '#28a745'};">
            <strong>{i}. {event_name}</strong><br>
            <small>Time: {event_time} | User: {username} | IP: {source_ip} | Region: {aws_region}</small><br>
            <small>Compliance Tags: {tags_html}</small><br>
            <small>Evidence ID: {evidence_id}</small>
            {ai_summary}
        </div>
        """

    priority_color = (
        "#dc3545"
        if priority == "HIGH"
        else "#ffc107" if priority == "MEDIUM" else "#28a745"
    )
    priority_emoji = (
        "🔴" if priority == "HIGH" else "🟡" if priority == "MEDIUM" else "🟢"
    )

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px;}}
            .header {{background: {priority_color}; color: white; padding: 20px; border-radius: 8px; text-align: center;}}
            .summary {{background: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 8px; text-align: center;}}
            .event-list {{margin: 20px 0;}}
            .footer {{text-align: center; color: #666; margin-top: 30px; font-size: 12px;}}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>{priority_emoji} {priority} Priority GRC Alert</h1>
            <p>Batched Alert - {event_count} Events</p>
            <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total Events:</strong> {event_count}</p>
            <p><strong>Priority:</strong> {priority}</p>
            <p><strong>Alert Type:</strong> Batched (aggregated)</p>
        </div>
        
        <div class="event-list">
            <h2>Events</h2>
            {events_html}
        </div>
        
        <div class="footer">
            <p>Generated by AWS GRC Evidence Collector</p>
            <p>This is an automated alert. Please review the events and take appropriate action.</p>
        </div>
    </body>
    </html>
    """

    # Generate text version
    lines = [
        "=" * 70,
        f"{priority} PRIORITY GRC ALERT",
        "=" * 70,
        f"Batched Alert - {event_count} Events",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "-" * 70,
        "SUMMARY",
        "-" * 70,
        f"Total Events: {event_count}",
        f"Priority: {priority}",
        f"Alert Type: Batched (aggregated)",
        "",
        "-" * 70,
        "EVENTS",
        "-" * 70,
        "",
    ]

    for i, event in enumerate(events, 1):
        event_name = event.get("event_name", "Unknown")
        event_time = event.get("event_time", event.get("timestamp", "Unknown"))
        user_identity = event.get("user_identity", {})
        username = user_identity.get(
            "userName", user_identity.get("principalId", "Unknown")
        )
        source_ip = event.get("source_ip", event.get("sourceIPAddress", "N/A"))
        aws_region = event.get("aws_region", event.get("awsRegion", "N/A"))
        evidence_id = event.get("evidence_id", "N/A")
        compliance_tags = event.get("compliance_tags", [])

        lines.append(f"{i}. {event_name}")
        lines.append(f"   Time: {event_time}")
        lines.append(f"   User: {username}")
        lines.append(f"   Source IP: {source_ip}")
        lines.append(f"   Region: {aws_region}")
        lines.append(
            f"   Compliance Tags: {', '.join(compliance_tags) if compliance_tags else 'N/A'}"
        )
        lines.append(f"   Evidence ID: {evidence_id}")

        if "ai_analysis" in event and event["ai_analysis"].get("ai_analyzed"):
            ai = event["ai_analysis"]
            lines.append(f"   AI Analysis: {ai.get('summary', 'N/A')}")
            lines.append(f"   Risk Level: {ai.get('risk_level', 'N/A')}")
            lines.append(
                f"   Recommended Action: {ai.get('recommended_action', 'N/A')}"
            )

        lines.append("")

    lines.extend(
        [
            "=" * 70,
            "END OF ALERT",
            "=" * 70,
            "Generated by AWS GRC Evidence Collector",
            "This is an automated alert. Please review the events and take appropriate action.",
        ]
    )

    text_body = "\n".join(lines)

    return html_body, text_body


def send_batch_email(events: List[Dict], priority: str) -> bool:
    """Send batch email for events."""
    if not ALERT_EMAIL:
        logger.error("ALERT_EMAIL environment variable not set")
        return False

    if not events:
        logger.warning("No events to send in batch")
        return False

    # Check rate limit
    if not check_rate_limit():
        logger.warning("Rate limit exceeded, skipping batch email")
        return False

    try:
        html_body, text_body = generate_batch_email(events, priority)

        event_count = len(events)
        subject = f"{'🔴' if priority == 'HIGH' else '🟡' if priority == 'MEDIUM' else '🟢'} {priority} Priority GRC Alert: {event_count} Events"

        response = ses.send_email(
            Source=FROM_EMAIL,
            Destination={"ToAddresses": [ALERT_EMAIL]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Html": {"Data": html_body, "Charset": "UTF-8"},
                    "Text": {"Data": text_body, "Charset": "UTF-8"},
                },
            },
        )

        message_id = response.get("MessageId")
        logger.info(
            f"Batch email sent successfully! Message ID: {message_id}, Events: {event_count}"
        )
        return True
    except ClientError as e:
        logger.error(f"Error sending batch email: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending batch email: {e}")
        return False


def process_priority_batch(priority: str, batch_size: int, batch_interval: int) -> int:
    """Process batch for a specific priority."""
    logger.info(
        f"Processing {priority} priority batch (size: {batch_size}, interval: {batch_interval} minutes)"
    )

    # Query pending events
    events = query_pending_events(priority, batch_size, batch_interval)

    if not events:
        logger.info(f"No pending {priority} priority events to batch")
        return 0

    # Send batch email
    success = send_batch_email(events, priority)

    if success:
        # Mark events as processed
        event_ids = [event["event_id"] for event in events]
        marked_count = mark_events_processed(event_ids)
        logger.info(f"Marked {marked_count} {priority} priority events as processed")
        return marked_count
    else:
        logger.warning(f"Failed to send batch email for {priority} priority events")
        return 0


def lambda_handler(event, context):
    """Main Lambda handler for batch processing."""
    logger.info("Starting batch processor")

    if not USE_BATCHING:
        logger.info("Batching is disabled, exiting")
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Batching is disabled"}),
        }

    if not ALERT_EMAIL:
        logger.error("ALERT_EMAIL environment variable not set, cannot send emails")
        return {"statusCode": 500, "body": json.dumps({"error": "ALERT_EMAIL not set"})}

    total_processed = 0

    # Process MEDIUM priority events
    if ENABLE_MEDIUM_ALERTS:
        logger.info("Processing MEDIUM priority events")
        medium_processed = process_priority_batch(
            "MEDIUM", MEDIUM_BATCH_SIZE, MEDIUM_BATCH_INTERVAL
        )
        total_processed += medium_processed
    else:
        logger.info("MEDIUM priority alerts are disabled")

    # Process LOW priority events
    if ENABLE_LOW_ALERTS:
        logger.info("Processing LOW priority events")
        low_processed = process_priority_batch(
            "LOW", LOW_BATCH_SIZE, LOW_BATCH_INTERVAL
        )
        total_processed += low_processed
    else:
        logger.info("LOW priority alerts are disabled")

    logger.info(
        f"Batch processing completed. Total events processed: {total_processed}"
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Batch processing completed",
                "total_processed": total_processed,
                "medium_enabled": ENABLE_MEDIUM_ALERTS,
                "low_enabled": ENABLE_LOW_ALERTS,
            }
        ),
    }
