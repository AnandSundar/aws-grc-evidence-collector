#!/usr/bin/env python3
"""
AWS GRC Evidence Collector - On-Demand Report Generator

This script generates and sends comprehensive email reports of GRC events
collected by the AWS GRC Evidence Collector system.

Usage:
    python generate_report.py --email recipient@example.com --days 7 --profile my-profile
    python generate_report.py --email recipient@example.com --start-date 2024-01-01 --end-date 2024-01-31
    python generate_report.py --email recipient@example.com --priority HIGH --days 1
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

# Color codes for console output
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def print_success(msg: str):
    """Print success message in green."""
    print(f"{GREEN}✅ {msg}{RESET}")


def print_error(msg: str):
    """Print error message in red."""
    print(f"{RED}❌ {msg}{RESET}")


def print_info(msg: str):
    """Print info message in blue."""
    print(f"{BLUE}ℹ️  {msg}{RESET}")


def print_warning(msg: str):
    """Print warning message in yellow."""
    print(f"{YELLOW}⚠️  {msg}{RESET}")


class ReportGenerator:
    """Handles report generation and email sending for GRC events."""

    def __init__(
        self, profile: Optional[str] = None, config_path: str = "grc_config.json"
    ):
        """
        Initialize the report generator.

        Args:
            profile: AWS CLI profile name
            config_path: Path to grc_config.json file
        """
        self.profile = profile
        self.config_path = config_path
        self.config = self._load_config()

        # Initialize AWS clients
        session = boto3.Session(profile_name=profile)
        self.region = session.region_name or "us-east-1"
        self.dynamodb = session.client("dynamodb", region_name=self.region)
        self.s3 = session.client("s3", region_name=self.region)
        self.ses = session.client("ses", region_name=self.region)

        # Get table name from config
        self.table_name = self.config.get("MetadataTable") or self.config.get(
            "dynamodb_table"
        )
        if not self.table_name:
            raise ValueError("DynamoDB table name not found in configuration")

        # Get bucket name from config
        self.bucket_name = self.config.get("EvidenceBucket")
        if not self.bucket_name:
            print_warning(
                "S3 bucket name not found in configuration. Full event data will not be fetched."
            )

    def _load_config(self) -> Dict:
        """
        Load configuration from grc_config.json.

        Returns:
            Configuration dictionary
        """
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                config = json.load(f)
                print_success(f"Loaded configuration from {self.config_path}")
                return config
        else:
            print_warning(f"Configuration file {self.config_path} not found")
            return {}

    def query_events(
        self,
        days: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query DynamoDB for events based on filters.

        Args:
            days: Number of days to look back (exclusive with start_date/end_date)
            start_date: Start date in YYYY-MM-DD format
            end_date: End date in YYYY-MM-DD format
            priority: Filter by priority (HIGH, MEDIUM, LOW)

        Returns:
            List of event dictionaries
        """
        print_info("Querying DynamoDB for events...")

        # Calculate time range
        if days:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
        elif start_date and end_date:
            start_time = datetime.strptime(start_date, "%Y-%m-%d")
            end_time = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
        else:
            # Default to last 24 hours
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)

        print_info(f"Time range: {start_time.isoformat()} to {end_time.isoformat()}")

        events = []

        try:
            # Query by priority if specified
            if priority:
                response = self.dynamodb.query(
                    TableName=self.table_name,
                    IndexName="PriorityIndex",
                    KeyConditionExpression="priority = :priority",
                    FilterExpression="#ts BETWEEN :start AND :end",
                    ExpressionAttributeNames={"#ts": "timestamp"},
                    ExpressionAttributeValues={
                        ":priority": {"S": priority},
                        ":start": {"S": start_time.isoformat()},
                        ":end": {"S": end_time.isoformat()},
                    },
                )
            else:
                # Scan all events and filter by time
                response = self.dynamodb.scan(
                    TableName=self.table_name,
                    FilterExpression="#ts BETWEEN :start AND :end",
                    ExpressionAttributeNames={"#ts": "timestamp"},
                    ExpressionAttributeValues={
                        ":start": {"S": start_time.isoformat()},
                        ":end": {"S": end_time.isoformat()},
                    },
                )

            items = response.get("Items", [])
            print_success(f"Found {len(items)} events in DynamoDB")

            # Fetch full event data from S3
            for item in items:
                event = self._dynamodb_item_to_dict(item)

                # Try to fetch full event data from S3
                if self.bucket_name and "s3_key" in event:
                    full_event = self._fetch_event_from_s3(event["s3_key"])
                    if full_event:
                        event.update(full_event)

                events.append(event)

            # Sort by timestamp descending
            events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        except ClientError as e:
            print_error(f"Error querying DynamoDB: {e}")
            raise
        except Exception as e:
            print_error(f"Unexpected error querying events: {e}")
            raise

        return events

    def _dynamodb_item_to_dict(self, item: Dict) -> Dict:
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
                result[key] = self._dynamodb_item_to_dict(value["M"])
            elif "L" in value:
                result[key] = [
                    (
                        self._dynamodb_item_to_dict(v)
                        if "M" in v
                        else v.get("S", v.get("N", v))
                    )
                    for v in value["L"]
                ]
            elif "SS" in value:
                result[key] = value["SS"]
            elif "NS" in value:
                result[key] = [int(n) for n in value["NS"]]
        return result

    def _fetch_event_from_s3(self, s3_key: str) -> Optional[Dict]:
        """
        Fetch full event data from S3.

        Args:
            s3_key: S3 key for the event

        Returns:
            Event dictionary or None if not found
        """
        try:
            response = self.s3.get_object(Bucket=self.bucket_name, Key=s3_key)
            event_data = json.loads(response["Body"].read().decode("utf-8"))
            return event_data
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                print_warning(f"Event not found in S3: {s3_key}")
            else:
                print_warning(f"Error fetching event from S3: {e}")
            return None
        except Exception as e:
            print_warning(f"Unexpected error fetching event from S3: {e}")
            return None

    def aggregate_events(self, events: List[Dict]) -> Dict:
        """
        Aggregate events by priority and calculate statistics.

        Args:
            events: List of event dictionaries

        Returns:
            Dictionary with aggregated statistics and grouped events
        """
        print_info("Aggregating events by priority...")

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

        print_success(f"Aggregated {aggregated['total']} events:")
        print_info(f"  - HIGH: {aggregated['statistics']['HIGH']}")
        print_info(f"  - MEDIUM: {aggregated['statistics']['MEDIUM']}")
        print_info(f"  - LOW: {aggregated['statistics']['LOW']}")

        return aggregated

    def generate_html_report(self, aggregated: Dict, time_range: str) -> str:
        """
        Generate HTML email report.

        Args:
            aggregated: Aggregated event data
            time_range: Description of time range

        Returns:
            HTML string
        """
        print_info("Generating HTML report...")

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
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
            color: #495057;
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
        
        {self._generate_compliance_section(aggregated)}
        
        {self._generate_events_section('HIGH', aggregated['by_priority']['HIGH'], 'Critical Security Events')}
        {self._generate_events_section('MEDIUM', aggregated['by_priority']['MEDIUM'], 'Medium Priority Events')}
        {self._generate_events_section('LOW', aggregated['by_priority']['LOW'], 'Low Priority Events')}
        
        <div class="footer">
            <p>This report was automatically generated by AWS GRC Evidence Collector</p>
            <p>For questions or concerns, contact your security team</p>
        </div>
    </div>
</body>
</html>
"""
        print_success("HTML report generated")
        return html

    def _generate_compliance_section(self, aggregated: Dict) -> str:
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

    def _generate_events_section(
        self, priority: str, events: List[Dict], title: str
    ) -> str:
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
            events_html += self._generate_event_item(event, priority)

        return f"""
        <div class="section">
            <h2>{title} ({len(events)})</h2>
            <ul class="event-list">
                {events_html}
            </ul>
        </div>
        """

    def _generate_event_item(self, event: Dict, priority: str) -> str:
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

    def generate_text_report(self, aggregated: Dict, time_range: str) -> str:
        """
        Generate plain text email report.

        Args:
            aggregated: Aggregated event data
            time_range: Description of time range

        Returns:
            Plain text string
        """
        print_info("Generating text report...")

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
                        lines.append(
                            f"     - Summary: {ai_analysis.get('summary', 'N/A')}"
                        )
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
        print_success("Text report generated")
        return text

    def send_email(
        self,
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
        print_info(f"Sending email to {to_email}...")

        try:
            # Verify email addresses are verified in SES (for sandbox mode)
            # In production, you would move out of sandbox

            response = self.ses.send_email(
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
            print_success(f"Email sent successfully! Message ID: {message_id}")
            return True

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "MessageRejected":
                print_error(
                    "Email rejected. Ensure sender and recipient emails are verified in SES (sandbox mode)."
                )
            elif error_code == "AccessDenied":
                print_error(
                    "Access denied. Ensure your AWS credentials have SES permissions."
                )
            else:
                print_error(f"Error sending email: {e}")
            return False
        except Exception as e:
            print_error(f"Unexpected error sending email: {e}")
            return False

    def generate_and_send_report(
        self,
        to_email: str,
        from_email: Optional[str] = None,
        days: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> bool:
        """
        Generate and send report.

        Args:
            to_email: Recipient email address
            from_email: Sender email address (default: no-reply@aws-grc.local)
            days: Number of days to look back
            start_date: Start date in YYYY-MM-DD format
            end_date: End date in YYYY-MM-DD format
            priority: Filter by priority (HIGH, MEDIUM, LOW)

        Returns:
            True if report sent successfully, False otherwise
        """
        try:
            # Set default sender email
            if not from_email:
                from_email = "no-reply@aws-grc.local"

            # Determine time range description
            if days:
                time_range = f"Last {days} day(s)"
            elif start_date and end_date:
                time_range = f"{start_date} to {end_date}"
            else:
                time_range = "Last 24 hours"

            if priority:
                time_range += f" ({priority} priority only)"

            print(f"\n{BOLD}{'='*70}{RESET}")
            print(f"{BOLD}AWS GRC EVIDENCE COLLECTOR - REPORT GENERATOR{RESET}")
            print(f"{BOLD}{'='*70}{RESET}\n")

            # Query events
            events = self.query_events(days, start_date, end_date, priority)

            if not events:
                print_warning("No events found for the specified criteria.")
                return False

            # Aggregate events
            aggregated = self.aggregate_events(events)

            # Generate reports
            html_report = self.generate_html_report(aggregated, time_range)
            text_report = self.generate_text_report(aggregated, time_range)

            # Create email subject
            high_count = aggregated["statistics"]["HIGH"]
            medium_count = aggregated["statistics"]["MEDIUM"]
            total_count = aggregated["total"]

            if high_count > 0:
                subject = f"🚨 GRC Report: {high_count} HIGH, {medium_count} MEDIUM, {total_count} Total Events"
            else:
                subject = f"📊 GRC Report: {total_count} Events ({time_range})"

            # Send email
            success = self.send_email(
                to_email, from_email, subject, html_report, text_report
            )

            if success:
                print(f"\n{BOLD}{'='*70}{RESET}")
                print_success("Report generation completed successfully!")
                print(f"{BOLD}{'='*70}{RESET}\n")
            else:
                print_error("Failed to send report.")

            return success

        except Exception as e:
            print_error(f"Error generating report: {e}")
            logger.exception("Report generation failed")
            return False


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Generate and send AWS GRC Evidence Collector reports via email",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report for last 7 days
  python generate_report.py --email user@example.com --days 7 --profile my-profile
  
  # Generate report for custom date range
  python generate_report.py --email user@example.com --start-date 2024-01-01 --end-date 2024-01-31
  
  # Generate report for HIGH priority events only
  python generate_report.py --email user@example.com --priority HIGH --days 1
  
  # Generate report with custom sender
  python generate_report.py --email user@example.com --from-email reports@company.com --days 7
        """,
    )

    parser.add_argument("--email", required=True, help="Recipient email address")

    parser.add_argument(
        "--from-email",
        default=None,
        help="Sender email address (default: no-reply@aws-grc.local)",
    )

    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Number of days to look back (exclusive with --start-date/--end-date)",
    )

    parser.add_argument(
        "--start-date",
        default=None,
        help="Start date in YYYY-MM-DD format (exclusive with --days)",
    )

    parser.add_argument(
        "--end-date",
        default=None,
        help="End date in YYYY-MM-DD format (exclusive with --days)",
    )

    parser.add_argument(
        "--priority",
        choices=["HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Filter by priority level",
    )

    parser.add_argument("--profile", default=None, help="AWS CLI profile name")

    parser.add_argument(
        "--config",
        default="grc_config.json",
        help="Path to grc_config.json file (default: grc_config.json)",
    )

    args = parser.parse_args()

    # Validate arguments
    if args.days and (args.start_date or args.end_date):
        print_error("Cannot use --days with --start-date or --end-date")
        sys.exit(1)

    if (args.start_date and not args.end_date) or (
        args.end_date and not args.start_date
    ):
        print_error("Both --start-date and --end-date must be provided together")
        sys.exit(1)

    # Validate date formats
    if args.start_date:
        try:
            datetime.strptime(args.start_date, "%Y-%m-%d")
            datetime.strptime(args.end_date, "%Y-%m-%d")
        except ValueError:
            print_error("Dates must be in YYYY-MM-DD format")
            sys.exit(1)

    # Create report generator and generate report
    try:
        generator = ReportGenerator(profile=args.profile, config_path=args.config)
        success = generator.generate_and_send_report(
            to_email=args.email,
            from_email=args.from_email,
            days=args.days,
            start_date=args.start_date,
            end_date=args.end_date,
            priority=args.priority,
        )

        sys.exit(0 if success else 1)

    except ValueError as e:
        print_error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        logger.exception("Unexpected error in main")
        sys.exit(1)


if __name__ == "__main__":
    main()
