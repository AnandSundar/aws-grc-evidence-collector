#!/usr/bin/env python3
"""
GRC Evidence Platform v2.0 - Report Generator Script

This script provides a CLI tool to generate audit reports on demand.
It supports multiple report types (scorecard, full, executive), time periods,
and output formats (JSON, PDF, CSV, HTML).

Usage:
    python scripts/generate_report.py --type scorecard --period 24h --output-format pdf

Author: GRC Platform Team
Version: 2.0
"""

import argparse
import csv
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("grc_report_generator.log"),
    ],
)
logger = logging.getLogger(__name__)


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_colored(message: str, color: str = Colors.RESET) -> None:
    """
    Print a colored message to the terminal.

    Args:
        message: The message to print
        color: ANSI color code to use
    """
    print(f"{color}{message}{Colors.RESET}")


def print_success(message: str) -> None:
    """Print a success message in green."""
    print_colored(f"[OK] {message}", Colors.GREEN)


def print_error(message: str) -> None:
    """Print an error message in red."""
    print_colored(f"[FAIL] {message}", Colors.RED)


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    print_colored(f"[WARN] {message}", Colors.YELLOW)


def print_info(message: str) -> None:
    """Print an info message in cyan."""
    print_colored(f"[INFO] {message}", Colors.CYAN)


def print_header(message: str) -> None:
    """Print a header message in bold blue."""
    print_colored(f"\n{'=' * 70}", Colors.BLUE)
    print_colored(f"{message}", Colors.BOLD + Colors.BLUE)
    print_colored(f"{'=' * 70}\n", Colors.BLUE)


class ReportGenerator:
    """
    Main class for generating GRC audit reports.

    This class provides methods to query evidence from DynamoDB,
    generate reports in various formats, and save or print the results.
    """

    CONFIG_FILE = "grc_config.json"

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize the Report Generator.

        Args:
            region: AWS region to query (default: from environment or us-east-1)
            profile: AWS profile name to use (default: default)
        """
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.session = boto3.Session(region_name=self.region, profile_name=profile)

        # Initialize AWS clients
        self.dynamodb_client = self.session.client("dynamodb")
        self.s3_client = self.session.client("s3")
        self.sts_client = self.session.client("sts")

        # Get account ID
        self.account_id = self._get_account_id()

        # Load configuration
        self.config = self._load_config()

        # Get resource names
        self.metadata_table = self._get_metadata_table()
        self.scorecard_table = self._get_scorecard_table()
        self.remediation_log_table = self._get_remediation_log_table()
        self.reports_bucket = self._get_reports_bucket()

        print_header(f"GRC Evidence Platform v2.0 - Report Generator")
        print_info(f"Account ID: {self.account_id}")
        print_info(f"Region: {self.region}")

    def _get_account_id(self) -> str:
        """
        Get the current AWS account ID.

        Returns:
            AWS account ID as string
        """
        try:
            response = self.sts_client.get_caller_identity()
            return response["Account"]
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to get account ID: {e}")
            raise

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from grc_config.json if it exists.

        Returns:
            Configuration dictionary
        """
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, "r") as f:
                    config = json.load(f)
                return config
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")

        return {}

    def _get_metadata_table(self) -> str:
        """Get the metadata DynamoDB table name."""
        resources = self.config.get("resources", {})
        for key, value in resources.items():
            if "dynamodb_table_metadata" in key:
                return value.get("name", "grc-evidence-platform-metadata")
        return "grc-evidence-platform-metadata"

    def _get_scorecard_table(self) -> str:
        """Get the scorecard DynamoDB table name."""
        resources = self.config.get("resources", {})
        for key, value in resources.items():
            if "dynamodb_table_scorecards" in key:
                return value.get("name", "grc-evidence-platform-scorecards")
        return "grc-evidence-platform-scorecards"

    def _get_remediation_log_table(self) -> str:
        """Get the remediation log DynamoDB table name."""
        resources = self.config.get("resources", {})
        for key, value in resources.items():
            if "dynamodb_table_remediation-log" in key:
                return value.get("name", "grc-evidence-platform-remediation-log")
        return "grc-evidence-platform-remediation-log"

    def _get_reports_bucket(self) -> str:
        """Get the reports S3 bucket name."""
        resources = self.config.get("resources", {})
        for key, value in resources.items():
            if "s3_bucket_reports" in key:
                return value.get(
                    "name", f"grc-evidence-platform-reports-{self.account_id}"
                )
        return f"grc-evidence-platform-reports-{self.account_id}"

    def _get_time_range(self, period: str) -> Tuple[datetime, datetime]:
        """
        Get start and end time for a given period.

        Args:
            period: Time period (24h, 7d, 30d, or custom in format YYYY-MM-DD:YYYY-MM-DD)

        Returns:
            Tuple of (start_time, end_time) as datetime objects
        """
        end_time = datetime.now()

        if period == "24h":
            start_time = end_time - timedelta(hours=24)
        elif period == "7d":
            start_time = end_time - timedelta(days=7)
        elif period == "30d":
            start_time = end_time - timedelta(days=30)
        elif ":" in period:
            # Custom format: YYYY-MM-DD:YYYY-MM-DD
            try:
                start_str, end_str = period.split(":")
                start_time = datetime.strptime(start_str, "%Y-%m-%d")
                end_time = datetime.strptime(end_str, "%Y-%m-%d")
            except ValueError as e:
                raise ValueError(
                    f"Invalid custom period format. Use YYYY-MM-DD:YYYY-MM-DD: {e}"
                )
        else:
            raise ValueError(
                f"Invalid period: {period}. Use 24h, 7d, 30d, or custom YYYY-MM-DD:YYYY-MM-DD"
            )

        return start_time, end_time

    def _query_evidence(
        self, start_time: datetime, end_time: datetime, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Query evidence from DynamoDB for the specified time range.

        Args:
            start_time: Start of time range
            end_time: End of time range
            severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            List of evidence records
        """
        evidence = []

        try:
            # Query using pagination
            paginator = self.dynamodb_client.get_paginator("scan")

            filter_expression = None
            expression_values = {}

            # Add time range filter (timestamp is a reserved keyword, need to escape)
            filter_expression = "#ts BETWEEN :start AND :end"
            expression_attribute_names = {"#ts": "timestamp"}
            expression_values[":start"] = {"S": start_time.isoformat()}
            expression_values[":end"] = {"S": end_time.isoformat()}

            # Add severity filter if specified
            if severity:
                filter_expression += " AND severity = :severity"
                expression_values[":severity"] = {"S": severity.upper()}

            page_iterator = paginator.paginate(
                TableName=self.metadata_table,
                FilterExpression=filter_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_values,
            )

            for page in page_iterator:
                for item in page.get("Items", []):
                    # Convert DynamoDB item to dictionary
                    record = {}
                    for key, value in item.items():
                        if "S" in value:
                            record[key] = value["S"]
                        elif "N" in value:
                            record[key] = int(value["N"])
                        elif "BOOL" in value:
                            record[key] = value["BOOL"]
                        elif "M" in value:
                            record[key] = value["M"]
                        elif "L" in value:
                            record[key] = value["L"]
                        elif "NULL" in value:
                            record[key] = None
                        else:
                            record[key] = value

                    # Parse record_data if present
                    if "record_data" in record:
                        try:
                            record["data"] = json.loads(record["record_data"])
                        except json.JSONDecodeError:
                            pass

                    evidence.append(record)

            logger.info(f"Queried {len(evidence)} evidence records from DynamoDB")

        except Exception as e:
            logger.error(f"Failed to query evidence: {e}")
            raise

        return evidence

    def _query_scorecards(
        self, start_time: datetime, end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Query scorecards from DynamoDB for the specified time range.

        Args:
            start_time: Start of time range
            end_time: End of time range

        Returns:
            List of scorecard records
        """
        scorecards = []

        try:
            paginator = self.dynamodb_client.get_paginator("scan")

            page_iterator = paginator.paginate(
                TableName=self.scorecard_table,
                FilterExpression="#ts BETWEEN :start AND :end",
                ExpressionAttributeNames={"#ts": "timestamp"},
                ExpressionAttributeValues={
                    ":start": {"S": start_time.isoformat()},
                    ":end": {"S": end_time.isoformat()},
                },
            )

            for page in page_iterator:
                for item in page.get("Items", []):
                    record = {}
                    for key, value in item.items():
                        if "S" in value:
                            record[key] = value["S"]
                        elif "N" in value:
                            record[key] = float(value["N"])
                        elif "BOOL" in value:
                            record[key] = value["BOOL"]
                        elif "M" in value:
                            record[key] = value["M"]

                    scorecards.append(record)

            logger.info(f"Queried {len(scorecards)} scorecard records from DynamoDB")

        except Exception as e:
            logger.error(f"Failed to query scorecards: {e}")
            raise

        return scorecards

    def _generate_scorecard_report(
        self, evidence: List[Dict[str, Any]], scorecards: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a compliance scorecard report.

        Args:
            evidence: List of evidence records
            scorecards: List of scorecard records

        Returns:
            Scorecard report dictionary
        """
        # Calculate statistics
        total_findings = len(evidence)
        critical_count = sum(1 for e in evidence if e.get("severity") == "CRITICAL")
        high_count = sum(1 for e in evidence if e.get("severity") == "HIGH")
        medium_count = sum(1 for e in evidence if e.get("severity") == "MEDIUM")
        low_count = sum(1 for e in evidence if e.get("severity") == "LOW")

        # Group by resource type
        by_resource_type: Dict[str, Dict[str, int]] = {}
        for e in evidence:
            resource_type = e.get("resource_type", "Unknown")
            if resource_type not in by_resource_type:
                by_resource_type[resource_type] = {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                }

            severity = e.get("severity", "LOW")
            if severity in by_resource_type[resource_type]:
                by_resource_type[resource_type][severity] += 1

        # Calculate compliance scores
        if scorecards:
            latest_scorecard = max(scorecards, key=lambda s: s.get("timestamp", ""))
            compliance_score = latest_scorecard.get("score", 0)
            compliance_standard = latest_scorecard.get("compliance_standard", "N/A")
        else:
            # Calculate score from findings
            if total_findings == 0:
                compliance_score = 100.0
            else:
                # Weighted score: CRITICAL=0, HIGH=25, MEDIUM=50, LOW=75
                weighted_sum = (
                    critical_count * 0
                    + high_count * 25
                    + medium_count * 50
                    + low_count * 75
                )
                compliance_score = weighted_sum / total_findings
            compliance_standard = "Calculated"

        # Determine risk level
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 10:
            risk_level = "HIGH"
        elif high_count > 0:
            risk_level = "HIGH"
        elif medium_count > 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        report = {
            "report_type": "scorecard",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_findings": total_findings,
                "critical_findings": critical_count,
                "high_findings": high_count,
                "medium_findings": medium_count,
                "low_findings": low_count,
            },
            "compliance": {
                "standard": compliance_standard,
                "score": round(compliance_score, 2),
                "risk_level": risk_level,
            },
            "by_resource_type": by_resource_type,
        }

        return report

    def _generate_full_report(
        self, evidence: List[Dict[str, Any]], scorecards: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive full audit report.

        Args:
            evidence: List of evidence records
            scorecards: List of scorecard records

        Returns:
            Full report dictionary
        """
        # Start with scorecard
        report = self._generate_scorecard_report(evidence, scorecards)
        report["report_type"] = "full"

        # Add detailed findings
        report["findings"] = []

        for e in evidence:
            finding = {
                "resource_id": e.get("resource_id", "N/A"),
                "resource_type": e.get("resource_type", "Unknown"),
                "severity": e.get("severity", "LOW"),
                "timestamp": e.get("timestamp", "N/A"),
                "collector_name": e.get("collector_name", "Unknown"),
            }

            # Add data if available
            if "data" in e:
                finding["details"] = e["data"]
            elif "record_data" in e:
                try:
                    finding["details"] = json.loads(e["record_data"])
                except:
                    finding["details"] = e["record_data"]

            report["findings"].append(finding)

        # Add remediation status
        report["remediation"] = {
            "total_remediated": 0,
            "pending_remediation": 0,
            "failed_remediation": 0,
        }

        # Add compliance trends
        if scorecards:
            report["compliance_trends"] = [
                {
                    "timestamp": s.get("timestamp"),
                    "score": s.get("score"),
                    "standard": s.get("compliance_standard"),
                }
                for s in sorted(scorecards, key=lambda x: x.get("timestamp", ""))
            ]

        return report

    def _generate_executive_report(
        self, evidence: List[Dict[str, Any]], scorecards: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate an executive summary report.

        Args:
            evidence: List of evidence records
            scorecards: List of scorecard records

        Returns:
            Executive report dictionary
        """
        # Get scorecard data
        scorecard = self._generate_scorecard_report(evidence, scorecards)

        # Create executive summary
        report = {
            "report_type": "executive",
            "generated_at": datetime.now().isoformat(),
            "executive_summary": {
                "compliance_score": scorecard["compliance"]["score"],
                "risk_level": scorecard["compliance"]["risk_level"],
                "total_findings": scorecard["summary"]["total_findings"],
                "critical_findings": scorecard["summary"]["critical_findings"],
                "high_priority_findings": scorecard["summary"]["high_findings"],
            },
            "key_insights": [],
            "recommendations": [],
        }

        # Generate key insights
        if scorecard["summary"]["critical_findings"] > 0:
            report["key_insights"].append(
                f"Immediate action required: {scorecard['summary']['critical_findings']} critical findings detected."
            )

        if scorecard["compliance"]["score"] < 70:
            report["key_insights"].append(
                f"Compliance score ({scorecard['compliance']['score']}) is below acceptable threshold."
            )

        if scorecard["summary"]["total_findings"] == 0:
            report["key_insights"].append(
                "No findings detected. Platform is in excellent compliance state."
            )

        # Generate recommendations
        if scorecard["summary"]["critical_findings"] > 0:
            report["recommendations"].append(
                "Address all CRITICAL findings within 24 hours to maintain security posture."
            )

        if scorecard["summary"]["high_findings"] > 5:
            report["recommendations"].append(
                f"Review and remediate {scorecard['summary']['high_findings']} HIGH severity findings."
            )

        if scorecard["compliance"]["score"] < 80:
            report["recommendations"].append(
                "Implement additional security controls to improve compliance score."
            )

        # Add top resource types with findings
        top_resources = sorted(
            scorecard["by_resource_type"].items(),
            key=lambda x: sum(x[1].values()),
            reverse=True,
        )[:5]

        report["top_resource_types"] = [
            {"resource_type": rt, "total_findings": sum(sev.values()), "breakdown": sev}
            for rt, sev in top_resources
        ]

        return report

    def _format_json(self, report: Dict[str, Any]) -> str:
        """
        Format report as JSON.

        Args:
            report: Report dictionary

        Returns:
            JSON string
        """
        return json.dumps(report, indent=2, default=str)

    def _format_csv(self, report: Dict[str, Any]) -> str:
        """
        Format report as CSV.

        Args:
            report: Report dictionary

        Returns:
            CSV string
        """
        output = []

        # Add summary
        output.append("# GRC Evidence Platform Report")
        output.append(f"# Generated: {report['generated_at']}")
        output.append(f"# Report Type: {report['report_type']}")
        output.append("")

        # Add summary statistics
        if "summary" in report:
            output.append("## Summary")
            output.append("Metric,Value")
            for key, value in report["summary"].items():
                output.append(f"{key},{value}")
            output.append("")

        # Add compliance info
        if "compliance" in report:
            output.append("## Compliance")
            output.append("Metric,Value")
            for key, value in report["compliance"].items():
                output.append(f"{key},{value}")
            output.append("")

        # Add findings if present
        if "findings" in report:
            output.append("## Findings")
            if report["findings"]:
                # Get all possible keys
                all_keys = set()
                for finding in report["findings"]:
                    all_keys.update(finding.keys())

                # Write header
                output.append(",".join(all_keys))

                # Write rows
                for finding in report["findings"]:
                    row = []
                    for key in all_keys:
                        value = finding.get(key, "")
                        if isinstance(value, (dict, list)):
                            value = json.dumps(value)
                        elif value is None:
                            value = ""
                        else:
                            value = str(value).replace(",", ";")
                        row.append(value)
                    output.append(",".join(row))
            else:
                output.append("No findings")
            output.append("")

        return "\n".join(output)

    def _format_html(self, report: Dict[str, Any]) -> str:
        """
        Format report as HTML.

        Args:
            report: Report dictionary

        Returns:
            HTML string
        """
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GRC Evidence Platform Report - {report['report_type'].title()}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .metric {{
            display: inline-block;
            margin: 10px 20px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .metric-label {{
            font-size: 12px;
            color: #7f8c8d;
            text-transform: uppercase;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #e67e22; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #27ae60; }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>GRC Evidence Platform Report</h1>
        <p><strong>Report Type:</strong> {report['report_type'].title()}</p>
        <p><strong>Generated:</strong> {report['generated_at']}</p>
"""

        # Add summary section
        if "summary" in report:
            html += """
        <h2>Summary</h2>
        <div class="summary">
"""
            for key, value in report["summary"].items():
                html += f"""
            <div class="metric">
                <div class="metric-value">{value}</div>
                <div class="metric-label">{key.replace('_', ' ')}</div>
            </div>
"""
            html += """
        </div>
"""

        # Add compliance section
        if "compliance" in report:
            html += """
        <h2>Compliance</h2>
        <div class="summary">
"""
            for key, value in report["compliance"].items():
                html += f"""
            <div class="metric">
                <div class="metric-value">{value}</div>
                <div class="metric-label">{key.replace('_', ' ')}</div>
            </div>
"""
            html += """
        </div>
"""

        # Add findings table if present
        if "findings" in report and report["findings"]:
            html += """
        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Resource ID</th>
                    <th>Resource Type</th>
                    <th>Severity</th>
                    <th>Timestamp</th>
                    <th>Collector</th>
                </tr>
            </thead>
            <tbody>
"""
            for finding in report["findings"][:100]:  # Limit to 100 for HTML
                severity_class = f"severity-{finding.get('severity', 'low').lower()}"
                html += f"""
                <tr>
                    <td>{finding.get('resource_id', 'N/A')}</td>
                    <td>{finding.get('resource_type', 'Unknown')}</td>
                    <td class="{severity_class}">{finding.get('severity', 'LOW')}</td>
                    <td>{finding.get('timestamp', 'N/A')}</td>
                    <td>{finding.get('collector_name', 'Unknown')}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
"""

        # Add footer
        html += """
        <div class="footer">
            <p>Generated by GRC Evidence Platform v2.0</p>
        </div>
    </div>
</body>
</html>
"""

        return html

    def _format_pdf(self, report: Dict[str, Any]) -> bytes:
        """
        Format report as PDF.

        Args:
            report: Report dictionary

        Returns:
            PDF bytes
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                PageBreak,
            )
            from reportlab.lib import colors

            # Create PDF buffer
            from io import BytesIO

            buffer = BytesIO()

            # Create document
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18,
            )

            # Get styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#2c3e50"),
                spaceAfter=30,
            )
            heading_style = ParagraphStyle(
                "CustomHeading",
                parent=styles["Heading2"],
                fontSize=16,
                textColor=colors.HexColor("#34495e"),
                spaceAfter=12,
            )

            # Build content
            content = []

            # Title
            content.append(Paragraph("GRC Evidence Platform Report", title_style))
            content.append(
                Paragraph(
                    f"<b>Report Type:</b> {report['report_type'].title()}",
                    styles["Normal"],
                )
            )
            content.append(
                Paragraph(
                    f"<b>Generated:</b> {report['generated_at']}", styles["Normal"]
                )
            )
            content.append(Spacer(1, 0.2 * inch))

            # Summary
            if "summary" in report:
                content.append(Paragraph("Summary", heading_style))
                summary_data = [["Metric", "Value"]]
                for key, value in report["summary"].items():
                    summary_data.append([key.replace("_", " ").title(), str(value)])

                summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
                summary_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 12),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ]
                    )
                )
                content.append(summary_table)
                content.append(Spacer(1, 0.2 * inch))

            # Compliance
            if "compliance" in report:
                content.append(Paragraph("Compliance", heading_style))
                compliance_data = [["Metric", "Value"]]
                for key, value in report["compliance"].items():
                    compliance_data.append([key.replace("_", " ").title(), str(value)])

                compliance_table = Table(
                    compliance_data, colWidths=[3 * inch, 2 * inch]
                )
                compliance_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 12),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ]
                    )
                )
                content.append(compliance_table)
                content.append(Spacer(1, 0.2 * inch))

            # Findings
            if "findings" in report and report["findings"]:
                content.append(Paragraph("Findings", heading_style))
                findings_data = [["Resource ID", "Type", "Severity", "Timestamp"]]

                for finding in report["findings"][:50]:  # Limit to 50 for PDF
                    severity = finding.get("severity", "LOW")
                    severity_color = (
                        colors.red
                        if severity == "CRITICAL"
                        else (
                            colors.orange
                            if severity == "HIGH"
                            else (
                                colors.yellow if severity == "MEDIUM" else colors.green
                            )
                        )
                    )

                    findings_data.append(
                        [
                            finding.get("resource_id", "N/A")[:30],
                            finding.get("resource_type", "Unknown")[:20],
                            severity,
                            finding.get("timestamp", "N/A")[:19],
                        ]
                    )

                findings_table = Table(
                    findings_data,
                    colWidths=[2 * inch, 1.5 * inch, 1 * inch, 1.5 * inch],
                )
                findings_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                            ("FONTSIZE", (0, 1), (-1, -1), 8),
                        ]
                    )
                )
                content.append(findings_table)

            # Build PDF
            doc.build(content)

            # Get PDF bytes
            pdf_bytes = buffer.getvalue()
            buffer.close()

            return pdf_bytes

        except ImportError:
            logger.error(
                "reportlab library not installed. Install with: pip install reportlab"
            )
            raise
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            raise

    def generate_report(
        self,
        report_type: str,
        period: str,
        output_format: str,
        output_file: Optional[str] = None,
    ) -> str:
        """
        Generate a report of the specified type and format.

        Args:
            report_type: Type of report (scorecard, full, executive)
            period: Time period (24h, 7d, 30d, or custom)
            output_format: Output format (json, pdf, csv, html)
            output_file: Optional output file path

        Returns:
            Report content or file path
        """
        print_info(f"Generating {report_type} report for period: {period}")

        # Get time range
        start_time, end_time = self._get_time_range(period)
        print_info(f"Time range: {start_time.isoformat()} to {end_time.isoformat()}")

        # Query evidence
        print_info("Querying evidence from DynamoDB...")
        evidence = self._query_evidence(start_time, end_time)

        # Query scorecards
        print_info("Querying scorecards from DynamoDB...")
        scorecards = self._query_scorecards(start_time, end_time)

        # Generate report based on type
        print_info(f"Generating {report_type} report...")
        if report_type == "scorecard":
            report = self._generate_scorecard_report(evidence, scorecards)
        elif report_type == "full":
            report = self._generate_full_report(evidence, scorecards)
        elif report_type == "executive":
            report = self._generate_executive_report(evidence, scorecards)
        else:
            raise ValueError(f"Invalid report type: {report_type}")

        # Format output
        print_info(f"Formatting as {output_format.upper()}...")
        if output_format == "json":
            content = self._format_json(report)
        elif output_format == "csv":
            content = self._format_csv(report)
        elif output_format == "html":
            content = self._format_html(report)
        elif output_format == "pdf":
            content = self._format_pdf(report)
        else:
            raise ValueError(f"Invalid output format: {output_format}")

        # Save to file or print to stdout
        if output_file:
            # Create directory if needed
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

            # Write file
            mode = "wb" if output_format == "pdf" else "w"
            encoding = None if output_format == "pdf" else "utf-8"

            with open(output_file, mode, encoding=encoding) as f:
                f.write(content)

            print_success(f"Report saved to: {output_file}")
            return output_file
        else:
            # Print to stdout
            if output_format == "pdf":
                print_error(
                    "Cannot print PDF to stdout. Please specify an output file."
                )
                sys.exit(1)
            else:
                print(content)
                return "stdout"

    def upload_to_s3(self, file_path: str) -> str:
        """
        Upload report to S3.

        Args:
            file_path: Path to the report file

        Returns:
            S3 object key
        """
        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y/%m/%d/%H/%M/%S")
            key = f"reports/{timestamp}/{filename}"

            self.s3_client.upload_file(file_path, self.reports_bucket, key)

            print_success(f"Report uploaded to S3: s3://{self.reports_bucket}/{key}")
            return key

        except Exception as e:
            logger.error(f"Failed to upload report to S3: {e}")
            raise


def main() -> None:
    """
    Main entry point for the report generator script.
    """
    parser = argparse.ArgumentParser(
        description="Generate GRC Evidence Platform audit reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a scorecard report for the last 24 hours in JSON format
  python scripts/generate_report.py --type scorecard --period 24h --output-format json
  
  # Generate a full report for the last 7 days in PDF format
  python scripts/generate_report.py --type full --period 7d --output-format pdf --output-file report.pdf
  
  # Generate an executive summary for a custom date range in HTML format
  python scripts/generate_report.py --type executive --period 2024-01-01:2024-01-31 --output-format html --output-file report.html
  
  # Generate a CSV report and upload to S3
  python scripts/generate_report.py --type scorecard --period 30d --output-format csv --output-file report.csv --upload
        """,
    )

    parser.add_argument(
        "--type",
        help="Report type (scorecard, full, executive)",
        choices=["scorecard", "full", "executive"],
        required=True,
    )
    parser.add_argument(
        "--period",
        help="Time period (24h, 7d, 30d, or custom YYYY-MM-DD:YYYY-MM-DD)",
        required=True,
    )
    parser.add_argument(
        "--output-format",
        help="Output format (json, pdf, csv, html)",
        choices=["json", "pdf", "csv", "html"],
        default="json",
    )
    parser.add_argument(
        "--output-file",
        help="Output file path (optional, prints to stdout if not specified)",
        default=None,
    )
    parser.add_argument(
        "--upload", help="Upload report to S3 after generation", action="store_true"
    )
    parser.add_argument(
        "--region",
        help="AWS region to query (default: from AWS_DEFAULT_REGION or us-east-1)",
        default=None,
    )
    parser.add_argument(
        "--profile", help="AWS profile name to use (default: default)", default=None
    )

    args = parser.parse_args()

    try:
        generator = ReportGenerator(region=args.region, profile=args.profile)

        # Generate report
        result = generator.generate_report(
            report_type=args.type,
            period=args.period,
            output_format=args.output_format,
            output_file=args.output_file,
        )

        # Upload to S3 if requested
        if args.upload and args.output_file:
            generator.upload_to_s3(args.output_file)

        print_success("Report generation completed successfully!")

    except NoCredentialsError:
        print_error("AWS credentials not found. Please configure your credentials.")
        print_colored(
            "Run 'aws configure' or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.",
            Colors.CYAN,
        )
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
