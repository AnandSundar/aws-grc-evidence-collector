"""
ReportLab PDF builder for audit reports.

This module provides functions to generate comprehensive PDF audit reports
and scorecard reports for the GRC Evidence Platform.
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    Image,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from .scorecard_schema import ComplianceScorecard, FrameworkScore

logger = logging.getLogger(__name__)

# Page configuration
PAGE_SIZE = letter
MARGIN = 0.75 * inch

# Color scheme
COLOR_HEADER = colors.HexColor("#1a365d")  # Dark blue
COLOR_SUBHEADER = colors.HexColor("#2c5282")  # Medium blue
COLOR_CRITICAL = colors.HexColor("#c53030")  # Red
COLOR_HIGH = colors.HexColor("#dd6b20")  # Orange
COLOR_MEDIUM = colors.HexColor("#d69e2e")  # Yellow
COLOR_LOW = colors.HexColor("#38a169")  # Green
COLOR_COMPLIANT = colors.HexColor("#2f855a")  # Dark green
COLOR_LIGHT_GRAY = colors.HexColor("#f7fafc")
COLOR_BORDER = colors.HexColor("#e2e8f0")


def generate_audit_report(
    scorecard: ComplianceScorecard,
    evidence_records: List[Dict],
    remediation_logs: List[Dict],
    output_path: str,
) -> str:
    """
    Generate comprehensive PDF audit report.

    Args:
        scorecard: ComplianceScorecard instance with compliance data
        evidence_records: List of evidence record dictionaries
        remediation_logs: List of remediation log dictionaries
        output_path: Path where the PDF file should be saved

    Returns:
        Path to the generated PDF file

    Raises:
        IOError: If unable to write the PDF file
        Exception: For other errors during PDF generation
    """
    try:
        logger.info(f"Generating audit report at {output_path}")

        # Create document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=PAGE_SIZE,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=MARGIN,
            bottomMargin=MARGIN,
        )

        # Build story (content elements)
        story = []

        # Add all sections
        story.extend(_create_cover_page_section(scorecard))
        story.append(PageBreak())
        story.extend(_create_executive_summary_section(scorecard))
        story.append(PageBreak())
        story.extend(_create_framework_table_section(scorecard))
        story.append(PageBreak())
        story.extend(_create_findings_table_section(evidence_records))
        story.append(PageBreak())
        story.extend(_create_evidence_summary_section(evidence_records))
        story.append(PageBreak())
        story.extend(_create_remediation_log_section(remediation_logs))
        story.append(PageBreak())
        story.extend(_create_appendix_section(evidence_records))

        # Build PDF
        doc.build(story)

        logger.info(f"Successfully generated audit report: {output_path}")
        return output_path

    except IOError as e:
        logger.error(f"IOError generating audit report: {e}")
        raise
    except Exception as e:
        logger.error(f"Error generating audit report: {e}")
        raise


def generate_scorecard_report(scorecard: ComplianceScorecard, output_path: str) -> str:
    """
    Generate simplified scorecard report.

    Args:
        scorecard: ComplianceScorecard instance with compliance data
        output_path: Path where the PDF file should be saved

    Returns:
        Path to the generated PDF file

    Raises:
        IOError: If unable to write the PDF file
        Exception: For other errors during PDF generation
    """
    try:
        logger.info(f"Generating scorecard report at {output_path}")

        # Create document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=PAGE_SIZE,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=MARGIN,
            bottomMargin=MARGIN,
        )

        # Build story
        story = []

        # Add title and summary
        story.extend(_create_scorecard_title_section(scorecard))
        story.append(Spacer(1, 0.25 * inch))
        story.extend(_create_scorecard_summary_section(scorecard))
        story.append(Spacer(1, 0.25 * inch))
        story.extend(_create_framework_table_section(scorecard))

        # Build PDF
        doc.build(story)

        logger.info(f"Successfully generated scorecard report: {output_path}")
        return output_path

    except IOError as e:
        logger.error(f"IOError generating scorecard report: {e}")
        raise
    except Exception as e:
        logger.error(f"Error generating scorecard report: {e}")
        raise


def _create_cover_page_section(scorecard: ComplianceScorecard) -> List[Any]:
    """
    Create cover page section.

    Args:
        scorecard: ComplianceScorecard instance

    Returns:
        List of story elements for the cover page
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontSize=28,
        textColor=COLOR_HEADER,
        spaceAfter=0.5 * inch,
        alignment=TA_CENTER,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Heading2"],
        fontSize=16,
        textColor=COLOR_SUBHEADER,
        spaceAfter=0.25 * inch,
        alignment=TA_CENTER,
    )

    normal_style = ParagraphStyle(
        "Normal",
        parent=styles["Normal"],
        fontSize=11,
        spaceAfter=0.15 * inch,
        alignment=TA_CENTER,
    )

    classification_style = ParagraphStyle(
        "Classification",
        parent=styles["Heading3"],
        fontSize=14,
        textColor=COLOR_CRITICAL,
        spaceAfter=0.5 * inch,
        alignment=TA_CENTER,
    )

    # Add vertical spacing
    elements.append(Spacer(1, 1.5 * inch))

    # Title
    elements.append(Paragraph("GRC Compliance Audit Report", title_style))
    elements.append(Paragraph("Evidence Platform v2.0", subtitle_style))

    # Account information
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(
        Paragraph(f"<b>AWS Account ID:</b> {scorecard.aws_account_id}", normal_style)
    )
    elements.append(Paragraph(f"<b>Region:</b> {scorecard.aws_region}", normal_style))
    elements.append(
        Paragraph(
            f"<b>Report Period:</b> {scorecard.period_start} to {scorecard.period_end}",
            normal_style,
        )
    )
    elements.append(
        Paragraph(f"<b>Generated:</b> {scorecard.generated_at}", normal_style)
    )

    # Classification
    elements.append(Spacer(1, 1.0 * inch))
    elements.append(Paragraph("CONFIDENTIAL", classification_style))

    # Disclaimer
    elements.append(Spacer(1, 1.5 * inch))
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.gray,
        alignment=TA_CENTER,
    )
    elements.append(
        Paragraph(
            "This report contains confidential information and is intended solely for authorized personnel. "
            "Unauthorized distribution is prohibited.",
            disclaimer_style,
        )
    )

    return elements


def _create_executive_summary_section(scorecard: ComplianceScorecard) -> List[Any]:
    """
    Create executive summary section.

    Args:
        scorecard: ComplianceScorecard instance

    Returns:
        List of story elements for the executive summary
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Section header
    header_style = ParagraphStyle(
        "Header",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=COLOR_HEADER,
        spaceAfter=0.25 * inch,
    )
    elements.append(Paragraph("Executive Summary", header_style))

    # Overall risk score
    risk_color = _get_risk_color(scorecard.overall_risk_rating)
    score_style = ParagraphStyle(
        "Score",
        parent=styles["Heading2"],
        fontSize=36,
        textColor=risk_color,
        alignment=TA_CENTER,
        spaceAfter=0.1 * inch,
    )
    elements.append(Paragraph(f"{scorecard.overall_risk_score:.1f}", score_style))

    # Risk rating
    rating_style = ParagraphStyle(
        "Rating",
        parent=styles["Heading3"],
        fontSize=16,
        textColor=risk_color,
        alignment=TA_CENTER,
        spaceAfter=0.5 * inch,
    )
    elements.append(
        Paragraph(f"Risk Rating: {scorecard.overall_risk_rating}", rating_style)
    )

    # Key metrics table
    metrics_data = [
        ["Metric", "Value"],
        ["Total Evidence Collected", str(scorecard.total_evidence_collected)],
        ["Total Findings", str(scorecard.total_findings)],
        ["Critical Findings", str(scorecard.critical_findings)],
        ["High Findings", str(scorecard.high_findings)],
        ["Medium Findings", str(scorecard.medium_findings)],
        ["Low Findings", str(scorecard.low_findings)],
        ["Auto-Remediated Today", str(scorecard.auto_remediated_today)],
    ]

    metrics_table = Table(metrics_data, colWidths=[2.5 * inch, 2.5 * inch])
    metrics_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), COLOR_LIGHT_GRAY),
                ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    elements.append(metrics_table)
    elements.append(Spacer(1, 0.5 * inch))

    # Top 5 risks
    if scorecard.top_5_risks:
        elements.append(Paragraph("<b>Top 5 Risks:</b>", styles["Heading3"]))
        for i, risk in enumerate(scorecard.top_5_risks, 1):
            elements.append(Paragraph(f"{i}. {risk}", styles["Normal"]))

    return elements


def _create_framework_table_section(scorecard: ComplianceScorecard) -> List[Any]:
    """
    Create framework coverage table section.

    Args:
        scorecard: ComplianceScorecard instance

    Returns:
        List of story elements for the framework table
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Section header
    header_style = ParagraphStyle(
        "Header",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=COLOR_HEADER,
        spaceAfter=0.25 * inch,
    )
    elements.append(Paragraph("Framework Coverage", header_style))

    if not scorecard.frameworks:
        elements.append(Paragraph("No framework data available.", styles["Normal"]))
        return elements

    # Build table data
    table_data = [
        ["Framework", "Version", "Score", "Passing", "Failing", "Not Tested", "Trend"]
    ]

    for framework_name, framework_score in scorecard.frameworks.items():
        trend_str = (
            f"+{framework_score.trend_vs_yesterday:.1f}%"
            if framework_score.trend_vs_yesterday >= 0
            else f"{framework_score.trend_vs_yesterday:.1f}%"
        )
        table_data.append(
            [
                framework_name,
                framework_score.version,
                f"{framework_score.score_percentage:.1f}%",
                str(framework_score.controls_passing),
                str(framework_score.controls_failing),
                str(framework_score.controls_not_tested),
                trend_str,
            ]
        )

    # Create table
    framework_table = Table(
        table_data,
        colWidths=[
            1.2 * inch,
            0.8 * inch,
            0.8 * inch,
            0.8 * inch,
            0.8 * inch,
            0.9 * inch,
            0.7 * inch,
        ],
    )
    framework_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_LIGHT_GRAY, colors.white]),
                ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    elements.append(framework_table)

    return elements


def _create_findings_table_section(evidence_records: List[Dict]) -> List[Any]:
    """
    Create critical and high findings table section.

    Args:
        evidence_records: List of evidence record dictionaries

    Returns:
        List of story elements for the findings table
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Section header
    header_style = ParagraphStyle(
        "Header",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=COLOR_HEADER,
        spaceAfter=0.25 * inch,
    )
    elements.append(Paragraph("Critical & High Findings", header_style))

    # Filter critical and high findings
    critical_high_findings = [
        record
        for record in evidence_records
        if record.get("severity", "").upper() in ["CRITICAL", "HIGH"]
    ]

    if not critical_high_findings:
        elements.append(
            Paragraph("No critical or high findings found.", styles["Normal"])
        )
        return elements

    # Build table data
    table_data = [["Resource", "Finding", "Severity", "Evidence Date", "Status"]]

    for finding in critical_high_findings[:20]:  # Limit to top 20
        severity = finding.get("severity", "UNKNOWN").upper()
        table_data.append(
            [
                finding.get("resource_id", "N/A")[:30],
                finding.get("finding_description", "N/A")[:40],
                severity,
                finding.get("evidence_timestamp", "N/A")[:10],
                finding.get("status", "N/A"),
            ]
        )

    # Create table
    findings_table = Table(
        table_data,
        colWidths=[1.5 * inch, 2.5 * inch, 0.8 * inch, 1.0 * inch, 0.8 * inch],
    )
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_LIGHT_GRAY, colors.white]),
                ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    elements.append(findings_table)

    if len(critical_high_findings) > 20:
        elements.append(Spacer(1, 0.25 * inch))
        elements.append(
            Paragraph(
                f"Showing 20 of {len(critical_high_findings)} critical/high findings.",
                styles["Italic"],
            )
        )

    return elements


def _create_evidence_summary_section(evidence_records: List[Dict]) -> List[Any]:
    """
    Create evidence collection summary section.

    Args:
        evidence_records: List of evidence record dictionaries

    Returns:
        List of story elements for the evidence summary
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Section header
    header_style = ParagraphStyle(
        "Header",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=COLOR_HEADER,
        spaceAfter=0.25 * inch,
    )
    elements.append(Paragraph("Evidence Collection Summary", header_style))

    if not evidence_records:
        elements.append(Paragraph("No evidence records available.", styles["Normal"]))
        return elements

    # Group by collector
    collector_stats = defaultdict(
        lambda: {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    )

    for record in evidence_records:
        collector = record.get("collector_name", "Unknown")
        severity = record.get("severity", "LOW").upper()
        collector_stats[collector]["total"] += 1
        if severity in collector_stats[collector]:
            collector_stats[collector][severity] += 1

    # Build table data
    table_data = [["Collector", "Total Records", "Critical", "High", "Medium", "Low"]]

    for collector, stats in sorted(collector_stats.items()):
        table_data.append(
            [
                collector,
                str(stats["total"]),
                str(stats["critical"]),
                str(stats["high"]),
                str(stats["medium"]),
                str(stats["low"]),
            ]
        )

    # Create table
    summary_table = Table(
        table_data,
        colWidths=[
            1.5 * inch,
            1.0 * inch,
            0.8 * inch,
            0.8 * inch,
            0.8 * inch,
            0.8 * inch,
        ],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_LIGHT_GRAY, colors.white]),
                ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    elements.append(summary_table)

    return elements


def _create_remediation_log_section(remediation_logs: List[Dict]) -> List[Any]:
    """
    Create auto-remediation log section.

    Args:
        remediation_logs: List of remediation log dictionaries

    Returns:
        List of story elements for the remediation log
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Section header
    header_style = ParagraphStyle(
        "Header",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=COLOR_HEADER,
        spaceAfter=0.25 * inch,
    )
    elements.append(Paragraph("Auto-Remediation Log", header_style))

    if not remediation_logs:
        elements.append(Paragraph("No remediation actions recorded.", styles["Normal"]))
        return elements

    # Build table data
    table_data = [
        ["Timestamp", "Resource Type", "Resource ID", "Action Taken", "Status"]
    ]

    for log in remediation_logs[:30]:  # Limit to top 30
        status = "SUCCESS" if log.get("success", False) else "FAILED"
        table_data.append(
            [
                log.get("timestamp", "N/A")[:19],
                log.get("resource_type", "N/A"),
                log.get("resource_id", "N/A")[:25],
                log.get("action_taken", "N/A")[:30],
                status,
            ]
        )

    # Create table
    remediation_table = Table(
        table_data,
        colWidths=[1.2 * inch, 1.2 * inch, 1.5 * inch, 2.0 * inch, 0.8 * inch],
    )
    remediation_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_LIGHT_GRAY, colors.white]),
                ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    elements.append(remediation_table)

    if len(remediation_logs) > 30:
        elements.append(Spacer(1, 0.25 * inch))
        elements.append(
            Paragraph(
                f"Showing 30 of {len(remediation_logs)} remediation actions.",
                styles["Italic"],
            )
        )

    return elements


def _create_appendix_section(evidence_records: List[Dict]) -> List[Any]:
    """
    Create appendix with evidence counts by day.

    Args:
        evidence_records: List of evidence record dictionaries

    Returns:
        List of story elements for the appendix
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Section header
    header_style = ParagraphStyle(
        "Header",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=COLOR_HEADER,
        spaceAfter=0.25 * inch,
    )
    elements.append(Paragraph("Appendix: Evidence Count by Day", header_style))

    if not evidence_records:
        elements.append(Paragraph("No evidence records available.", styles["Normal"]))
        return elements

    # Group by date
    daily_counts = defaultdict(int)
    for record in evidence_records:
        timestamp = record.get("evidence_timestamp", "")
        if timestamp:
            date_str = timestamp[:10]  # Extract date part
            daily_counts[date_str] += 1

    # Sort by date
    sorted_dates = sorted(daily_counts.keys())

    # Build table data
    table_data = [["Date", "Evidence Count"]]
    for date_str in sorted_dates:
        table_data.append([date_str, str(daily_counts[date_str])])

    # Add total
    table_data.append(["<b>Total</b>", f"<b>{len(evidence_records)}</b>"])

    # Create table
    appendix_table = Table(table_data, colWidths=[2.5 * inch, 2.5 * inch])
    appendix_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("ROWBACKGROUNDS", (0, 1), (-2, -1), [COLOR_LIGHT_GRAY, colors.white]),
                ("BACKGROUND", (0, -1), (-1, -1), COLOR_SUBHEADER),
                ("TEXTCOLOR", (0, -1), (-1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    elements.append(appendix_table)

    return elements


def _create_scorecard_title_section(scorecard: ComplianceScorecard) -> List[Any]:
    """
    Create scorecard title section.

    Args:
        scorecard: ComplianceScorecard instance

    Returns:
        List of story elements for the title
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontSize=24,
        textColor=COLOR_HEADER,
        spaceAfter=0.25 * inch,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=COLOR_SUBHEADER,
        spaceAfter=0.5 * inch,
    )

    # Title
    elements.append(Paragraph("Compliance Scorecard", title_style))
    elements.append(
        Paragraph(
            f"Account: {scorecard.aws_account_id} | Region: {scorecard.aws_region}",
            subtitle_style,
        )
    )
    elements.append(
        Paragraph(
            f"Period: {scorecard.period_start} to {scorecard.period_end}",
            subtitle_style,
        )
    )

    return elements


def _create_scorecard_summary_section(scorecard: ComplianceScorecard) -> List[Any]:
    """
    Create scorecard summary section.

    Args:
        scorecard: ComplianceScorecard instance

    Returns:
        List of story elements for the summary
    """
    elements = []

    # Get styles
    styles = getSampleStyleSheet()

    # Risk score and rating
    risk_color = _get_risk_color(scorecard.overall_risk_rating)

    score_style = ParagraphStyle(
        "Score",
        parent=styles["Heading2"],
        fontSize=28,
        textColor=risk_color,
        alignment=TA_CENTER,
    )

    rating_style = ParagraphStyle(
        "Rating",
        parent=styles["Heading3"],
        fontSize=14,
        textColor=risk_color,
        alignment=TA_CENTER,
        spaceAfter=0.5 * inch,
    )

    elements.append(Paragraph(f"{scorecard.overall_risk_score:.1f}", score_style))
    elements.append(
        Paragraph(f"Overall Risk Rating: {scorecard.overall_risk_rating}", rating_style)
    )

    # Summary metrics
    metrics_data = [
        ["Total Evidence", str(scorecard.total_evidence_collected)],
        ["Total Findings", str(scorecard.total_findings)],
        ["Critical", str(scorecard.critical_findings)],
        ["High", str(scorecard.high_findings)],
        ["Auto-Remediated", str(scorecard.auto_remediated_today)],
    ]

    metrics_table = Table(metrics_data, colWidths=[2.5 * inch, 2.5 * inch])
    metrics_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), COLOR_LIGHT_GRAY),
                ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    elements.append(metrics_table)

    return elements


def _get_risk_color(rating: str) -> colors.Color:
    """
    Get color based on risk rating.

    Args:
        rating: Risk rating string

    Returns:
        Color object for the rating
    """
    rating_upper = rating.upper()
    if rating_upper == "CRITICAL":
        return COLOR_CRITICAL
    elif rating_upper == "HIGH":
        return COLOR_HIGH
    elif rating_upper == "MEDIUM":
        return COLOR_MEDIUM
    elif rating_upper == "LOW":
        return COLOR_LOW
    elif rating_upper == "COMPLIANT":
        return COLOR_COMPLIANT
    else:
        return colors.gray
