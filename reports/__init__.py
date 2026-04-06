"""
GRC Evidence Platform - Reports Package

This package provides report generation capabilities for the GRC Evidence Platform,
including PDF reports, HTML templates, and data schemas for compliance scorecards.
"""

__version__ = "2.0.0"

# Export main classes and functions from scorecard_schema
from .scorecard_schema import (
    ComplianceScorecard,
    FrameworkScore,
    RemediationSummary,
    EvidenceGap,
)

# Export main functions from pdf_generator
from .pdf_generator import generate_audit_report, generate_scorecard_report

__all__ = [
    # Data classes
    "ComplianceScorecard",
    "FrameworkScore",
    "RemediationSummary",
    "EvidenceGap",
    # PDF generation functions
    "generate_audit_report",
    "generate_scorecard_report",
]
