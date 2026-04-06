"""
Dataclass schemas for compliance scorecard and related structures.

This module defines the data structures used for generating compliance reports,
including framework scores, compliance scorecards, remediation summaries, and
evidence gaps.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class FrameworkScore:
    """
    Represents compliance score for a specific framework.

    Attributes:
        framework: Name of the compliance framework (e.g., "PCI-DSS", "SOC2", "CIS", "NIST")
        version: Version of the framework (e.g., "4.0", "2017", "1.5", "Rev.5")
        controls_total: Total number of controls in the framework
        controls_passing: Number of controls that passed compliance checks
        controls_failing: Number of controls that failed compliance checks
        controls_not_tested: Number of controls that were not tested
        score_percentage: Overall compliance score as a percentage (0-100)
        trend_vs_yesterday: Change in score percentage compared to yesterday (+/- percentage points)
        highest_risk_failing_controls: List of control IDs with highest risk failures
        evidence_count: Total number of evidence records collected for this framework
    """

    framework: str
    version: str
    controls_total: int
    controls_passing: int
    controls_failing: int
    controls_not_tested: int
    score_percentage: float
    trend_vs_yesterday: float
    highest_risk_failing_controls: List[str] = field(default_factory=list)
    evidence_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the FrameworkScore to a dictionary.

        Returns:
            Dictionary representation of the FrameworkScore
        """
        return {
            "framework": self.framework,
            "version": self.version,
            "controls_total": self.controls_total,
            "controls_passing": self.controls_passing,
            "controls_failing": self.controls_failing,
            "controls_not_tested": self.controls_not_tested,
            "score_percentage": self.score_percentage,
            "trend_vs_yesterday": self.trend_vs_yesterday,
            "highest_risk_failing_controls": self.highest_risk_failing_controls,
            "evidence_count": self.evidence_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FrameworkScore":
        """
        Create a FrameworkScore from a dictionary.

        Args:
            data: Dictionary containing FrameworkScore data

        Returns:
            FrameworkScore instance
        """
        return cls(
            framework=data.get("framework", ""),
            version=data.get("version", ""),
            controls_total=data.get("controls_total", 0),
            controls_passing=data.get("controls_passing", 0),
            controls_failing=data.get("controls_failing", 0),
            controls_not_tested=data.get("controls_not_tested", 0),
            score_percentage=data.get("score_percentage", 0.0),
            trend_vs_yesterday=data.get("trend_vs_yesterday", 0.0),
            highest_risk_failing_controls=data.get("highest_risk_failing_controls", []),
            evidence_count=data.get("evidence_count", 0),
        )


@dataclass
class ComplianceScorecard:
    """
    Represents a comprehensive compliance scorecard for an AWS account.

    Attributes:
        scorecard_id: Unique identifier for the scorecard
        generated_at: Timestamp when the scorecard was generated (ISO 8601)
        aws_account_id: AWS account ID
        aws_region: AWS region
        period_start: Start of the reporting period (ISO 8601)
        period_end: End of the reporting period (ISO 8601)
        overall_risk_score: Overall risk score (0-100, higher = better)
        overall_risk_rating: Risk rating (CRITICAL/HIGH/MEDIUM/LOW/COMPLIANT)
        total_evidence_collected: Total number of evidence records collected
        total_findings: Total number of findings
        critical_findings: Number of critical severity findings
        high_findings: Number of high severity findings
        medium_findings: Number of medium severity findings
        low_findings: Number of low severity findings
        auto_remediated_today: Number of issues auto-remediated today
        frameworks: Dictionary of framework names to FrameworkScore objects
        top_5_risks: List of top 5 highest priority unresolved findings
        collectors_run: List of collector names that were executed
        scorecard_s3_path: S3 path where the scorecard is stored
    """

    scorecard_id: str
    generated_at: str
    aws_account_id: str
    aws_region: str
    period_start: str
    period_end: str
    overall_risk_score: float
    overall_risk_rating: str
    total_evidence_collected: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    auto_remediated_today: int
    frameworks: Dict[str, FrameworkScore] = field(default_factory=dict)
    top_5_risks: List[str] = field(default_factory=list)
    collectors_run: List[str] = field(default_factory=list)
    scorecard_s3_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the ComplianceScorecard to a dictionary.

        Returns:
            Dictionary representation of the ComplianceScorecard
        """
        return {
            "scorecard_id": self.scorecard_id,
            "generated_at": self.generated_at,
            "aws_account_id": self.aws_account_id,
            "aws_region": self.aws_region,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "overall_risk_score": self.overall_risk_score,
            "overall_risk_rating": self.overall_risk_rating,
            "total_evidence_collected": self.total_evidence_collected,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "auto_remediated_today": self.auto_remediated_today,
            "frameworks": {k: v.to_dict() for k, v in self.frameworks.items()},
            "top_5_risks": self.top_5_risks,
            "collectors_run": self.collectors_run,
            "scorecard_s3_path": self.scorecard_s3_path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceScorecard":
        """
        Create a ComplianceScorecard from a dictionary.

        Args:
            data: Dictionary containing ComplianceScorecard data

        Returns:
            ComplianceScorecard instance
        """
        frameworks_data = data.get("frameworks", {})
        frameworks = {
            k: FrameworkScore.from_dict(v) for k, v in frameworks_data.items()
        }

        return cls(
            scorecard_id=data.get("scorecard_id", ""),
            generated_at=data.get("generated_at", ""),
            aws_account_id=data.get("aws_account_id", ""),
            aws_region=data.get("aws_region", ""),
            period_start=data.get("period_start", ""),
            period_end=data.get("period_end", ""),
            overall_risk_score=data.get("overall_risk_score", 0.0),
            overall_risk_rating=data.get("overall_risk_rating", ""),
            total_evidence_collected=data.get("total_evidence_collected", 0),
            total_findings=data.get("total_findings", 0),
            critical_findings=data.get("critical_findings", 0),
            high_findings=data.get("high_findings", 0),
            medium_findings=data.get("medium_findings", 0),
            low_findings=data.get("low_findings", 0),
            auto_remediated_today=data.get("auto_remediated_today", 0),
            frameworks=frameworks,
            top_5_risks=data.get("top_5_risks", []),
            collectors_run=data.get("collectors_run", []),
            scorecard_s3_path=data.get("scorecard_s3_path", ""),
        )

    @staticmethod
    def calculate_risk_rating(risk_score: float) -> str:
        """
        Calculate risk rating based on risk score.

        Args:
            risk_score: Risk score (0-100, higher = better)

        Returns:
            Risk rating string: CRITICAL/HIGH/MEDIUM/LOW/COMPLIANT
        """
        if risk_score >= 95:
            return "COMPLIANT"
        elif risk_score >= 81:
            return "LOW"
        elif risk_score >= 61:
            return "MEDIUM"
        elif risk_score >= 41:
            return "HIGH"
        else:
            return "CRITICAL"


@dataclass
class RemediationSummary:
    """
    Represents a summary of a remediation action.

    Attributes:
        remediation_id: Unique identifier for the remediation action
        timestamp: Timestamp when the remediation was performed (ISO 8601)
        resource_type: Type of the AWS resource that was remediated
        resource_id: ID of the AWS resource that was remediated
        action_taken: Description of the remediation action taken
        success: Whether the remediation was successful
        compliance_frameworks: List of compliance frameworks affected by this remediation
    """

    remediation_id: str
    timestamp: str
    resource_type: str
    resource_id: str
    action_taken: str
    success: bool
    compliance_frameworks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the RemediationSummary to a dictionary.

        Returns:
            Dictionary representation of the RemediationSummary
        """
        return {
            "remediation_id": self.remediation_id,
            "timestamp": self.timestamp,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action_taken": self.action_taken,
            "success": self.success,
            "compliance_frameworks": self.compliance_frameworks,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RemediationSummary":
        """
        Create a RemediationSummary from a dictionary.

        Args:
            data: Dictionary containing RemediationSummary data

        Returns:
            RemediationSummary instance
        """
        return cls(
            remediation_id=data.get("remediation_id", ""),
            timestamp=data.get("timestamp", ""),
            resource_type=data.get("resource_type", ""),
            resource_id=data.get("resource_id", ""),
            action_taken=data.get("action_taken", ""),
            success=data.get("success", False),
            compliance_frameworks=data.get("compliance_frameworks", []),
        )


@dataclass
class EvidenceGap:
    """
    Represents a gap in evidence collection.

    Attributes:
        collector_name: Name of the collector that should have collected the evidence
        last_collection_time: Timestamp of the last successful collection (ISO 8601)
        max_age_hours: Maximum acceptable age of evidence in hours
        is_stale: Whether the evidence is considered stale (older than max_age_hours)
        compliance_frameworks: List of compliance frameworks affected by this gap
        severity: Severity of the evidence gap (HIGH/MEDIUM/LOW)
    """

    collector_name: str
    last_collection_time: str
    max_age_hours: int
    is_stale: bool
    compliance_frameworks: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the EvidenceGap to a dictionary.

        Returns:
            Dictionary representation of the EvidenceGap
        """
        return {
            "collector_name": self.collector_name,
            "last_collection_time": self.last_collection_time,
            "max_age_hours": self.max_age_hours,
            "is_stale": self.is_stale,
            "compliance_frameworks": self.compliance_frameworks,
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceGap":
        """
        Create an EvidenceGap from a dictionary.

        Args:
            data: Dictionary containing EvidenceGap data

        Returns:
            EvidenceGap instance
        """
        return cls(
            collector_name=data.get("collector_name", ""),
            last_collection_time=data.get("last_collection_time", ""),
            max_age_hours=data.get("max_age_hours", 24),
            is_stale=data.get("is_stale", False),
            compliance_frameworks=data.get("compliance_frameworks", []),
            severity=data.get("severity", "MEDIUM"),
        )
