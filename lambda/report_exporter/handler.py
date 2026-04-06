"""
GRC Evidence Platform - Audit Report Exporter Lambda

This Lambda function generates comprehensive audit reports including cover page,
executive summary, framework coverage, findings, evidence collection summary,
remediation log, and appendix. Outputs both JSON and CSV formats.

Author: GRC Platform Team
Version: 2.0
"""

import json
import logging
import os
import boto3
import csv
import io
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from botocore.exceptions import ClientError

# Import Excel generator
try:
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'reports'))
    from excel_generator import ExcelReportGenerator
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False
    logging.warning("Excel generator not available. Excel reports will not be generated.")

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


@dataclass
class AuditReport:
    """Comprehensive audit report data structure."""

    # Cover Page
    account_id: str
    report_period_start: str
    report_period_end: str
    generated_date: str
    classification: str

    # Executive Summary
    overall_risk_score: float
    trend_data: List[Dict[str, Any]]
    top_5_risks: List[Dict[str, Any]]

    # Framework Coverage
    framework_coverage: List[Dict[str, Any]]

    # Critical & High Findings
    critical_high_findings: List[Dict[str, Any]]

    # Evidence Collection Summary
    evidence_collection_summary: Dict[str, Any]

    # Auto-Remediation Log
    auto_remediation_log: List[Dict[str, Any]]

    # Appendix
    appendix: Dict[str, Any]


def query_evidence_for_period(
    dynamodb_client: Any,
    table_name: str,
    start_date: datetime,
    end_date: datetime,
    gsi_name: str,
) -> List[Dict[str, Any]]:
    """
    Query evidence records for the audit period.

    Args:
        dynamodb_client: Boto3 DynamoDB client
        table_name: DynamoDB table name
        start_date: Start of audit period
        end_date: End of audit period
        gsi_name: Global secondary index name for timestamp queries

    Returns:
        List of evidence records
    """
    evidence_list = []

    try:
        paginator = dynamodb_client.get_paginator("query")

        query_params = {
            "TableName": table_name,
            "IndexName": gsi_name,
            "KeyConditionExpression": "created_at BETWEEN :start_date AND :end_date",
            "ExpressionAttributeValues": {
                ":start_date": {"S": start_date.isoformat()},
                ":end_date": {"S": end_date.isoformat()},
            },
        }

        for page in paginator.paginate(**query_params):
            for item in page.get("Items", []):
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
            f"{Colors.OKCYAN}Queried {len(evidence_list)} evidence records for audit period{Colors.ENDC}"
        )

    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to query evidence: {e}{Colors.ENDC}")

    return evidence_list


def query_remediations_for_period(
    dynamodb_client: Any, table_name: str, start_date: datetime, end_date: datetime
) -> List[Dict[str, Any]]:
    """
    Query remediation logs for the audit period.

    Args:
        dynamodb_client: Boto3 DynamoDB client
        table_name: Remediation log table name
        start_date: Start of audit period
        end_date: End of audit period

    Returns:
        List of remediation records
    """
    remediation_list = []

    try:
        paginator = dynamodb_client.get_paginator("scan")

        scan_params = {
            "TableName": table_name,
            "FilterExpression": "created_at BETWEEN :start_date AND :end_date",
            "ExpressionAttributeValues": {
                ":start_date": {"S": start_date.isoformat()},
                ":end_date": {"S": end_date.isoformat()},
            },
        }

        for page in paginator.paginate(**scan_params):
            for item in page.get("Items", []):
                remediation = {}
                for key, value in item.items():
                    if "S" in value:
                        remediation[key] = value["S"]
                    elif "N" in value:
                        remediation[key] = float(value["N"])
                    elif "L" in value:
                        remediation[key] = [v["S"] for v in value["L"]]
                    elif "M" in value:
                        remediation[key] = json.loads(value["M"])
                remediation_list.append(remediation)

        logger.info(
            f"{Colors.OKCYAN}Queried {len(remediation_list)} remediation records for audit period{Colors.ENDC}"
        )

    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to query remediations: {e}{Colors.ENDC}")

    return remediation_list


def query_scorecards_for_period(
    s3_client: Any, bucket_name: str, start_date: datetime, end_date: datetime
) -> List[Dict[str, Any]]:
    """
    Query scorecards for the audit period to build trend data.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: S3 bucket name
        start_date: Start of audit period
        end_date: End of audit period

    Returns:
        List of scorecard records
    """
    scorecards = []

    try:
        current_date = start_date.date()
        end_date_obj = end_date.date()

        while current_date <= end_date_obj:
            s3_key = f"scorecards/{current_date.isoformat()}/scorecard.json"
            try:
                response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
                content = response["Body"].read().decode("utf-8")
                scorecards.append(json.loads(content))
            except ClientError:
                # Scorecard may not exist for this date
                pass

            current_date += timedelta(days=1)

        logger.info(
            f"{Colors.OKCYAN}Retrieved {len(scorecards)} scorecards for trend analysis{Colors.ENDC}"
        )

    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to query scorecards: {e}{Colors.ENDC}")

    return scorecards


def calculate_framework_coverage(
    evidence_list: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Calculate framework coverage from evidence records.

    Args:
        evidence_list: List of evidence records

    Returns:
        List of framework coverage data
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
                    "framework_name": framework,
                    "total_tested": 0,
                    "passing": 0,
                    "failing": 0,
                }

            framework_data[framework]["total_tested"] += 1
            if control_status == "PASS":
                framework_data[framework]["passing"] += 1
            else:
                framework_data[framework]["failing"] += 1

    # Calculate scores
    framework_coverage = []
    for data in framework_data.values():
        score = (
            (data["passing"] / data["total_tested"] * 100)
            if data["total_tested"] > 0
            else 0.0
        )
        framework_coverage.append({**data, "score": round(score, 2)})

    return framework_coverage


def generate_trend_data(scorecards: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generate trend data from scorecards.

    Args:
        scorecards: List of scorecard records

    Returns:
        List of trend data points
    """
    trend_data = []

    for scorecard in sorted(scorecards, key=lambda x: x.get("scorecard_date", "")):
        trend_data.append(
            {
                "date": scorecard.get("scorecard_date"),
                "overall_score": scorecard.get("overall_score", 0),
                "critical_count": scorecard.get("critical_count", 0),
                "high_count": scorecard.get("high_count", 0),
            }
        )

    return trend_data


def get_critical_high_findings(
    evidence_list: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Extract critical and high priority findings.

    Args:
        evidence_list: List of evidence records

    Returns:
        List of critical and high findings
    """
    findings = []

    for evidence in evidence_list:
        priority = evidence.get("priority", "LOW")
        if priority in ["CRITICAL", "HIGH"]:
            findings.append(
                {
                    "event_id": evidence.get("event_id", "unknown"),
                    "event_name": evidence.get("event_name", "unknown"),
                    "priority": priority,
                    "finding_title": evidence.get("finding_title", "Unknown"),
                    "event_time": evidence.get("event_time"),
                    "aws_region": evidence.get("aws_region"),
                    "resource_id": (
                        evidence.get("resources", [{}])[0].get("ARN", "N/A")
                        if evidence.get("resources")
                        else "N/A"
                    ),
                    "remediation_status": evidence.get("remediation_status", "PENDING"),
                    "ai_risk_score": evidence.get("ai_risk_score"),
                }
            )

    # Sort by priority (CRITICAL first) then by AI risk score
    findings.sort(
        key=lambda x: (
            0 if x["priority"] == "CRITICAL" else 1,
            -(x["ai_risk_score"] or 0),
        )
    )

    return findings


def generate_evidence_collection_summary(
    evidence_list: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Generate evidence collection summary.

    Args:
        evidence_list: List of evidence records

    Returns:
        Evidence collection summary
    """
    # Count by collector
    collector_counts = {}
    for evidence in evidence_list:
        collector = evidence.get("collector_name", "unknown")
        collector_counts[collector] = collector_counts.get(collector, 0) + 1

    # Count by priority
    priority_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for evidence in evidence_list:
        priority = evidence.get("priority", "LOW")
        if priority in priority_counts:
            priority_counts[priority] += 1

    # Calculate SLA adherence
    within_sla = 0
    for evidence in evidence_list:
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

                if delay_hours <= 24:
                    within_sla += 1
            except (ValueError, AttributeError):
                within_sla += 1

    sla_adherence = (
        round((within_sla / len(evidence_list) * 100), 2) if evidence_list else 100.0
    )

    return {
        "total_records": len(evidence_list),
        "records_by_collector": collector_counts,
        "records_by_priority": priority_counts,
        "sla_adherence_percent": sla_adherence,
        "within_sla_count": within_sla,
        "total_tested": len(evidence_list),
    }


def generate_appendix(evidence_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate appendix with evidence count by day.

    Args:
        evidence_list: List of evidence records

    Returns:
        Appendix data
    """
    daily_counts = {}

    for evidence in evidence_list:
        created_at_str = evidence.get("created_at", "")
        if created_at_str:
            try:
                created_at = datetime.fromisoformat(
                    created_at_str.replace("Z", "+00:00")
                )
                date_key = created_at.date().isoformat()
                daily_counts[date_key] = daily_counts.get(date_key, 0) + 1
            except (ValueError, AttributeError):
                pass

    return {
        "evidence_count_by_day": daily_counts,
        "total_days": len(daily_counts),
        "total_evidence_records": len(evidence_list),
    }


def generate_csv_evidence_matrix(
    evidence_list: List[Dict[str, Any]], remediation_list: List[Dict[str, Any]]
) -> str:
    """
    Generate CSV evidence matrix.

    Args:
        evidence_list: List of evidence records
        remediation_list: List of remediation records

    Returns:
        CSV string
    """
    output = io.StringIO()

    # Create a set of remediated finding IDs for quick lookup
    remediated_findings = {
        r.get("finding_id")
        for r in remediation_list
        if r.get("finding_id") and r.get("action_status") == "SUCCESS"
    }

    fieldnames = [
        "date",
        "collector",
        "resource_id",
        "control_status",
        "priority",
        "compliance_frameworks",
        "finding_title",
        "remediated",
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for evidence in evidence_list:
        created_at_str = evidence.get("created_at", "")
        date = created_at_str.split("T")[0] if created_at_str else "N/A"

        # Extract resource ID
        resources = evidence.get("resources", [])
        resource_id = resources[0].get("ARN", "N/A") if resources else "N/A"

        # Get compliance frameworks
        frameworks = evidence.get("compliance_frameworks", "[]")
        if isinstance(frameworks, str):
            try:
                frameworks = json.loads(frameworks)
            except json.JSONDecodeError:
                frameworks = [frameworks]

        # Check if remediated
        event_id = evidence.get("event_id", "")
        remediated = "yes" if event_id in remediated_findings else "no"

        writer.writerow(
            {
                "date": date,
                "collector": evidence.get("collector_name", "unknown"),
                "resource_id": resource_id,
                "control_status": evidence.get("control_status", "UNKNOWN"),
                "priority": evidence.get("priority", "LOW"),
                "compliance_frameworks": ", ".join(frameworks),
                "finding_title": evidence.get("finding_title", "N/A"),
                "remediated": remediated,
            }
        )

    return output.getvalue()


def generate_excel_report(
    evidence_list: List[Dict[str, Any]],
    remediation_list: List[Dict[str, Any]],
    scorecards: List[Dict[str, Any]],
    audit_report: AuditReport
) -> Optional[bytes]:
    """
    Generate Excel report with multiple sheets.

    Args:
        evidence_list: List of evidence records
        remediation_list: List of remediation records
        scorecards: List of scorecard records
        audit_report: Audit report object

    Returns:
        Excel bytes or None if generation fails
    """
    if not EXCEL_AVAILABLE:
        logger.warning(f"{Colors.WARNING}Excel generator not available. Skipping Excel report generation.{Colors.ENDC}")
        return None

    try:
        generator = ExcelReportGenerator()

        # Prepare findings data for Excel
        findings_data = []
        for evidence in evidence_list:
            # Extract resource ID
            resources = evidence.get("resources", [])
            resource_id = resources[0].get("ARN", "N/A") if resources else "N/A"

            # Get compliance frameworks
            frameworks = evidence.get("compliance_frameworks", "[]")
            if isinstance(frameworks, str):
                try:
                    frameworks = json.loads(frameworks)
                except json.JSONDecodeError:
                    frameworks = [frameworks]

            finding = {
                'evidence_id': evidence.get("event_id", "N/A"),
                'event_name': evidence.get("event_name", "N/A"),
                'event_time': evidence.get("event_time", "N/A"),
                'resource_type': evidence.get("resource_type", "N/A"),
                'resource_id': resource_id,
                'priority': evidence.get("priority", "LOW"),
                'control_status': evidence.get("control_status", "UNKNOWN"),
                'risk_score': evidence.get("ai_risk_score", 0),
                'risk_level': "HIGH" if evidence.get("ai_risk_score", 0) > 7 else "MEDIUM" if evidence.get("ai_risk_score", 0) > 4 else "LOW",
                'finding_title': evidence.get("finding_title", "N/A"),
                'finding_description': evidence.get("finding_description", "N/A"),
                'compliance_frameworks': frameworks,
                'remediation_available': "Yes" if evidence.get("remediation_status") == "PENDING" else "No",
                'remediation_action': evidence.get("remediation_action", "N/A"),
                'user_identity': evidence.get("user_identity", {}).get("username", "N/A"),
                'source_ip': evidence.get("source_ip_address", "N/A"),
                'aws_region': evidence.get("aws_region", "N/A"),
                'ai_analyzed': "Yes" if evidence.get("ai_analyzed") else "No",
                'model_used': evidence.get("ai_model_used", "N/A"),
                'collected_at': evidence.get("created_at", "N/A")
            }
            findings_data.append(finding)

        # Prepare remediations data for Excel
        remediations_data = []
        for remediation in remediation_list:
            remediations_data.append({
                'id': remediation.get("id", "N/A"),
                'resource_id': remediation.get("resource_id", "N/A"),
                'resource_type': remediation.get("resource_type", "N/A"),
                'remediation_type': remediation.get("remediation_type", "N/A"),
                'execution_mode': remediation.get("execution_mode", "DRY_RUN"),
                'status': remediation.get("action_status", "PENDING"),
                'action_taken': remediation.get("action_taken", "N/A"),
                'result': remediation.get("result", "N/A"),
                'error': remediation.get("error_message", "N/A"),
                'triggered_by': remediation.get("triggered_by", "N/A"),
                'triggered_at': remediation.get("created_at", "N/A"),
                'completed_at': remediation.get("updated_at", "N/A"),
                'success': remediation.get("action_status") == "SUCCESS"
            })

        # Prepare compliance data for Excel
        compliance_frameworks = []
        for fc in audit_report.framework_coverage:
            compliance_frameworks.append({
                'framework_name': fc['framework_name'],
                'version': '1.0',
                'total_controls': fc['total_tested'],
                'passed': fc['passing'],
                'failed': fc['failing'],
                'not_applicable': 0,
                'compliance_percentage': round(fc['score'], 2),
                'status': 'COMPLIANT' if fc['score'] >= 80 else 'NON_COMPLIANT'
            })

        # Prepare summary data for Excel
        summary_data = {
            'report_period': f"{audit_report.report_period_start} to {audit_report.report_period_end}",
            'overall_risk_score': audit_report.overall_risk_score,
            'total_evidence': audit_report.evidence_collection_summary['total_records'],
            'critical_findings': len([f for f in audit_report.critical_high_findings if f['priority'] == 'CRITICAL']),
            'high_findings': len([f for f in audit_report.critical_high_findings if f['priority'] == 'HIGH']),
            'successful_remediations': sum(1 for r in remediation_list if r.get("action_status") == "SUCCESS"),
            'failed_remediations': sum(1 for r in remediation_list if r.get("action_status") == "FAILED"),
            'compliance_score': round(100 - audit_report.overall_risk_score, 2)
        }

        # Generate comprehensive Excel report
        generator.generate_comprehensive_report(
            findings=findings_data,
            remediations=remediations_data,
            compliance_data={'frameworks': compliance_frameworks},
            summary_data=summary_data
        )

        # Get Excel bytes
        excel_bytes = generator.get_workbook_bytes()
        logger.info(f"{Colors.OKGREEN}Excel report generated successfully{Colors.ENDC}")

        return excel_bytes

    except Exception as e:
        logger.error(f"{Colors.FAIL}Failed to generate Excel report: {e}{Colors.ENDC}")
        logger.exception(f"{Colors.FAIL}Full traceback:{Colors.ENDC}")
        return None


def generate_audit_report(
    account_id: str,
    start_date: datetime,
    end_date: datetime,
    evidence_list: List[Dict[str, Any]],
    remediation_list: List[Dict[str, Any]],
    scorecards: List[Dict[str, Any]],
) -> AuditReport:
    """
    Generate comprehensive audit report.

    Args:
        account_id: AWS account ID
        start_date: Start of audit period
        end_date: End of audit period
        evidence_list: List of evidence records
        remediation_list: List of remediation records
        scorecards: List of scorecard records

    Returns:
        Audit report
    """
    # Calculate overall risk score (inverse of compliance score)
    total_tested = len(evidence_list)
    failing = sum(1 for e in evidence_list if e.get("control_status") != "PASS")
    compliance_score = (
        ((total_tested - failing) / total_tested * 100) if total_tested > 0 else 100.0
    )
    overall_risk_score = 100 - compliance_score

    # Get top 5 risks
    critical_high = get_critical_high_findings(evidence_list)
    top_5_risks = critical_high[:5]

    # Generate trend data
    trend_data = generate_trend_data(scorecards)

    # Calculate framework coverage
    framework_coverage = calculate_framework_coverage(evidence_list)

    # Generate summaries
    evidence_summary = generate_evidence_collection_summary(evidence_list)
    appendix = generate_appendix(evidence_list)

    # Format remediation log
    auto_remediation_log = [
        {
            "id": r.get("id"),
            "remediation_type": r.get("remediation_type"),
            "resource_id": r.get("resource_id"),
            "finding_title": r.get("finding_title"),
            "action_status": r.get("action_status"),
            "action_timestamp": r.get("action_timestamp"),
            "execution_mode": r.get("execution_mode"),
        }
        for r in remediation_list
    ]

    return AuditReport(
        # Cover Page
        account_id=account_id,
        report_period_start=start_date.date().isoformat(),
        report_period_end=end_date.date().isoformat(),
        generated_date=datetime.utcnow().isoformat(),
        classification="CONFIDENTIAL",
        # Executive Summary
        overall_risk_score=round(overall_risk_score, 2),
        trend_data=trend_data,
        top_5_risks=top_5_risks,
        # Framework Coverage
        framework_coverage=framework_coverage,
        # Critical & High Findings
        critical_high_findings=critical_high,
        # Evidence Collection Summary
        evidence_collection_summary=evidence_summary,
        # Auto-Remediation Log
        auto_remediation_log=auto_remediation_log,
        # Appendix
        appendix=appendix,
    )


def store_report(
    s3_client: Any,
    bucket_name: str,
    report_date: str,
    audit_report: AuditReport,
    csv_matrix: str,
    excel_bytes: Optional[bytes] = None,
) -> Dict[str, str]:
    """
    Store audit report, CSV matrix, and Excel report to S3.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: S3 bucket name
        report_date: Report date string
        audit_report: Audit report object
        csv_matrix: CSV evidence matrix string
        excel_bytes: Optional Excel report bytes

    Returns:
        Dictionary with S3 paths
    """
    s3_paths = {}

    # Store JSON report
    json_key = f"reports/{report_date}/audit-report-{report_date}.json"
    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=json_key,
            Body=json.dumps(asdict(audit_report), indent=2),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        s3_paths["json_report"] = f"s3://{bucket_name}/{json_key}"
        logger.info(
            f"{Colors.OKGREEN}JSON report stored: {s3_paths['json_report']}{Colors.ENDC}"
        )
    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to store JSON report: {e}{Colors.ENDC}")

    # Store CSV matrix
    csv_key = f"reports/{report_date}/evidence-matrix-{report_date}.csv"
    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=csv_key,
            Body=csv_matrix,
            ContentType="text/csv",
            ServerSideEncryption="AES256",
        )
        s3_paths["csv_matrix"] = f"s3://{bucket_name}/{csv_key}"
        logger.info(
            f"{Colors.OKGREEN}CSV matrix stored: {s3_paths['csv_matrix']}{Colors.ENDC}"
        )
    except ClientError as e:
        logger.error(f"{Colors.FAIL}Failed to store CSV matrix: {e}{Colors.ENDC}")

    # Store Excel report if available
    if excel_bytes:
        excel_key = f"reports/{report_date}/grc-evidence-report-{report_date}.xlsx"
        try:
            s3_client.put_object(
                Bucket=bucket_name,
                Key=excel_key,
                Body=excel_bytes,
                ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ServerSideEncryption="AES256",
            )
            s3_paths["excel_report"] = f"s3://{bucket_name}/{excel_key}"
            logger.info(
                f"{Colors.OKGREEN}Excel report stored: {s3_paths['excel_report']}{Colors.ENDC}"
            )
        except ClientError as e:
            logger.error(f"{Colors.FAIL}Failed to store Excel report: {e}{Colors.ENDC}")

    return s3_paths


def generate_presigned_url(
    s3_client: Any, bucket_name: str, key: str, expiry_seconds: int = 604800  # 7 days
) -> Optional[str]:
    """
    Generate pre-signed URL for S3 object.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: S3 bucket name
        key: S3 object key
        expiry_seconds: URL expiry time in seconds

    Returns:
        Pre-signed URL or None if generation fails
    """
    try:
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": key},
            ExpiresIn=expiry_seconds,
        )
        return url
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to generate pre-signed URL: {e}{Colors.ENDC}"
        )
        return None


def send_report_notification(
    sns_client: Any,
    topic_arn: str,
    audit_report: AuditReport,
    s3_paths: Dict[str, str],
    presigned_urls: Dict[str, str],
) -> None:
    """
    Send SNS notification with report links.

    Args:
        sns_client: Boto3 SNS client
        topic_arn: SNS topic ARN
        audit_report: Audit report object
        s3_paths: Dictionary of S3 paths
        presigned_urls: Dictionary of pre-signed URLs
    """
    subject = f"[GRC Audit Report] {audit_report.report_period_start} to {audit_report.report_period_end}"

    # Build framework coverage section
    framework_section = "\n".join(
        [
            f"  • {fc['framework_name']}: {fc['score']}% ({fc['passing']}/{fc['total_tested']} passing)"
            for fc in audit_report.framework_coverage
        ]
    )

    # Build top risks section
    risks_section = "\n".join(
        [
            f"  {i+1}. [{risk['priority']}] {risk['finding_title']} - {risk['remediation_status']}"
            for i, risk in enumerate(audit_report.top_5_risks)
        ]
    )

    # Build report downloads section
    downloads_section = f"""REPORT DOWNLOADS
----------------
JSON Report (valid for 7 days):
{presigned_urls.get('json_report', s3_paths.get('json_report', 'N/A'))}

CSV Evidence Matrix (valid for 7 days):
{presigned_urls.get('csv_matrix', s3_paths.get('csv_matrix', 'N/A'))}"""

    # Add Excel report link if available
    if 'excel_report' in s3_paths:
        downloads_section += f"""

Excel Report (valid for 7 days):
{presigned_urls.get('excel_report', s3_paths.get('excel_report', 'N/A'))}"""

    downloads_section += "\n\nView the full report in the GRC Platform console."

    message = f"""
GRC Platform - Audit Report Available
======================================

Report Period: {audit_report.report_period_start} to {audit_report.report_period_end}
Generated: {audit_report.generated_date}
Classification: {audit_report.classification}
Account: {audit_report.account_id}

EXECUTIVE SUMMARY
-----------------
Overall Risk Score: {audit_report.overall_risk_score}%
Critical Findings: {len([f for f in audit_report.critical_high_findings if f['priority'] == 'CRITICAL'])}
High Findings: {len([f for f in audit_report.critical_high_findings if f['priority'] == 'HIGH'])}
Total Evidence: {audit_report.evidence_collection_summary['total_records']}
SLA Adherence: {audit_report.evidence_collection_summary['sla_adherence_percent']}%

FRAMEWORK COVERAGE
------------------
{framework_section}

TOP 5 RISKS
-----------
{risks_section if risks_section else "  No critical or high risks detected."}

EVIDENCE COLLECTION SUMMARY
---------------------------
Total Records: {audit_report.evidence_collection_summary['total_records']}
  • CRITICAL: {audit_report.evidence_collection_summary['records_by_priority']['CRITICAL']}
  • HIGH: {audit_report.evidence_collection_summary['records_by_priority']['HIGH']}
  • MEDIUM: {audit_report.evidence_collection_summary['records_by_priority']['MEDIUM']}
  • LOW: {audit_report.evidence_collection_summary['records_by_priority']['LOW']}

Auto-Remediations: {len(audit_report.auto_remediation_log)}
  • Successful: {sum(1 for r in audit_report.auto_remediation_log if r['action_status'] == 'SUCCESS')}
  • Failed: {sum(1 for r in audit_report.auto_remediation_log if r['action_status'] == 'FAILED')}

{downloads_section}
"""

    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
            MessageStructure="string",
        )
        logger.info(f"{Colors.WARNING}Report notification sent via SNS{Colors.ENDC}")
    except ClientError as e:
        logger.error(
            f"{Colors.FAIL}Failed to send report notification: {e}{Colors.ENDC}"
        )


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for audit report generation.

    Args:
        event: Event containing report parameters (from EventBridge or direct invoke)
        context: Lambda context object

    Returns:
        HTTP response with status code and result
    """
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(f"{Colors.HEADER}Audit Report Exporter Lambda Invoked{Colors.ENDC}")
    logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    logger.info(
        f"{Colors.OKCYAN}Event received: {json.dumps(event, indent=2)}{Colors.ENDC}"
    )

    # Get environment variables
    report_bucket = os.environ.get("REPORT_BUCKET")
    evidence_table = os.environ.get("EVIDENCE_DYNAMODB_TABLE")
    remediation_table = os.environ.get("REMEDIATION_DYNAMODB_TABLE")
    scorecard_bucket = os.environ.get("SCORECARD_BUCKET")
    sns_topic_arn = os.environ.get("REPORT_SNS_TOPIC")
    evidence_gsi = os.environ.get("EVIDENCE_TIMESTAMP_GSI", "created_at-index")
    account_id = os.environ.get(
        "AWS_ACCOUNT_ID", boto3.client("sts").get_caller_identity()["Account"]
    )

    if not all(
        [
            report_bucket,
            evidence_table,
            remediation_table,
            scorecard_bucket,
            sns_topic_arn,
        ]
    ):
        error_msg = "Missing required environment variables: REPORT_BUCKET, EVIDENCE_DYNAMODB_TABLE, REMEDIATION_DYNAMODB_TABLE, SCORECARD_BUCKET, REPORT_SNS_TOPIC"
        logger.error(f"{Colors.FAIL}{error_msg}{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}

    # Initialize AWS clients
    s3_client = boto3.client("s3")
    dynamodb_client = boto3.client("dynamodb")
    sns_client = boto3.client("sns")

    try:
        # Determine report period (default to last 7 days)
        if "report_period_days" in event:
            days = event["report_period_days"]
        else:
            days = 7

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        report_date = end_date.date().isoformat()

        logger.info(
            f"{Colors.OKCYAN}Generating audit report for period: {start_date.date()} to {end_date.date()}{Colors.ENDC}"
        )

        # Query data
        evidence_list = query_evidence_for_period(
            dynamodb_client, evidence_table, start_date, end_date, evidence_gsi
        )

        remediation_list = query_remediations_for_period(
            dynamodb_client, remediation_table, start_date, end_date
        )

        scorecards = query_scorecards_for_period(
            s3_client, scorecard_bucket, start_date, end_date
        )

        # Generate audit report
        audit_report = generate_audit_report(
            account_id,
            start_date,
            end_date,
            evidence_list,
            remediation_list,
            scorecards,
        )

        # Generate CSV evidence matrix
        csv_matrix = generate_csv_evidence_matrix(evidence_list, remediation_list)

        # Generate Excel report
        excel_bytes = generate_excel_report(
            evidence_list,
            remediation_list,
            scorecards,
            audit_report
        )

        # Store reports to S3
        s3_paths = store_report(
            s3_client, report_bucket, report_date, audit_report, csv_matrix, excel_bytes
        )

        # Generate pre-signed URLs
        presigned_urls = {}
        if "json_report" in s3_paths:
            json_key = s3_paths["json_report"].replace(f"s3://{report_bucket}/", "")
            presigned_urls["json_report"] = generate_presigned_url(
                s3_client, report_bucket, json_key
            )

        if "csv_matrix" in s3_paths:
            csv_key = s3_paths["csv_matrix"].replace(f"s3://{report_bucket}/", "")
            presigned_urls["csv_matrix"] = generate_presigned_url(
                s3_client, report_bucket, csv_key
            )

        if "excel_report" in s3_paths:
            excel_key = s3_paths["excel_report"].replace(f"s3://{report_bucket}/", "")
            presigned_urls["excel_report"] = generate_presigned_url(
                s3_client, report_bucket, excel_key
            )

        # Send notification
        send_report_notification(
            sns_client, sns_topic_arn, audit_report, s3_paths, presigned_urls
        )

        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        logger.info(f"{Colors.OKGREEN}Audit report generated successfully{Colors.ENDC}")
        logger.info(
            f"{Colors.OKGREEN}Report Period: {start_date.date()} to {end_date.date()}{Colors.ENDC}"
        )
        logger.info(
            f"{Colors.OKGREEN}Overall Risk Score: {audit_report.overall_risk_score}%{Colors.ENDC}"
        )
        logger.info(
            f"{Colors.OKGREEN}Total Evidence: {audit_report.evidence_collection_summary['total_records']}{Colors.ENDC}"
        )
        logger.info(
            f"{Colors.OKGREEN}Critical/High Findings: {len(audit_report.critical_high_findings)}{Colors.ENDC}"
        )
        logger.info(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Audit report generated successfully",
                    "report_date": report_date,
                    "report_period": {
                        "start": start_date.date().isoformat(),
                        "end": end_date.date().isoformat(),
                    },
                    "overall_risk_score": audit_report.overall_risk_score,
                    "total_evidence": audit_report.evidence_collection_summary[
                        "total_records"
                    ],
                    "critical_high_findings": len(audit_report.critical_high_findings),
                    "s3_paths": s3_paths,
                    "presigned_urls": presigned_urls,
                }
            ),
        }

    except Exception as e:
        logger.error(
            f"{Colors.FAIL}Error generating audit report: {str(e)}{Colors.ENDC}"
        )
        logger.exception(f"{Colors.FAIL}Full traceback:{Colors.ENDC}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
