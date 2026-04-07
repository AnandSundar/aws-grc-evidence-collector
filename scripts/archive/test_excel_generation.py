#!/usr/bin/env python3
"""
Test script for Excel report generation.

This script tests the Excel generation functionality with sample data
to verify that the Excel generator works correctly.

Usage:
    python scripts/test_excel_generation.py
"""

import sys
import os
from datetime import datetime
from typing import Dict, Any, List

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from reports.excel_generator import ExcelReportGenerator
    print("[OK] Excel generator imported successfully")
except ImportError as e:
    print(f"[ERROR] Failed to import Excel generator: {e}")
    sys.exit(1)


def create_sample_findings() -> List[Dict[str, Any]]:
    """Create sample finding data for testing."""
    return [
        {
            'evidence_id': 'EVID-001',
            'event_name': 'CreateUser',
            'event_time': '2026-04-06T10:30:00Z',
            'resource_type': 'IAM User',
            'resource_id': 'arn:aws:iam::123456789012:user/test-user',
            'priority': 'HIGH',
            'control_status': 'FAIL',
            'risk_score': 8.5,
            'risk_level': 'HIGH',
            'finding_title': 'IAM user without MFA',
            'finding_description': 'IAM user test-user does not have MFA enabled',
            'compliance_frameworks': ['PCI-DSS', 'SOC2', 'NIST'],
            'remediation_available': 'Yes',
            'remediation_action': 'Enable MFA for user',
            'user_identity': 'admin@example.com',
            'source_ip': '192.168.1.100',
            'aws_region': 'us-east-1',
            'ai_analyzed': 'Yes',
            'model_used': 'bedrock-claude-v2',
            'collected_at': '2026-04-06T10:35:00Z'
        },
        {
            'evidence_id': 'EVID-002',
            'event_name': 'CreateBucket',
            'event_time': '2026-04-06T11:45:00Z',
            'resource_type': 'S3 Bucket',
            'resource_id': 'arn:aws:s3:::test-bucket',
            'priority': 'CRITICAL',
            'control_status': 'FAIL',
            'risk_score': 9.2,
            'risk_level': 'HIGH',
            'finding_title': 'S3 bucket public access',
            'finding_description': 'S3 bucket test-bucket is configured for public access',
            'compliance_frameworks': ['PCI-DSS', 'SOC2', 'NIST', 'CIS'],
            'remediation_available': 'Yes',
            'remediation_action': 'Block public access',
            'user_identity': 'admin@example.com',
            'source_ip': '192.168.1.100',
            'aws_region': 'us-east-1',
            'ai_analyzed': 'Yes',
            'model_used': 'bedrock-claude-v2',
            'collected_at': '2026-04-06T11:50:00Z'
        },
        {
            'evidence_id': 'EVID-003',
            'event_name': 'CreateDBInstance',
            'event_time': '2026-04-06T12:15:00Z',
            'resource_type': 'RDS Instance',
            'resource_id': 'arn:aws:rds:us-east-1:123456789012:db/test-db',
            'priority': 'MEDIUM',
            'control_status': 'PASS',
            'risk_score': 3.5,
            'risk_level': 'MEDIUM',
            'finding_title': 'RDS instance encryption',
            'finding_description': 'RDS instance test-db has encryption enabled',
            'compliance_frameworks': ['PCI-DSS', 'SOC2', 'NIST'],
            'remediation_available': 'No',
            'remediation_action': 'N/A',
            'user_identity': 'dbadmin@example.com',
            'source_ip': '192.168.1.200',
            'aws_region': 'us-east-1',
            'ai_analyzed': 'Yes',
            'model_used': 'bedrock-claude-v2',
            'collected_at': '2026-04-06T12:20:00Z'
        }
    ]


def create_sample_remediations() -> List[Dict[str, Any]]:
    """Create sample remediation data for testing."""
    return [
        {
            'id': 'REM-001',
            'resource_id': 'arn:aws:iam::123456789012:user/test-user',
            'resource_type': 'IAM User',
            'remediation_type': 'EnableMFA',
            'execution_mode': 'AUTO',
            'status': 'SUCCESS',
            'action_taken': 'Enabled virtual MFA device for user',
            'result': 'MFA successfully enabled',
            'error': 'N/A',
            'triggered_by': 'lambda-remediation-engine',
            'triggered_at': '2026-04-06T10:40:00Z',
            'completed_at': '2026-04-06T10:42:00Z',
            'success': True
        },
        {
            'id': 'REM-002',
            'resource_id': 'arn:aws:s3:::test-bucket',
            'resource_type': 'S3 Bucket',
            'remediation_type': 'BlockPublicAccess',
            'execution_mode': 'DRY_RUN',
            'status': 'PENDING',
            'action_taken': 'Would block public access',
            'result': 'Action logged (DRY_RUN mode)',
            'error': 'N/A',
            'triggered_by': 'lambda-remediation-engine',
            'triggered_at': '2026-04-06T11:55:00Z',
            'completed_at': '2026-04-06T11:55:00Z',
            'success': False
        }
    ]


def create_sample_compliance_data() -> Dict[str, Any]:
    """Create sample compliance data for testing."""
    return {
        'report_period': '2026-04-01 to 2026-04-06',
        'frameworks': [
            {
                'framework_name': 'PCI-DSS',
                'version': '4.0',
                'total_controls': 45,
                'passed': 42,
                'failed': 3,
                'not_applicable': 0,
                'compliance_percentage': 93.33,
                'status': 'COMPLIANT'
            },
            {
                'framework_name': 'SOC 2',
                'version': '2017',
                'total_controls': 38,
                'passed': 35,
                'failed': 3,
                'not_applicable': 0,
                'compliance_percentage': 92.11,
                'status': 'COMPLIANT'
            },
            {
                'framework_name': 'NIST 800-53',
                'version': 'Rev 5',
                'total_controls': 62,
                'passed': 55,
                'failed': 7,
                'not_applicable': 0,
                'compliance_percentage': 88.71,
                'status': 'COMPLIANT'
            },
            {
                'framework_name': 'CIS AWS',
                'version': '1.5',
                'total_controls': 95,
                'passed': 78,
                'failed': 17,
                'not_applicable': 0,
                'compliance_percentage': 82.11,
                'status': 'NON_COMPLIANT'
            }
        ]
    }


def create_sample_summary_data() -> Dict[str, Any]:
    """Create sample summary data for testing."""
    return {
        'report_period': '2026-04-01 to 2026-04-06',
        'overall_risk_score': 15.5,
        'total_evidence': 3,
        'critical_findings': 1,
        'high_findings': 1,
        'successful_remediations': 1,
        'failed_remediations': 0,
        'compliance_score': 84.5
    }


def test_excel_generation():
    """Test the Excel generation functionality."""
    print("\n" + "="*60)
    print("Testing Excel Report Generation")
    print("="*60)

    try:
        # Create sample data
        print("\n1. Creating sample data...")
        findings = create_sample_findings()
        remediations = create_sample_remediations()
        compliance_data = create_sample_compliance_data()
        summary_data = create_sample_summary_data()
        print(f"   [OK] {len(findings)} findings")
        print(f"   [OK] {len(remediations)} remediations")
        print(f"   [OK] {len(compliance_data['frameworks'])} compliance frameworks")

        # Create Excel generator
        print("\n2. Initializing Excel generator...")
        generator = ExcelReportGenerator()
        print("   [OK] Generator initialized")

        # Generate comprehensive report
        print("\n3. Generating comprehensive Excel report...")
        generator.generate_comprehensive_report(
            findings=findings,
            remediations=remediations,
            compliance_data=compliance_data,
            summary_data=summary_data
        )
        print("   [OK] Report generated successfully")

        # Save to file
        print("\n4. Saving Excel report to file...")
        output_file = f"test_grc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        generator.save_workbook(output_file)
        print(f"   [OK] Report saved to: {output_file}")

        # Get as bytes (for S3 upload simulation)
        print("\n5. Testing Excel bytes generation...")
        excel_bytes = generator.get_workbook_bytes()
        print(f"   [OK] Generated {len(excel_bytes)} bytes")
        print(f"   [OK] Size: {len(excel_bytes) / 1024:.2f} KB")

        print("\n" + "="*60)
        print("[SUCCESS] All tests passed successfully!")
        print("="*60)

        print("\nExcel Report Structure:")
        print("  1. Summary Sheet - Executive summary with key metrics")
        print("  2. Findings Sheet - All evidence findings with details")
        print("  3. Remediation Sheet - Auto-remediation actions and status")
        print("  4. Compliance Sheet - Framework compliance status")

        print(f"\nYou can open the generated file: {output_file}")
        print("\nNext steps:")
        print("  - Deploy the updated Lambda functions to AWS")
        print("  - Trigger the report exporter Lambda")
        print("  - Find the Excel report in S3 reports bucket")
        print("  - Download and review the comprehensive Excel report")

        return True

    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    print("\nGRC Platform - Excel Generation Test")
    print("Testing Excel report generation functionality...")

    success = test_excel_generation()

    if success:
        print("\n[SUCCESS] Excel generation is working correctly!")
        print("You can now deploy and test in your AWS environment.")
        return 0
    else:
        print("\n[ERROR] Excel generation test failed.")
        print("Please check the error messages above and fix any issues.")
        return 1


if __name__ == "__main__":
    sys.exit(main())