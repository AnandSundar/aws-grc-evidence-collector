#!/usr/bin/env python3
"""
GRC Evidence Platform - Simple CSV Report Generator

Windows-friendly script to generate CSV reports from AWS DynamoDB data.
Usage: python scripts/generate_csv_report.py
"""

import csv
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


def create_aws_clients():
    """Create AWS clients."""
    session = boto3.Session()
    dynamodb = session.client('dynamodb')
    s3 = session.client('s3')
    sts = session.client('sts')

    # Get account ID
    account_id = sts.get_caller_identity()['Account']

    return dynamodb, s3, account_id


def scan_dynamodb_table(dynamodb, table_name):
    """Scan entire DynamoDB table and return all items."""
    items = []

    try:
        paginator = dynamodb.get_paginator('scan')
        for page in paginator.paginate(TableName=table_name):
            for item in page.get('Items', []):
                # Convert DynamoDB format to regular dict
                converted = {}
                for key, value in item.items():
                    if 'S' in value:
                        converted[key] = value['S']
                    elif 'N' in value:
                        converted[key] = value['N']
                    elif 'BOOL' in value:
                        converted[key] = str(value['BOOL'])
                    elif 'M' in value:
                        converted[key] = json.dumps(value['M'])
                    elif 'L' in value:
                        converted[key] = json.dumps(value['L'])
                    elif 'NULL' in value:
                        converted[key] = ''
                    else:
                        converted[key] = str(value)
                items.append(converted)

    except ClientError as e:
        print(f"Error scanning table {table_name}: {e}")

    return items


def generate_findings_csv(metadata_items, output_file):
    """Generate CSV report for findings/evidence."""
    if not metadata_items:
        print("No findings data available")
        return False

    # Get all possible columns
    all_columns = set()
    for item in metadata_items:
        all_columns.update(item.keys())

    # Define desired column order
    preferred_columns = [
        'event_id', 'event_name', 'event_time', 'priority',
        'control_status', 'finding_title', 'description',
        'aws_region', 'source_ip_address', 'created_at'
    ]

    # Add any remaining columns
    columns = [col for col in preferred_columns if col in all_columns]
    remaining_columns = sorted(all_columns - set(columns))
    columns.extend(remaining_columns)

    # Write CSV
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(metadata_items)

    print(f"Generated findings CSV: {output_file} ({len(metadata_items)} records)")
    return True


def generate_remediations_csv(remediation_items, output_file):
    """Generate CSV report for remediation actions."""
    if not remediation_items:
        print("No remediation data available")
        return False

    # Get all possible columns
    all_columns = set()
    for item in remediation_items:
        all_columns.update(item.keys())

    # Define desired column order
    preferred_columns = [
        'remediation_id', 'resource_id', 'remediation_type',
        'status', 'execution_mode', 'action_taken',
        'triggered_at', 'completed_at'
    ]

    # Add any remaining columns
    columns = [col for col in preferred_columns if col in all_columns]
    remaining_columns = sorted(all_columns - set(columns))
    columns.extend(remaining_columns)

    # Write CSV
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(remediation_items)

    print(f"Generated remediations CSV: {output_file} ({len(remediation_items)} records)")
    return True


def upload_to_s3(s3, bucket, file_path, account_id):
    """Upload CSV file to S3."""
    try:
        filename = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y/%m/%d/%H/%M/%S")
        key = f"reports/{timestamp}/{filename}"

        s3.upload_file(file_path, bucket, key)
        print(f"Uploaded to S3: s3://{bucket}/{key}")
        return True

    except ClientError as e:
        print(f"Error uploading to S3: {e}")
        return False


def main():
    """Main function to generate CSV reports."""
    print("="*60)
    print("GRC Evidence Platform - CSV Report Generator")
    print("="*60)

    try:
        # Create AWS clients
        print("\n1. Connecting to AWS...")
        dynamodb, s3, account_id = create_aws_clients()
        print(f"   Connected to AWS Account: {account_id}")

        # Define table names
        metadata_table = "grc-evidence-platform-metadata-dev"
        remediation_table = "grc-evidence-platform-remediation-logs-dev"
        reports_bucket = f"grc-evidence-platform-reports-{account_id}-us-east-1"

        # Generate output filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)

        # Query findings/evidence data
        print(f"\n2. Querying findings from {metadata_table}...")
        findings = scan_dynamodb_table(dynamodb, metadata_table)
        print(f"   Found {len(findings)} findings")

        if findings:
            findings_file = output_dir / f"grc_findings_{timestamp}.csv"
            generate_findings_csv(findings, findings_file)

            # Upload to S3
            upload_to_s3(s3, reports_bucket, str(findings_file), account_id)
        else:
            print("   No findings to export")

        # Query remediation data
        print(f"\n3. Querying remediations from {remediation_table}...")
        remediations = scan_dynamodb_table(dynamodb, remediation_table)
        print(f"   Found {len(remediations)} remediation records")

        if remediations:
            remediation_file = output_dir / f"grc_remediations_{timestamp}.csv"
            generate_remediations_csv(remediations, remediation_file)

            # Upload to S3
            upload_to_s3(s3, reports_bucket, str(remediation_file), account_id)
        else:
            print("   No remediations to export")

        print("\n" + "="*60)
        print("CSV Report Generation Complete!")
        print("="*60)

        if findings or remediations:
            print(f"\nFiles saved to: {output_dir.absolute()}")
            print(f"S3 Bucket: {reports_bucket}")

            # Show file sizes
            if findings:
                size_kb = os.path.getsize(findings_file) / 1024
                print(f"  - {findings_file.name}: {size_kb:.2f} KB")
            if remediations:
                size_kb = os.path.getsize(remediation_file) / 1024
                print(f"  - {remediation_file.name}: {size_kb:.2f} KB")
        else:
            print("\nNo data available to export.")
            print("Tables are empty - run some evidence collectors first!")

        print("\nHow to view CSV files:")
        print("  - Open in Excel: Double-click the CSV file")
        print("  - Download from S3: aws s3 cp s3://{bucket}/reports/ . --recursive".format(bucket=reports_bucket))

        return 0

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())