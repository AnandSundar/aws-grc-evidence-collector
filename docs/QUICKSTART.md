# GRC Evidence Platform v2.0 - Quick Start Guide

Get the GRC Evidence Platform up and running in under 5 minutes with this 3-step deployment guide.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Step 1: Install Dependencies](#step-1-install-dependencies)
3. [Step 2: Deploy Platform](#step-2-deploy-platform)
4. [Step 3: Run Collectors](#step-3-run-collectors)
5. [Verify Deployment](#verify-deployment)
6. [Next Steps](#next-steps)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, ensure you have the following:

### Required

- **AWS Account**: Active AWS account with administrator access
- **Python 3.11+**: Installed and accessible via command line
- **boto3**: AWS SDK for Python (will be installed)
- **AWS CLI**: Configured with credentials and default region
- **Git**: For cloning the repository (optional)

### Optional

- **AWS Free Tier**: To minimize costs during testing
- **AWS SES Verified Email**: For email alerts (can be configured later)
- **AWS Bedrock Access**: For AI-powered risk analysis (optional)

### Verify Prerequisites

```bash
# Check Python version
python --version
# Expected output: Python 3.11.x or higher

# Check AWS CLI version
aws --version
# Expected output: aws-cli/2.x.x

# Verify AWS credentials
aws sts get-caller-identity
# Expected output: JSON with AccountId, UserId, Arn

# Check default region
aws configure get region
# Expected output: e.g., us-east-1
```

If AWS CLI is not configured, run:

```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Enter your default region (e.g., us-east-1)
# Enter your default output format (json)
```

---

## Step 1: Install Dependencies

Clone the repository and install Python dependencies.

### Clone the Repository

```bash
# If using Git
git clone https://github.com/your-org/aws-grc-evidence-collector.git
cd aws-grc-evidence-collector

# Or download and extract the ZIP file
# Navigate to the extracted directory
```

### Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Install Dependencies

```bash
# Install Python packages
pip install -r requirements.txt

# Expected output:
# Collecting boto3
# Collecting botocore
# Collecting pytest
# ...
# Successfully installed boto3-1.x.x botocore-1.x.x pytest-7.x.x ...
```

### Verify Installation

```bash
# Verify key packages are installed
python -c "import boto3; print('boto3 version:', boto3.__version__)"
python -c "import pytest; print('pytest version:', pytest.__version__)"

# Expected output:
# boto3 version: 1.x.x
# pytest version: 7.x.x
```

---

## Step 2: Deploy Platform

Deploy the GRC Evidence Platform infrastructure using CloudFormation.

### Option A: Using Make (Recommended)

```bash
# Deploy all CloudFormation stacks
make deploy

# Expected output:
# Deploying GRC Evidence Platform...
# Creating CloudFormation stack: grc-evidence-platform
# Waiting for stack creation to complete...
# Stack creation completed successfully!
# Stack ID: arn:aws:cloudformation:us-east-1:123456789012:stack/grc-evidence-platform/xxxxx
```

### Option B: Using Python Script

```bash
# Deploy using Python script
python scripts/deploy_cloudformation.py

# Expected output:
# Initializing deployment...
# Validating CloudFormation templates...
# Creating stack: grc-evidence-platform
# Stack creation in progress...
# ✓ IAM Roles stack created
# ✓ Monitoring stack created
# ✓ GRC Platform stack created
# Deployment completed successfully!
```

### Option C: Using AWS CLI

```bash
# Deploy CloudFormation stack directly
aws cloudformation create-stack \
  --stack-name grc-evidence-platform \
  --template-body file://cloudformation/grc-platform-template.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters \
    ParameterKey=EnableAI,ParameterValue=false \
    ParameterKey=EnableMediumAlerts,ParameterValue=true \
    ParameterKey=EnableLowAlerts,ParameterValue=true

# Wait for stack creation
aws cloudformation wait stack-create-complete \
  --stack-name grc-evidence-platform

# Expected output:
# Stack creation completed successfully
```

### Deployment Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `EnableAI` | `false` | Enable AWS Bedrock AI analysis |
| `EnableMediumAlerts` | `true` | Enable MEDIUM priority alerts |
| `EnableLowAlerts` | `true` | Enable LOW priority alerts |
| `AlertEmail` | - | Email address for alerts (optional) |
| `FromEmail` | `no-reply@aws-grc.local` | From email address for alerts |

### Expected Deployment Time

- **IAM Roles Stack**: 1-2 minutes
- **Monitoring Stack**: 2-3 minutes
- **GRC Platform Stack**: 3-5 minutes
- **Total**: 5-10 minutes

---

## Step 3: Run Collectors

Run the evidence collectors to gather compliance evidence from your AWS account.

### Option A: Using Make (Recommended)

```bash
# Run all collectors
make collect

# Expected output:
# Starting evidence collection...
# ✓ IAMCollector collected 15 records
# ✓ RDSCollector collected 8 records
# ✓ S3Collector collected 12 records
# ✓ ConfigCollector collected 45 records
# ✓ SecurityHubCollector collected 23 records
# ✓ GuardDutyCollector collected 7 records
# ✓ VPCCollector collected 9 records
# ✓ KMSCollector collected 4 records
# ✓ ACMCollector collected 3 records
# ✓ MacieCollector collected 2 records
# ✓ InspectorCollector collected 6 records
# ✓ CloudTrailCollector collected 134 records
# Collection completed: 268 evidence records collected
```

### Option B: Using Python Script

```bash
# Run all collectors using Python script
python scripts/run_all_collectors.py

# Expected output:
# Initializing collectors...
# Running IAMCollector...
# Running RDSCollector...
# Running S3Collector...
# ...
# Evidence collection completed successfully!
# Total records: 268
# Records stored in S3: s3://grc-evidence-bucket-xxxxx/evidence/
# Metadata indexed in DynamoDB: grc-evidence-metadata
```

### Option C: Run Individual Collectors

```bash
# Run specific collectors
python -m collectors.iam_collector
python -m collectors.s3_collector
python -m collectors.rds_collector

# Expected output for IAMCollector:
# Starting IAM evidence collection...
# ✓ Root account MFA check: PASS
# ✓ User MFA check: 2 FAIL, 8 PASS
# ✓ Password policy check: PASS
# ✓ Access key rotation check: 1 FAIL, 14 PASS
# IAM collection complete: 15 records
```

### Collection Duration

- **Individual Collector**: 10-30 seconds
- **All Collectors**: 2-5 minutes
- **First Run**: May take longer due to initial API calls

---

## Verify Deployment

Verify that the platform is deployed and functioning correctly.

### Check CloudFormation Stack Status

```bash
# Check stack status
aws cloudformation describe-stacks \
  --stack-name grc-evidence-platform \
  --query 'Stacks[0].StackStatus' \
  --output text

# Expected output:
# CREATE_COMPLETE
```

### View CloudWatch Dashboard

```bash
# Open CloudWatch dashboard in browser
aws cloudwatch get-dashboard \
  --dashboard-name grc-evidence-platform \
  --query 'DashboardBody' \
  --output text > dashboard.json

# Or open directly in AWS Console:
# https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=grc-evidence-platform
```

### Verify S3 Bucket

```bash
# List S3 buckets created by the platform
aws s3 ls | grep grc-evidence

# Expected output:
# 2026-04-05 05:30:15 grc-evidence-bucket-123456789012
# 2026-04-05 05:30:20 grc-reports-bucket-123456789012

# Check evidence files
aws s3 ls s3://grc-evidence-bucket-123456789012/evidence/2026/04/05/

# Expected output:
# 2026-04-05 05:32:10    2345 550e8400-e29b-41d4-a716-446655440000.json
# 2026-04-05 05:32:12    1892 660e9500-f39c-52e5-b827-557766551111.json
# ...
```

### Verify DynamoDB Tables

```bash
# List DynamoDB tables
aws dynamodb list-tables --query 'TableNames[?contains(@, `grc`)]'

# Expected output:
# [
#     "grc-evidence-metadata",
#     "grc-pending-events",
#     "grc-scorecard",
#     "grc-rate-limit"
# ]

# Check metadata table
aws dynamodb describe-table --table-name grc-evidence-metadata --query 'Table.ItemCount'

# Expected output:
# 268
```

### Verify Lambda Functions

```bash
# List Lambda functions
aws lambda list-functions --query 'Functions[?contains(FunctionName, `grc`)].FunctionName'

# Expected output:
# [
#     "grc-handler",
#     "grc-handler-ai",
#     "grc-batch-processor",
#     "grc-evidence-processor",
#     "grc-remediation-engine",
#     "grc-scorecard-generator",
#     "grc-report-exporter"
# ]

# Check Lambda function status
aws lambda get-function --function-name grc-handler --query 'Configuration.State'

# Expected output:
# "Active"
```

### Verify EventBridge Rules

```bash
# List EventBridge rules
aws events list-rules --query 'Rules[?contains(Name, `grc`)].Name'

# Expected output:
# [
#     "grc-high-priority-events",
#     "grc-medium-priority-events",
#     "grc-low-priority-events",
#     "grc-daily-scorecard",
#     "grc-hourly-evidence-processor"
# ]
```

### Test Event Flow

```bash
# Trigger a test event
aws events put-events --entries '[{
  "Source": "com.grc.test",
  "DetailType": "Test Event",
  "Detail": "{\"test\": \"data\"}"
}]'

# Expected output:
# {
#     "FailedEntryCount": 0,
#     "Entries": [
#         {
#             "EventId": "11710aed-b79e-4468-a20b-bb3c0c3b4820"
#         }
#     ]
# }
```

---

## Next Steps

Now that the platform is deployed and running, here are the recommended next steps:

### 1. Configure Alerts

Set up email notifications for compliance alerts.

```bash
# Update SNS topic subscription
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:grc-alerts \
  --protocol email \
  --notification-endpoint your-email@example.com

# Confirm subscription by clicking the link in the email
```

### 2. Customize Collectors

Modify collector configurations to match your compliance requirements.

```bash
# Edit collector configuration
vim collectors/iam_collector.py

# Adjust check thresholds, add custom checks, etc.
```

### 3. Review Findings

Access the CloudWatch dashboard to review compliance findings.

```bash
# Open CloudWatch dashboard
aws cloudwatch get-dashboard \
  --dashboard-name grc-evidence-platform \
  --output text > dashboard.json

# Or open in AWS Console:
# https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=grc-evidence-platform
```

### 4. Generate Reports

Generate your first compliance report.

```bash
# Generate PDF report
python scripts/generate_report.py --format pdf --output report.pdf

# Expected output:
# Generating compliance report...
# Querying evidence from last 24 hours...
# Calculating compliance scores...
# Generating PDF report...
# Report saved to: report.pdf
```

### 5. Enable AI Analysis (Optional)

Enable AWS Bedrock for intelligent risk scoring.

```bash
# Update CloudFormation stack with AI enabled
aws cloudformation update-stack \
  --stack-name grc-evidence-platform \
  --template-body file://cloudformation/grc-platform-template.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters ParameterKey=EnableAI,ParameterValue=true

# Wait for update to complete
aws cloudformation wait stack-update-complete \
  --stack-name grc-evidence-platform
```

### 6. Schedule Regular Collections

Set up a cron job or scheduled task to run collectors regularly.

```bash
# On Linux/macOS: Add to crontab
crontab -e

# Add line to run collectors daily at 2 AM UTC
0 2 * * * cd /path/to/aws-grc-evidence-collector && /path/to/venv/bin/python scripts/run_all_collectors.py >> /var/log/grc-collector.log 2>&1

# On Windows: Create scheduled task
schtasks /create /tn "GRC Evidence Collector" /tr "python C:\path\to\scripts\run_all_collectors.py" /sc daily /st 02:00
```

### 7. Explore Documentation

Read the comprehensive documentation to understand the platform in depth.

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - Architecture overview
- [`docs/COLLECTORS.md`](docs/COLLECTORS.md) - Collector documentation
- [`docs/REMEDIATION_PLAYBOOKS.md`](docs/REMEDIATION_PLAYBOOKS.md) - Auto-remediation guide
- [`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md) - Control mapping
- [`docs/COST_ANALYSIS.md`](docs/COST_ANALYSIS.md) - Cost breakdown
- [`docs/INTERVIEW_PREP.md`](docs/INTERVIEW_PREP.md) - Interview preparation

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: AWS Credentials Not Configured

**Error Message:**
```
Unable to locate credentials
```

**Solution:**
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### Issue: CloudFormation Stack Creation Failed

**Error Message:**
```
Stack creation failed: Resource creation failed
```

**Solution:**
```bash
# Check stack events for detailed error
aws cloudformation describe-stack-events \
  --stack-name grc-evidence-platform \
  --max-items 10

# Common issues:
# - Insufficient IAM permissions
# - Resource limits exceeded
# - Invalid parameter values
```

#### Issue: Lambda Function Timeout

**Error Message:**
```
Task timed out after 30.00 seconds
```

**Solution:**
```bash
# Increase Lambda timeout
aws lambda update-function-configuration \
  --function-name grc-handler \
  --timeout 60

# Increase Lambda memory
aws lambda update-function-configuration \
  --function-name grc-handler \
  --memory-size 512
```

#### Issue: S3 Bucket Access Denied

**Error Message:**
```
Access Denied: s3://grc-evidence-bucket-xxxxx
```

**Solution:**
```bash
# Check bucket policy
aws s3api get-bucket-policy --bucket grc-evidence-bucket-xxxxx

# Verify IAM role permissions
aws iam get-role-policy \
  --role-name grc-lambda-role \
  --policy-name grc-lambda-policy
```

#### Issue: DynamoDB Throttling

**Error Message:**
```
ProvisionedThroughputExceededException
```

**Solution:**
```bash
# Switch to on-demand capacity mode
aws dynamodb update-table \
  --table-name grc-evidence-metadata \
  --billing-mode PAY_PER_REQUEST
```

#### Issue: Collector Returns No Records

**Error Message:**
```
IAMCollector collected 0 records
```

**Solution:**
```bash
# Check AWS service access
aws iam list-users
aws s3 ls
aws rds describe-db-instances

# Verify collector is running correctly
python -m collectors.iam_collector --verbose

# Check CloudWatch logs
aws logs tail /aws/lambda/grc-handler --follow
```

#### Issue: Email Alerts Not Received

**Error Message:**
```
No email alerts received
```

**Solution:**
```bash
# Check SNS topic subscription
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:123456789012:grc-alerts

# Verify subscription is confirmed
# Status should be "Confirmed", not "PendingConfirmation"

# Check SES email verification
aws ses list-verified-email-addresses

# If using SES, verify email address first
aws ses verify-email-identity --email-address your-email@example.com
```

### Getting Help

If you encounter issues not covered here:

1. **Check CloudWatch Logs**: Review Lambda function logs for detailed error messages
2. **Review CloudFormation Events**: Check stack creation events for infrastructure issues
3. **Enable Debug Logging**: Set `LOG_LEVEL=DEBUG` in Lambda environment variables
4. **Consult Documentation**: Refer to the comprehensive documentation in the `docs/` directory
5. **Open an Issue**: Report bugs or request features on GitHub

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Set environment variable
export LOG_LEVEL=DEBUG

# Or update Lambda function environment
aws lambda update-function-configuration \
  --function-name grc-handler \
  --environment Variables={LOG_LEVEL=DEBUG}

# View logs in real-time
aws logs tail /aws/lambda/grc-handler --follow --format short
```

---

## Summary

Congratulations! You've successfully deployed the GRC Evidence Platform v2.0 in just 3 steps:

1. ✅ **Installed Dependencies**: Python packages and AWS CLI configured
2. ✅ **Deployed Platform**: CloudFormation stacks created successfully
3. ✅ **Ran Collectors**: Evidence collected from your AWS account

The platform is now actively monitoring your AWS environment for compliance issues. You can:

- View real-time compliance status in the CloudWatch dashboard
- Receive email alerts for high-priority security events
- Generate PDF reports for auditors
- Automate remediation of common security misconfigurations
- Track compliance trends over time with daily scorecards

For more information, explore the comprehensive documentation in the [`docs/`](docs/) directory.

---

**Estimated Total Time**: 5-10 minutes

**Estimated Cost**: $0-4.18/month (first 30 days: ~$0-2.88)

**Next Recommended Action**: Configure email alerts and review initial findings
