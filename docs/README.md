# AWS GRC Evidence Collector

An AI-powered Governance, Risk, and Compliance (GRC) evidence collector built on AWS. This serverless application automatically captures AWS API activity, classifies it by risk level, stores it as audit-ready evidence, and uses AWS Bedrock (Claude 3 Sonnet) for advanced risk analysis.

## Architecture

![Architecture](ARCHITECTURE.md)
*(See `docs/ARCHITECTURE.md` for the full ASCII diagram and data flow description)*

## Features

| Feature | Version 1 (Boto3) | Version 2 (CloudFormation + AI) |
|---|---|---|
| **Deployment** | Python Script (`setup.py`) | IaC (`deploy_cloudformation.py`) |
| **Event Routing** | EventBridge → Lambda | EventBridge → Lambda |
| **Evidence Storage** | S3 (Encrypted, Versioned) | S3 (Encrypted, Versioned, Lifecycle) |
| **Metadata Index** | DynamoDB (TTL 90 days) | DynamoDB (TTL 90 days) |
| **Alerting** | SNS (HIGH priority) | SNS (HIGH priority) |
| **AI Analysis** | ❌ None | ✅ Bedrock (Claude 3 Sonnet) |
| **Cost** | $0/month (Free Tier) | ~$0.78/month (Bedrock usage) |

## Prerequisites

- AWS Account
- AWS CLI configured (`aws configure`)
- Python 3.11+
- IAM permissions to create resources (S3, DynamoDB, Lambda, IAM, SNS, EventBridge, CloudTrail)
- (For Version 2) Model access requested for `nvidia.nemotron-nano-12b-v2` in AWS Bedrock (us-east-1)

## One-Command Deployment

### **Version 1: Python/Boto3 (Free Tier)**
Deploy the basic infrastructure without AI:
```bash
python setup.py
```

### **Version 2: CloudFormation + AI (Bedrock)**
Deploy the production-grade stack with AI enabled:
```bash
python deploy_cloudformation.py --ai --email your-email@example.com
```

### **Using AWS Profiles**
If you have multiple AWS profiles configured, you can specify which one to use with the `--profile` flag:

**Version 1:**
```bash
python setup.py --profile my-aws-profile
```

**Version 2:**
```bash
python deploy_cloudformation.py --ai --profile my-aws-profile
```

**Testing & Teardown:**
```bash
python test_events.py --profile my-aws-profile
python teardown.py --profile my-aws-profile
```

---

## Quick Start (Version 1 - No AI)

1. **Install dependencies:**
   ```bash
   pip install boto3
   ```
2. **Deploy resources:**
   ```bash
   python setup.py
   ```
3. **Test the system:**
   ```bash
   python test_events.py
   ```

## Enhanced Deploy (Version 2 - CloudFormation + AI)

1. **Run the deployment script:**
   ```bash
   python deploy_cloudformation.py
   ```
2. **Select Option 2** to deploy with AI enabled.
3. **Test the system:**
   ```bash
   python test_events.py
   ```

## Evidence Types

| Priority | Trigger Events | Compliance Frameworks | Action |
|---|---|---|---|
| **HIGH** | IAM changes, Security Group changes, S3 Policy changes, Root Login | PCI-DSS 8.3, SOC2 CC6.1, NIST AC-2, ISO27001 A.9 | Store + Alert + AI Analyze |
| **MEDIUM** | EC2 Instance state changes, Snapshots, Tags | PCI-DSS 6.4, SOC2 CC7.1, NIST CM-3 | Store + AI Analyze |
| **LOW** | Describe*, Get*, List*, Head* | SOC2 CC6.8 | Store only |

## Cost Breakdown

- **S3, DynamoDB, Lambda, SNS, EventBridge, CloudTrail:** Covered by AWS Free Tier for typical portfolio usage.
- **AWS Bedrock (Claude 3 Sonnet):** ~$0.003 per 1000 input tokens, ~$0.015 per 1000 output tokens. Estimated at < $1/month for testing.

## What This Demonstrates

| Skill | Implementation in Project |
|---|---|
| **Serverless Architecture** | Event-driven flow using EventBridge and Lambda |
| **Infrastructure as Code** | Full CloudFormation template with parameters and conditions |
| **Cloud Security** | S3 Encryption, IAM Least Privilege, CloudTrail logging |
| **AI Integration** | AWS Bedrock API integration for automated risk scoring |
| **Python Engineering** | Boto3 SDK usage, error handling, modular code structure |

## Teardown Instructions

To avoid unexpected charges, clean up the resources when done:

**For Version 1 (Boto3):**
```bash
python teardown.py
```

**For Version 2 (CloudFormation):**
```bash
python deploy_cloudformation.py
# Select Option 4 (Delete stack)
# OR
python teardown.py --stack-name grc-evidence-collector-dev
```
