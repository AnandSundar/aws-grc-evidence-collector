# GRC Evidence Platform v2.0

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-85%25-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![AWS](https://img.shields.io/badge/AWS-Native-orange)

This is a production-grade, AI-powered GRC Evidence Platform built entirely on native AWS services. It automates what enterprise compliance teams pay $15,000–$40,000/year for SaaS tools to provide — evidence collection across 12 AWS services, AI-powered risk scoring via AWS Bedrock, auto-remediation of 5 critical violation types, daily compliance scorecards, CI/CD compliance gates, and audit-ready PDF report generation. Total monthly cost: ~$6.

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Compliance Frameworks](#compliance-frameworks)
- [Cost Analysis](#cost-analysis)
- [Documentation](#documentation)
- [Development](#development)
- [License](#license)
- [Author](#author)

## Project Overview

The GRC Evidence Platform v2.0 is a comprehensive, serverless compliance automation solution built entirely on AWS native services. It replaces expensive SaaS GRC tools by automating evidence collection, risk analysis, remediation, and reporting for cloud infrastructure compliance.

### Why It Matters

- **Cost Effective**: Replaces $15,000-$40,000/year SaaS tools with ~$6/month AWS costs
- **AWS Native**: No third-party dependencies, fully integrated with AWS services
- **AI-Powered**: Uses AWS Bedrock (Claude 3 Sonnet) for intelligent risk scoring
- **Audit Ready**: Generates professional PDF reports for auditors and stakeholders
- **Automated**: Daily evidence collection, automated remediation, and compliance scorecards

## Features

### Evidence Collectors (12 Services)

1. **IAM Collector** - Captures user policies, roles, groups, and access keys
2. **S3 Collector** - Monitors bucket configurations, encryption, and public access
3. **RDS Collector** - Tracks database instances, snapshots, and security settings
4. **VPC Collector** - Maps network topology, security groups, and NACLs
5. **Config Collector** - Aggregates AWS Config rule compliance data
6. **Security Hub Collector** - Centralizes security findings from multiple sources
7. **GuardDuty Collector** - Collects threat detection findings
8. **Macie Collector** - Monitors sensitive data discovery and classification
9. **Inspector Collector** - Captures vulnerability assessment results
10. **KMS Collector** - Tracks key management and rotation policies
11. **ACM Collector** - Monitors SSL/TLS certificate lifecycle
12. **CloudTrail Collector** - Audits API activity and compliance events

### Lambda Functions (5 Functions)

1. **Evidence Processor** - Processes and normalizes evidence from collectors
2. **Remediation Engine** - Auto-remediates 5 critical violation types
3. **Scorecard Generator** - Creates daily compliance scorecards
4. **Report Generator** - Generates audit-ready PDF reports
5. **Evidence Aging Monitor** - Tracks evidence freshness and alerts on stale data

### AI-Powered Risk Scoring

- **AWS Bedrock Integration**: Uses Claude 3 Sonnet for intelligent analysis
- **Contextual Risk Assessment**: Evaluates findings in business context
- **Prioritization**: Automatically prioritizes high-impact issues
- **Recommendations**: Provides actionable remediation suggestions

### Auto-Remediation

Remediates 5 critical violation types automatically:

1. **S3 Public Access Blocks** - Removes public access from sensitive buckets
2. **Unencrypted RDS Instances** - Enables encryption for databases
3. **Overly Permissive IAM Policies** - Tightens permission boundaries
4. **Security Group Open Ports** - Closes unnecessary public exposures
5. **Unrotated Access Keys** - Disables stale credentials

### Reporting

- **Daily Compliance Scorecards** - Executive summary of compliance posture
- **Weekly Full Reports** - Comprehensive evidence and findings
- **Audit-Ready PDFs** - Professional formatting for auditors
- **Executive Summaries** - High-level risk overview for stakeholders
- **Control Matrix** - Detailed mapping to compliance frameworks

### CI/CD Integration

- **Compliance Gates** - Block deployments if compliance score drops
- **Pre-merge Checks** - Validate changes against compliance policies
- **Automated Evidence Collection** - Capture evidence on every deployment

## Architecture

The platform follows a serverless, event-driven architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                     GRC Evidence Platform                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Collectors  │───▶│   S3 Bucket  │───▶│   Lambda     │      │
│  │  (12 Services)│    │   (Evidence) │    │  Processors  │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │             │
│         ▼                    ▼                    ▼             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   CloudWatch │    │  DynamoDB    │    │   AWS        │      │
│  │   Events     │    │  (Metadata)  │    │   Bedrock    │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │             │
│         ▼                    ▼                    ▼             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   SNS        │    │   S3 Bucket  │    │   PDF        │      │
│  │   Alerts     │    │   (Reports)  │    │   Reports    │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

For detailed architecture documentation, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick Start

### Prerequisites

- AWS Account with appropriate permissions
- Python 3.9 or higher
- AWS CLI configured with credentials
- Terraform or AWS CDK (optional, for advanced deployments)

### Step 1: Clone and Configure

```bash
# Clone the repository
git clone https://github.com/yourusername/aws-grc-evidence-collector.git
cd aws-grc-evidence-collector

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# Set AWS_DEFAULT_REGION, GRC_ALERT_EMAIL, etc.
```

### Step 2: Deploy the Platform

```bash
# Install dependencies
make install

# Deploy CloudFormation stack
make deploy-quick

# This will:
# - Create S3 buckets for evidence and reports
# - Create DynamoDB tables for metadata
# - Deploy Lambda functions
# - Set up CloudWatch Events and SNS topics
# - Configure IAM roles and policies
```

### Step 3: Collect Evidence and Generate Reports

```bash
# Run all collectors
make collect

# Generate a compliance report
make report

# View the generated report
# Reports are saved to: reports/grc-compliance-report-*.pdf
```

For detailed deployment instructions, see [docs/QUICKSTART.md](docs/QUICKSTART.md).

## Compliance Frameworks

The platform supports multiple compliance frameworks with automated mapping:

### PCI-DSS

- **Requirements Covered**: 1.2, 1.3, 2.2, 3.1, 3.2, 4.1, 6.5, 7.2, 8.2, 8.3, 10.2, 11.4, 12.3
- **Evidence Types**: Network configuration, access control, encryption, logging
- **Report Sections**: PCI-DSS control matrix with pass/fail status

### SOC 2

- **Trust Principles**: Security, Availability, Processing Integrity
- **Criteria Covered**: CC1.1-CC7.3
- **Evidence Types**: Access reviews, change management, incident response
- **Report Sections**: SOC 2 control mapping with evidence links

### CIS AWS Foundations

- **Benchmarks**: CIS AWS Foundations Benchmark v1.4.0
- **Controls Covered**: 1.1-1.23 (IAM), 2.1-2.8 (S3), 3.1-3.14 (Logging)
- **Evidence Types**: Configuration snapshots, compliance checks
- **Report Sections**: CIS scorecard with remediation recommendations

### NIST 800-53

- **Controls Covered**: AC-1, AC-2, AC-3, AC-6, AU-1, AU-2, AU-3, AU-12, CM-1, CM-2, CM-6, CM-7, SC-7, SC-8, SC-12, SC-13, SC-28
- **Evidence Types**: Access control, audit logging, configuration management
- **Report Sections**: NIST control matrix with implementation status

For detailed compliance mappings, see [docs/COMPLIANCE_MAPPING.md](docs/COMPLIANCE_MAPPING.md).

## Cost Analysis

The platform is designed for cost efficiency with three deployment options:

### Option 1: Minimal Deployment (~$3/month)

- **S3 Storage**: $0.50 (10 GB evidence storage)
- **DynamoDB**: $0.25 (on-demand, 5 GB data)
- **Lambda**: $0.50 (1M invocations/month)
- **CloudWatch**: $0.50 (logs and metrics)
- **SNS**: $0.25 (1000 notifications)
- **Total**: **~$2.00/month**

### Option 2: Standard Deployment (~$6/month)

- **S3 Storage**: $1.00 (20 GB evidence storage)
- **DynamoDB**: $0.50 (on-demand, 10 GB data)
- **Lambda**: $1.00 (2M invocations/month)
- **CloudWatch**: $1.00 (logs and metrics)
- **SNS**: $0.50 (5000 notifications)
- **AWS Bedrock**: $2.00 (AI analysis, 100K tokens)
- **Total**: **~$6.00/month**

### Option 3: Enterprise Deployment (~$15/month)

- **S3 Storage**: $2.50 (50 GB evidence storage)
- **DynamoDB**: $1.00 (on-demand, 25 GB data)
- **Lambda**: $2.50 (5M invocations/month)
- **CloudWatch**: $2.00 (logs and metrics)
- **SNS**: $1.00 (10000 notifications)
- **AWS Bedrock**: $6.00 (AI analysis, 300K tokens)
- **Total**: **~$15.00/month**

For detailed cost breakdowns, see [docs/COST_ANALYSIS.md](docs/COST_ANALYSIS.md).

## Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Detailed system architecture and component design
- **[QUICKSTART.md](docs/QUICKSTART.md)** - Step-by-step deployment guide
- **[COLLECTORS.md](docs/COLLECTORS.md)** - Detailed documentation for all 12 evidence collectors
- **[REMEDIATION_PLAYBOOKS.md](docs/REMEDIATION_PLAYBOOKS.md)** - Auto-remediation procedures and playbooks
- **[COMPLIANCE_MAPPING.md](docs/COMPLIANCE_MAPPING.md)** - Framework mappings and control matrices
- **[COST_ANALYSIS.md](docs/COST_ANALYSIS.md)** - Detailed cost breakdown and optimization tips
- **[CLOUDFORMATION_GUIDE.md](docs/CLOUDFORMATION_GUIDE.md)** - CloudFormation template reference
- **[INTERVIEW_PREP.md](docs/INTERVIEW_PREP.md)** - Technical interview preparation guide

## Development

### Setting Up Development Environment

```bash
# Install development dependencies
make install

# Run tests
make test

# Run integration tests
make test-integration

# Lint code
make lint

# Full check (lint + test)
make check
```

### Project Structure

```
aws-grc-evidence-collector/
├── collectors/              # Evidence collectors (12 services)
│   ├── iam_collector.py
│   ├── s3_collector.py
│   ├── rds_collector.py
│   └── ...
├── lambda/                  # Lambda functions
│   ├── evidence_processor/
│   ├── remediation_engine/
│   ├── scorecard_generator/
│   └── report_generator/
├── remediations/            # Auto-remediation logic
│   ├── iam_remediations.py
│   ├── s3_remediations.py
│   └── ...
├── reports/                 # Report generation
│   ├── pdf_generator.py
│   └── templates/
├── scripts/                 # Utility scripts
│   ├── setup.py
│   ├── deploy_cloudformation.py
│   └── generate_report.py
├── tests/                   # Test suite
│   ├── test_collectors.py
│   ├── test_remediations.py
│   └── fixtures/
├── cloudformation/          # Infrastructure as code
│   ├── grc-platform-template.yaml
│   └── grc-collector-template.yaml
└── docs/                    # Documentation
```

### Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`make check`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- Follow PEP 8 for Python code
- Use type hints where appropriate
- Write docstrings for all functions and classes
- Maintain test coverage above 80%
- Use meaningful variable and function names

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=collectors --cov=remediations

# Run specific test file
pytest tests/test_collectors.py -v

# Run integration tests
python tests/test_events.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Anand Sundar**

- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [your-linkedin](https://linkedin.com/in/your-linkedin)
- Email: your.email@example.com

---

**Built with ❤️ using AWS native services**
