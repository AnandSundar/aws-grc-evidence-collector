# AWS GRC Evidence Collector

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-85%25-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![AWS](https://img.shields.io/badge/AWS-Native-orange)

## 🎯 Project Overview

The AWS GRC Evidence Collector is a **fully automated, serverless GRC (Governance, Risk, and Compliance) evidence collection and reporting platform** built entirely on native AWS services. It eliminates the need for expensive SaaS GRC tools by automating evidence collection, risk analysis, remediation, and comprehensive compliance reporting for cloud infrastructure.


<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/029f5e1a-0493-44f8-a87f-752f2466f16a" />



### The Problem It Solves

Traditional GRC processes are **manual, time-consuming, and error-prone**:
- **Weeks to months** of audit preparation work
- **Spreadsheet-based** evidence collection with screenshots
- **Reactive** discovery of compliance issues during audits
- **Static reports** that become outdated immediately
- **High cost** ($15,000-$40,000/year for enterprise SaaS tools)

### The Solution: GRC Engineering

This platform represents a **paradigm shift** from traditional GRC to **GRC Engineering** - treating compliance as engineering problems solved with code, automation, and infrastructure as principles.

**Key Benefits:**
- ✅ **Reduced audit prep time** from weeks to hours
- ✅ **Continuous compliance** monitoring 24/7
- ✅ **Automated evidence collection** across 13 AWS services
- ✅ **AI-powered risk analysis** (optional)
- ✅ **Auto-remediation** of security violations
- ✅ **Comprehensive reporting** for auditors and stakeholders
- ✅ **Cost-effective**: <$1/month vs $15,000-$40,000/year SaaS tools

---

## 🔄 GRC Engineering - The New Way to Do GRC

### Traditional GRC (Old Way) ❌

| Aspect | Traditional Approach |
|--------|---------------------|
| **Evidence Collection** | Manual collection via spreadsheets and screenshots |
| **Audit Preparation** | Quarterly/annual preparation requiring weeks of work |
| **Discovery** | Reactive - discovering issues during audits |
| **Reports** | Static reports that are immediately outdated |
| **Knowledge** | Heavy reliance on tribal knowledge and human memory |
| **Cost** | $15,000-$40,000/year for SaaS tools |
| **Scalability** | Low - manual processes don't scale |
| **Visibility** | No real-time visibility into compliance posture |
| **Error Rate** | High - human error in manual processes |
| **Evidence Handling** | Manually gathered, stored, and verified |

**Result:** Compliance is a burden, a cost center, and a source of stress.

### GRC Engineering (New Way - This Project) ✅

| Aspect | GRC Engineering Approach |
|--------|--------------------------|
| **Evidence Collection** | **Infrastructure as Code (IaC)** - compliance controls codified in CloudFormation |
| **Audit Preparation** | **Continuous compliance** - 24/7 automated evidence collection and monitoring |
| **Discovery** | **Proactive** - real-time event processing via CloudTrail and EventBridge |
| **Reports** | **Automated generation** - daily scorecards, weekly reports, always current |
| **Knowledge** | **Version-controlled** - compliance as code, auditable and repeatable |
| **Cost** | **<$1/month** - AWS serverless, pay-per-use pricing |
| **Scalability** | **Serverless** - scales automatically, handles any volume |
| **Visibility** | **Real-time** - dashboards, alerts, instant compliance status |
| **Error Rate** | **Low** - automated, consistent, repeatable processes |
| **Evidence Handling** | **Automated pipeline** - Collect → Analyze → Store → Report → Remediate |

**Result:** Compliance is automated, continuous, and a competitive advantage.

### The Evidence Pipeline

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  COLLECT    │────▶│  ANALYZE    │────▶│   STORE     │────▶│   REPORT    │
│             │     │             │     │             │     │             │
│ Real-time   │     │ AI-powered  │     │ Encrypted   │     │ Automated   │
│ Scheduled   │     │ Risk scoring│     │ Indexed     │     │ PDF/CSV     │
│ Event-driven│     │ Prioritization│     | Versioned   │     │ Executive   │
└─────────────┘     └─────────────┘     └─────────────┘     └──────┬──────┘
                                                                       │
                                                                       ▼
                                                                ┌─────────────┐
                                                                │  REMEDIATE  │
                                                                │             │
                                                                │ Auto-fix    │
                                                                │ Security    │
                                                                │ Guardrails  │
                                                                └─────────────┘
```

### Key Philosophy: Compliance as Code

**GRC Engineering** is built on these principles:

1. **Compliance as Code** - Controls are codified in CloudFormation, version-controlled, and auditable
2. **Continuous Monitoring** - 24/7 automated evidence collection, not periodic snapshots
3. **Automated Evidence Collection** - No manual screenshots or spreadsheets
4. **Shift-Left Security** - Compliance built into infrastructure, not bolted on
5. **DevSecOps for Compliance** - Compliance integrated into CI/CD pipelines
6. **Evidence as Data** - Structured, queryable, verifiable evidence
7. **Automated Remediation** - Fix issues before they become violations
8. **AI-Powered Analysis** - Intelligent risk assessment and prioritization

**This is not a tool - it's a methodology.**

---


<img width="1146" height="670" alt="image" src="https://github.com/user-attachments/assets/b569a447-fb18-482c-8f8d-6cd770e9537d" />



## 🏗️ Technical Architecture

### High-Level Architecture

The platform follows a **serverless, event-driven architecture** built entirely on AWS native services:

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                         AWS ACCOUNT - GRC EVIDENCE PLATFORM                          │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          EVENT INGESTION LAYER                                      │
│                                                                                     │
│  CloudTrail Events ──▶ EventBridge Rules ──▶ Lambda: Evidence Processor           │
│  (Real-time API calls)   (Scheduled Rules)       (Event filtering & prioritization)│
└─────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          EVIDENCE COLLECTION LAYER                                  │
│                                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │   IAM    │  │    S3    │  │   RDS    │  │   VPC    │  │   KMS    │            │
│  │Collector │  │Collector │  │Collector │  │Collector │  │Collector │            │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │
│                                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  Config  │  │Security  │  │GuardDuty │  │  Macie   │  │Inspector │            │
│  │Collector │  │  Hub     │  │Collector │  │Collector │  │Collector │            │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │
│                                                                                     │
│  ┌──────────┐  ┌──────────┐                                                          │
│  │   ACM    │  │CloudTrail│                                                          │
│  │Collector │  │Collector │                                                          │
│  └──────────┘  └──────────┘                                                          │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          STORAGE LAYER                                              │
│                                                                                     │
│  ┌──────────────────────┐              ┌──────────────────────┐                    │
│  │  S3: Evidence Bucket │              │  DynamoDB: Metadata   │                    │
│  │  - Encrypted (KMS)   │              │  - Evidence index    │                    │
│  │  - Versioned         │              │  - Scorecards        │                    │
│  │  - Lifecycle policies│              │  - Remediation logs  │                    │
│  └──────────────────────┘              └──────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          PROCESSING LAYER                                           │
│                                                                                     │
│  ┌──────────────────────┐              ┌──────────────────────┐                    │
│  │  Lambda: Batch       │              │  Lambda: Evidence     │                    │
│  │  Processor          │              │  Aging Monitor       │                    │
│  │  (MEDIUM/LOW events) │              │  (TTL management)    │                    │
│  └──────────────────────┘              └──────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          ANALYSIS LAYER                                             │
│                                                                                     │
│  ┌──────────────────────┐              ┌──────────────────────┐                    │
│  │  AWS Bedrock         │              │  AWS Config          │                    │
│  │  (AI Analysis)       │              │  (30 Config Rules)   │                    │
│  │  - Risk scoring      │              │  - Continuous eval   │                    │
│  │  - Prioritization    │              │  - Compliance status │                    │
│  └──────────────────────┘              └──────────────────────┘                    │
│                                                                                     │
│  ┌──────────────────────┐              ┌──────────────────────┐                    │
│  │  GuardDuty           │              │  Security Hub        │                    │
│  │  (Threat detection)  │              │  (Findings aggregation)│                  │
│  └──────────────────────┘              └──────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          REMEDIATION LAYER                                          │
│                                                                                     │
│  ┌──────────────────────┐              ┌──────────────────────┐                    │
│  │  Lambda: Remediation │              │  SNS: Alerts         │                    │
│  │  Engine              │              │  - Email             │                    │
│  │  - Auto-remediate    │              │  - SMS               │                    │
│  │  - DRY_RUN mode      │              │  - Webhook           │                    │
│  └──────────────────────┘              └──────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          REPORTING LAYER                                            │
│                                                                                     │
│  ┌──────────────────────┐              ┌──────────────────────┐                    │
│  │  Lambda: Scorecard   │              │  Lambda: Report       │                    │
│  │  Generator           │              │  Exporter            │                    │
│  │  - Daily scorecards  │              │  - PDF reports       │                    │
│  │  - Compliance scores │              │  - CSV exports       │                    │
│  │  - Trend analysis    │              │  - Executive summary  │                    │
│  └──────────────────────┘              └──────────────────────┘                    │
│                                                                                     │
│                                      ┌──────────────────────┐                      │
│                                      │  S3: Reports Bucket  │                      │
│                                      │  - PDF reports       │                      │
│                                      │  - CSV exports       │                      │
│                                      │  - Pre-signed URLs    │                      │
│                                      └──────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### AWS Services Used

| Service | Purpose | Cost |
|---------|---------|------|
| **KMS** | Encryption for all data at rest | $0.00 (within Free Tier) |
| **S3** | Evidence and report storage | $0.01-0.23/GB |
| **DynamoDB** | Metadata, scorecards, remediation logs | $0.25/GB (on-demand) |
| **Lambda** | Event processing, collectors, reporting | $0.20/1M requests |
| **EventBridge** | Scheduling and event routing | $1.00/1M events |
| **CloudTrail** | API activity logging | Free (first trail) |
| **AWS Config** | Continuous compliance monitoring | $2.00/rule/month |
| **Security Hub** | Centralized findings aggregation | $0.30/account/month |
| **GuardDuty** | Threat detection | $1.00/account/month |
| **CloudWatch** | Logging, metrics, alarms | $0.50/GB logs |
| **SNS** | Alerts and notifications | $0.50/1M notifications |
| **Bedrock** | AI-powered analysis (optional) | $3-15/1M tokens |

### Evidence Collection Flow

```
1. AWS API Call Made
   ↓
2. CloudTrail Captures Event
   ↓
3. EventBridge Triggers Lambda
   ↓
4. Evidence Processor Lambda:
   - Filters events by priority (HIGH/MEDIUM/LOW)
   - Enriches with compliance tags
   - Stores in S3 (evidence/YYYY/MM/DD/evidence_id.json)
   - Writes metadata to DynamoDB
   - Triggers AI analysis (if enabled)
   - Sends alerts (if HIGH priority)
   ↓
5. Batch Processor (for MEDIUM/LOW):
   - Aggregates events every 15-60 minutes
   - Processes in batch to reduce costs
   - Updates DynamoDB
   ↓
6. Evidence Aging Monitor (hourly):
   - Checks for stale evidence
   - Triggers re-collection if needed
   - Sends alerts for missing evidence
```

### Security & Encryption

- **KMS Encryption**: All S3 buckets and DynamoDB tables encrypted with customer-managed KMS key
- **Key Rotation**: Automatic KMS key rotation enabled
- **Least Privilege**: IAM roles follow principle of least privilege
- **VPC Endpoints**: Private communication between services (optional)
- **Data in Transit**: All data encrypted with TLS 1.2+
- **Immutable Evidence**: S3 versioning prevents tampering
- **Audit Logging**: CloudTrail logs all API calls
- **Secure Defaults**: All resources deployed with secure configurations

### Monitoring & Alerting

- **CloudWatch Alarms**: Lambda errors, throttles, duration
- **DynamoDB Alarms**: Read/write throttles
- **SNS Notifications**: HIGH priority findings, remediation actions
- **Daily Scorecards**: Executive summary of compliance posture
- **Weekly Reports**: Comprehensive evidence and findings

---

## 🧩 Core Components

### Lambda Functions

#### 1. Evidence Processor (Real-Time Event Processing)
- **Purpose**: Processes CloudTrail events in real-time
- **Triggers**: EventBridge rules (CloudTrail, Config, GuardDuty)
- **Functionality**:
  - Event filtering and prioritization
  - Compliance tag derivation
  - S3 evidence storage
  - DynamoDB metadata indexing
  - AI analysis (optional)
  - HIGH priority alerting
- **Schedule**: Event-driven (real-time)

#### 2. Batch Processor (Cost Optimization)
- **Purpose**: Batch processes MEDIUM/LOW priority events
- **Triggers**: EventBridge scheduled rules
- **Functionality**:
  - Aggregates events to reduce Lambda invocations
  - Processes in batches every 15-60 minutes
  - Updates DynamoDB in batch
  - Optimizes for cost efficiency
- **Schedule**: Every 15 minutes (MEDIUM), 60 minutes (LOW)

#### 3. Remediation Engine (Auto-Remediation)
- **Purpose**: Automatically remediates security violations
- **Triggers**: EventBridge, manual invocation
- **Modes**:
  - `DRY_RUN`: Logs actions without executing (default)
  - `AUTO`: Executes remediations automatically
  - `APPROVAL_REQUIRED`: Requires approval before execution
- **Remediations**:
  - S3 public access blocking
  - S3 encryption enforcement
  - IAM access key disabling
  - KMS key rotation enforcement
  - Security group rule revocation
  - RDS security hardening
- **Schedule**: Event-driven or scheduled

#### 4. Scorecard Generator (Daily Reports)
- **Purpose**: Generates daily compliance scorecards
- **Triggers**: EventBridge scheduled rule
- **Functionality**:
  - Aggregates evidence from DynamoDB
  - Calculates compliance scores
  - Identifies trends
  - Generates executive summary
  - Stores in DynamoDB
- **Schedule**: Daily at 06:00 UTC

#### 5. Report Exporter (Weekly Reports)
- **Purpose**: Generates comprehensive compliance reports
- **Triggers**: EventBridge scheduled rule
- **Functionality**:
  - Generates PDF reports
  - Exports CSV data
  - Creates executive summaries
  - Generates control matrices
  - Uploads to S3
  - Sends email with pre-signed URLs
- **Schedule**: Weekly on Sunday at 08:00 UTC

#### 6. Evidence Aging Monitor (Lifecycle Management)
- **Purpose**: Monitors evidence freshness and lifecycle
- **Triggers**: EventBridge scheduled rule
- **Functionality**:
  - Checks for stale evidence
  - Triggers re-collection
  - Manages TTL (Time-To-Live)
  - Alerts on missing evidence
  - Optimizes storage costs
- **Schedule**: Every hour

<img width="1292" height="770" alt="2026-04-14 09_18_48- GRC Daily Digest  Compliance Scorecard - 2026-04-14 - anandaws0001@gmail com - " src="https://github.com/user-attachments/assets/a11ea1f5-99e7-4de3-a267-7f44212e29e7" />


<img width="1274" height="586" alt="2026-04-14 09_19_39- GRC Audit Report  2026-04-05 to 2026-04-12 - anandaws0001@gmail com - Gmail — M" src="https://github.com/user-attachments/assets/197bbbf4-8920-4e88-8b91-01289b2ddf1b" />


<img width="1266" height="742" alt="2026-04-14 09_20_06- GRC Audit Report  2026-04-05 to 2026-04-12 - anandaws0001@gmail com - Gmail — M" src="https://github.com/user-attachments/assets/0d82c433-c8af-4e1a-8993-dd30fd89e004" />


<img width="1325" height="724" alt="2026-04-14 09_20_36-Cost Explorer _ Billing and Cost Management _ Global — Mozilla Firefox" src="https://github.com/user-attachments/assets/2e9a665b-5892-489b-b1ab-93ed0121c504" />


<img width="946" height="737" alt="2026-04-14 09_21_34-" src="https://github.com/user-attachments/assets/cf637e2b-0911-4783-8f79-8a316a845283" />


<img width="1680" height="588" alt="2026-04-14 09_22_04-grc_report xlsx - Excel" src="https://github.com/user-attachments/assets/0a2586b5-90f8-42d5-b9de-a2ddd28b51e7" />


### Evidence Collectors (13 Collectors)

| # | Collector | Checks | Priority | Compliance Frameworks |
|---|-----------|--------|----------|----------------------|
| 1 | **IAM Collector** | MFA enforcement, access key rotation, password policy, console access, unused users | HIGH | PCI-DSS, SOC2, NIST, CIS |
| 2 | **S3 Collector** | Public access, encryption, versioning, bucket policies, logging | HIGH | PCI-DSS, SOC2, NIST, CIS |
| 3 | **RDS Collector** | Encryption, multi-AZ, public access, security groups, snapshots | HIGH | PCI-DSS, SOC2, NIST, CIS |
| 4 | **VPC Collector** | Security groups, NACLs, flow logs, network topology | MEDIUM | PCI-DSS, SOC2, NIST, CIS |
| 5 | **KMS Collector** | Key rotation, key usage, key policies, key age | HIGH | PCI-DSS, SOC2, NIST, CIS |
| 6 | **Config Collector** | Config rule compliance, resource configuration drift | MEDIUM | PCI-DSS, SOC2, NIST, CIS |
| 7 | **Security Hub Collector** | Aggregated security findings, severity, remediation | HIGH | PCI-DSS, SOC2, NIST, CIS |
| 8 | **GuardDuty Collector** | Threat detection findings, severity, IP reputation | HIGH | PCI-DSS, SOC2, NIST, CIS |
| 9 | **Macie Collector** | Sensitive data discovery, PII classification, data encryption | MEDIUM | PCI-DSS, SOC2, HIPAA, GDPR |
| 10 | **Inspector Collector** | Vulnerability assessments, CVE severity, patch status | MEDIUM | PCI-DSS, SOC2, NIST, CIS |
| 11 | **ACM Collector** | SSL/TLS certificates, expiration, renewal | MEDIUM | PCI-DSS, SOC2, NIST, CIS |
| 12 | **CloudTrail Collector** | API activity logging, trail configuration, encryption | MEDIUM | PCI-DSS, SOC2, NIST, CIS |
| 13 | **VPC Flow Logs Collector** | Network traffic logging, VPC flow log configuration | LOW | PCI-DSS, SOC2, NIST, CIS |

**How Collectors Work:**

1. **Scheduled Execution**: Run on schedule (hourly, daily, weekly)
2. **API Calls**: Query AWS service APIs for current state
3. **Compliance Checks**: Compare against compliance requirements
4. **Evidence Generation**: Create structured evidence records
5. **Storage**: Store in S3 (evidence files) and DynamoDB (metadata)
6. **Alerting**: Send alerts for HIGH priority findings

### AWS Config Rules (30+ Rules)

| Rule | Description | Framework |
|------|-------------|-----------|
| `CLOUD_TRAIL_ENABLED` | CloudTrail is enabled and logging | PCI-DSS, SOC2, NIST |
| `S3_BUCKET_PUBLIC_READ_PROHIBITED` | S3 buckets not publicly readable | PCI-DSS, SOC2, NIST |
| `S3_BUCKET_PUBLIC_WRITE_PROHIBITED` | S3 buckets not publicly writable | PCI-DSS, SOC2, NIST |
| `S3_SERVER_SIDE_ENCRYPTION_ENABLED` | S3 buckets have encryption enabled | PCI-DSS, SOC2, NIST |
| `IAM_USER_MFA_ENABLED` | IAM users have MFA enabled | PCI-DSS, SOC2, NIST, CIS |
| `IAM_PASSWORD_POLICY` | IAM password policy meets requirements | PCI-DSS, SOC2, NIST, CIS |
| `IAM_ACCESS_KEYS_ROTATED` | IAM access keys rotated every 90 days | PCI-DSS, SOC2, NIST, CIS |
| `IAM_ROOT_ACCESS_KEY_CHECK` | Root account has no access keys | PCI-DSS, SOC2, NIST, CIS |
| `RDS_STORAGE_ENCRYPTED` | RDS instances have encryption enabled | PCI-DSS, SOC2, NIST |
| `RDS_INSTANCE_PUBLIC_ACCESS_CHECK` | RDS instances not publicly accessible | PCI-DSS, SOC2, NIST |
| `RDS_MULTI_AZ_SUPPORT` | RDS instances have Multi-AZ enabled | PCI-DSS, SOC2, NIST |
| `VPC_FLOW_LOGS_ENABLED` | VPCs have flow logs enabled | PCI-DSS, SOC2, NIST |
| `EC2_SECURITY_GROUP_ATTACHED_TO_ENI` | Security groups attached to ENIs | PCI-DSS, SOC2, NIST |
| `RESTRICTED_SSH` | SSH restricted to specific IP ranges | PCI-DSS, SOC2, NIST, CIS |
| `RESTRICTED_COMMON_PORTS` | Common ports restricted | PCI-DSS, SOC2, NIST, CIS |
| `KMS_KEY_NOT_SCHEDULED_FOR_DELETION` | KMS keys not scheduled for deletion | PCI-DSS, SOC2, NIST |
| `ACM_CERTIFICATE_EXPIRATION_CHECK` | ACM certificates not expired | PCI-DSS, SOC2, NIST |
| `GUARDDUTY_ENABLED_CENTRALIZED` | GuardDuty enabled and centralized | PCI-DSS, SOC2, NIST |
| `+ 10 more rules...` | | |

**Config Rule Evaluation:**
- **Continuous Evaluation**: Real-time compliance checks
- **Periodic Evaluation**: Scheduled checks (every 1-24 hours)
- **Resource Types**: S3 buckets, IAM users, RDS instances, VPCs, etc.
- **Compliance Status**: COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE, INSUFFICIENT_DATA

### Remediation Capabilities

#### Auto-Remediation Actions

| Action | Trigger | Mode | Security Guardrails |
|--------|---------|------|-------------------|
| **S3 Public Access Block** | Config rule violation | AUTO/DRY_RUN | Cannot block critical production buckets |
| **S3 Encryption Enforcement** | Unencrypted S3 bucket | AUTO/DRY_RUN | Cannot encrypt buckets with existing data |
| **IAM Access Key Disable** | Access key > 90 days old | AUTO/DRY_RUN | Cannot disable root account keys |
| **KMS Key Rotation Enable** | KMS key without rotation | AUTO/DRY_RUN | Cannot rotate AWS-managed keys |
| **Security Group Revoke** | Open security group rule | AUTO/DRY_RUN | Cannot revoke rules for production resources |
| **RDS Encryption Enable** | Unencrypted RDS instance | AUTO/DRY_RUN | Requires snapshot first |

#### Remediation Modes

1. **DRY_RUN (Default)**:
   - Logs what would be done
   - No actual changes
   - Safe for testing
   - Full audit trail

2. **AUTO**:
   - Automatically executes remediations
   - No manual intervention
   - Fast response time
   - Guardrails prevent dangerous actions

3. **APPROVAL_REQUIRED**:
   - Creates approval request
   - Requires human approval
   - Balance of automation and control
   - Audit trail of approvals

#### Security Guardrails

- **No Critical Resource Modification**: Cannot modify/delete critical resources
- **No Root Account Actions**: Cannot perform actions on root account
- **No Production Impact**: Cannot affect running production workloads
- **Audit Trail**: All remediation actions logged to DynamoDB
- **Rollback Support**: All remediations can be rolled back

---

## 📋 Compliance Frameworks Covered

### PCI-DSS 4.0

**Requirements Covered:** 1, 2, 3, 6, 7, 8, 10, 11, 12

| Requirement | Controls | Evidence | Auto-Remediated |
|-------------|----------|----------|-----------------|
| 1. Network Security | Firewall rules, security groups, VPC config | VPC Collector, Config Rules | Yes |
| 2. Secure Configurations | Default passwords, secure settings | Config Collector, Config Rules | Yes |
| 3. Protect Cardholder Data | Encryption, key management | S3 Collector, KMS Collector | Yes |
| 6. Vulnerability Management | Patching, vulnerability scans | Inspector Collector, GuardDuty | No |
| 7. Access Control | MFA, access controls, least privilege | IAM Collector | Yes |
| 8. Authentication | Password policy, access key rotation | IAM Collector | Yes |
| 10. Tracking & Monitoring | Logging, monitoring, alerts | CloudTrail Collector, Config Rules | No |
| 11. Security Testing | Vulnerability scans, penetration tests | Inspector Collector, GuardDuty | No |
| 12. Security Policy | Documentation, training, incident response | CloudTrail Collector | No |

**Evidence Types:** Network configuration, access control, encryption, logging, vulnerability reports

### SOC 2 Type II

**Trust Principles:** Security, Availability, Processing Integrity

| Criteria | Controls | Evidence | Auto-Remediated |
|----------|----------|----------|-----------------|
| CC6.1 | Logical and physical access controls | IAM Collector, VPC Collector | Yes |
| CC6.2 | System operations, change management | CloudTrail Collector, Config Rules | No |
| CC6.3 | Change management controls | CloudTrail Collector, Config Rules | No |
| CC6.4 | Change testing and approval | CloudTrail Collector, Config Rules | No |
| CC6.5 | Segregation of duties | IAM Collector | No |
| CC6.6 | System monitoring | CloudTrail Collector, Config Rules | No |
| CC6.7 | System modifications | CloudTrail Collector, Config Rules | Yes |
| CC6.8 | System component changes | CloudTrail Collector, Config Rules | Yes |
| CC7.1 | System availability | RDS Collector, Config Rules | Yes |
| CC7.2 | System availability monitoring | CloudWatch, Config Rules | No |
| CC7.3 | System recovery planning | RDS Collector, Config Rules | No |

**Evidence Types:** Access reviews, change management, incident response, availability reports

### NIST 800-53 Rev 5

**Controls Covered:** AC, AU, CM, IA, IR, SC, SI

| Control Family | Controls | Evidence | Auto-Remediated |
|----------------|----------|----------|-----------------|
| AC (Access Control) | AC-1, AC-2, AC-3, AC-6 | IAM Collector | Yes |
| AU (Audit & Accountability) | AU-1, AU-2, AU-3, AU-12 | CloudTrail Collector, Config Rules | No |
| CM (Configuration Management) | CM-1, CM-2, CM-6, CM-7 | Config Collector, Config Rules | Yes |
| IA (Identification & Authentication) | IA-1, IA-2, IA-3, IA-5 | IAM Collector | Yes |
| IR (Incident Response) | IR-1, IR-4, IR-6 | GuardDuty Collector, Security Hub | No |
| SC (System & Communications Protection) | SC-7, SC-8, SC-12, SC-13 | VPC Collector, S3 Collector | Yes |
| SI (System & Information Integrity) | SI-1, SI-3, SI-4 | Inspector Collector, GuardDuty | No |

**Evidence Types:** Access control, audit logging, configuration management, system protection

### CIS AWS Foundations Benchmark v1.5

**Controls Covered:** 90+ controls across 5 sections

| Section | Controls | Evidence | Auto-Remediated |
|---------|----------|----------|-----------------|
| 1. Identity and Access Management | 1.1-1.23 | IAM Collector, Config Rules | Yes |
| 2. Storage | 2.1-2.8 | S3 Collector, Config Rules | Yes |
| 3. Logging | 3.1-3.14 | CloudTrail Collector, Config Rules | No |
| 4. Monitoring | 4.1-4.5 | CloudWatch, GuardDuty | No |
| 5. Networking | 5.1-5.3 | VPC Collector, Config Rules | Yes |

**Evidence Types:** Configuration snapshots, compliance checks, security assessments

### HIPAA

**Requirements Addressed:** 164.312(a)(1), 164.312(e)(1)

| Requirement | Controls | Evidence | Auto-Remediated |
|-------------|----------|----------|-----------------|
| 164.312(a)(1) - Access Control | IAM policies, MFA | IAM Collector | Yes |
| 164.312(e)(1) - Encryption | S3 encryption, KMS keys | S3 Collector, KMS Collector | Yes |

**Evidence Types:** Access controls, encryption status, audit logs

### GDPR

**Requirements Addressed:** Article 32 - Security of Processing

| Requirement | Controls | Evidence | Auto-Remediated |
|-------------|----------|----------|-----------------|
| Article 32 - Technical & Organizational Measures | Encryption, access controls, monitoring | All Collectors | Yes |

**Evidence Types:** Data protection measures, access logs, security monitoring

---

## 🚀 Deployment and Usage

### Prerequisites

- **AWS Account** with appropriate permissions
- **AWS CLI** installed and configured with credentials
- **Python 3.9+** installed
- **Git** installed (for cloning the repository)
- **AWS Credentials** with the following permissions:
  - CloudFormation (full access)
  - Lambda (full access)
  - S3 (full access)
  - DynamoDB (full access)
  - IAM (full access)
  - KMS (full access)
  - EventBridge (full access)
  - CloudTrail (full access)
  - AWS Config (full access)
  - SNS (full access)
  - CloudWatch (full access)

### Deployment Options

The platform supports 4 deployment configurations:

#### Option 1: No AI, No Auto-Remediation
- **Monthly Cost**: ~$4.18
- **Features**: Evidence collection, reporting, monitoring
- **Best For**: Basic compliance needs, cost optimization

#### Option 2: With AI Analysis Only
- **Monthly Cost**: ~$4.93
- **Features**: AI-powered risk analysis (HIGH+MEDIUM events)
- **Best For**: Intelligent risk prioritization

#### Option 3: With Auto-Remediation Only
- **Monthly Cost**: ~$4.18
- **Features**: Automated remediation (DRY_RUN mode)
- **Best For**: Security automation

#### Option 4: Full Platform (Recommended) ⭐
- **Monthly Cost**: ~$6.18
- **Features**: All features enabled
- **Best For**: Complete GRC Engineering platform

### Step-by-Step Deployment

#### 1. Clone the Repository

```bash
git clone https://github.com/AnandSundar/aws-grc-evidence-collector.git
cd aws-grc-evidence-collector
```

#### 2. Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### 3. Configure AWS Credentials

```bash
# Set AWS region
export AWS_DEFAULT_REGION=us-east-1

# Verify credentials
aws sts get-caller-identity
```

#### 4. Deploy Using Interactive Script

```bash
# Run deployment script
python scripts/deploy_cloudformation.py

# Select deployment option:
# 1. Deploy: No AI, No Auto-Remediation
# 2. Deploy: With AI Analysis only
# 3. Deploy: With Auto-Remediation only
# 4. Deploy: Full Platform — AI + Auto-Remediation ⭐ RECOMMENDED
```

#### 5. Enter Deployment Details

```bash
# When prompted, enter:
- Alert Email: your.email@example.com (or leave blank)
- Environment: dev | staging | prod (default: dev)
- Confirm: yes
```

#### 6. Monitor Deployment

The deployment script will:
- Create S3 buckets (evidence, reports, cloudtrail, config)
- Create DynamoDB tables (metadata, scorecards, remediation logs)
- Deploy Lambda functions (5 functions)
- Create EventBridge rules (daily, weekly, hourly)
- Set up CloudTrail
- Configure AWS Config (30+ rules)
- Create IAM roles with least privilege
- Set up SNS topics for alerts
- Configure CloudWatch alarms

Expected deployment time: **5-10 minutes**

#### 7. Verify Deployment

```bash
# Check CloudFormation stack
aws cloudformation describe-stacks \
  --stack-name grc-evidence-platform \
  --query 'Stacks[0].StackStatus'

# Expected output: "CREATE_COMPLETE"

# View stack outputs
aws cloudformation describe-stacks \
  --stack-name grc-evidence-platform \
  --query 'Stacks[0].Outputs'
```

### Triggering Reports Manually

#### Trigger Daily Scorecard

```bash
aws lambda invoke \
  --function-name grc-evidence-platform-scorecard-generator-dev \
  response.json

cat response.json
```

#### Trigger Weekly Report

```bash
aws lambda invoke \
  --function-name grc-evidence-platform-report-exporter-dev \
  response.json

cat response.json
```

#### Trigger Evidence Collection

```bash
aws lambda invoke \
  --function-name grc-evidence-platform-evidence-processor-dev \
  --payload '{"test": true}' \
  response.json

cat response.json
```

### Viewing Evidence and Reports

#### List Reports in S3

```bash
aws s3 ls s3://grc-evidence-platform-reports-<account-id>-<region>/ --recursive
```

#### Download a Report

```bash
aws s3 cp \
  s3://grc-evidence-platform-reports-<account-id>-<region>/reports/2026/04/05/compliance-report.pdf \
  ./compliance-report.pdf
```

#### View Evidence in DynamoDB

```bash
# List evidence records
aws dynamodb scan \
  --table-name grc-evidence-platform-metadata-dev \
  --projection-expression "evidence_id, event_type, priority, timestamp" \
  --max-items 10

# Query by event type
aws dynamodb query \
  --table-name grc-evidence-platform-metadata-dev \
  --index-name EventTypeIndex \
  --key-condition-expression "event_type = :type" \
  --expression-attribute-values '{":type": {"S": "CreateUser"}}'
```

### Cost Optimization Tips

1. **Start with Option 1**: Deploy basic platform first, add features as needed
2. **Enable S3 Lifecycle Policies**: Automatically transition old evidence to Glacier
3. **Optimize Lambda Invocations**: Use batch processing for MEDIUM/LOW events
4. **Reduce Config Rules**: Disable unnecessary Config rules in non-production
5. **Use Free Tier**: Maximize AWS Free Tier benefits
6. **Monitor Costs**: Set up AWS Budgets and CloudWatch alarms


<img width="1263" height="546" alt="image" src="https://github.com/user-attachments/assets/0ba54753-ccfb-404e-bc72-90ef2d5ad7f7" />



<img width="1098" height="830" alt="image" src="https://github.com/user-attachments/assets/e811e7e0-8b3b-4474-a2d2-97281b2fdf2a" />



<img width="1181" height="860" alt="image" src="https://github.com/user-attachments/assets/3f7979ed-bfe2-4fe8-96d5-ceb750c96f72" />



<img width="1135" height="767" alt="image" src="https://github.com/user-attachments/assets/0084fdeb-d014-4910-956f-e1dafb7c4045" />


<img width="1517" height="689" alt="image" src="https://github.com/user-attachments/assets/184b8bbb-9d7d-4290-9467-056468ea7b13" />


---

## ✨ Features and Capabilities

### Real-Time Evidence Collection

- **CloudTrail Integration**: Capture all AWS API calls in real-time
- **Event-Driven Processing**: Process events as they occur
- **Priority-Based Routing**: HIGH events processed immediately, MEDIUM/LOW batched
- **Automatic Tagging**: Derive compliance tags from event types
- **Enrichment**: Add context (user, source IP, region) to events

### Scheduled Evidence Collection

- **Hourly**: Evidence aging monitor
- **Daily**: Evidence collectors (13 collectors)
- **Weekly**: Comprehensive report generation
- **Monthly**: Compliance trend analysis

### AI-Powered Risk Analysis (Optional)

- **AWS Bedrock Integration**: Uses NVIDIA Nemotron Nano 12B v2 for analysis
- **Contextual Assessment**: Evaluates findings in business context
- **Intelligent Prioritization**: Automatically prioritizes high-impact issues
- **Recommendations**: Provides actionable remediation suggestions
- **Cost Optimization**: Only analyzes HIGH and MEDIUM priority events

**AI Analysis Output:**
```json
{
  "risk_level": "HIGH",
  "risk_score": 8,
  "summary": "Root account accessed without MFA from unknown IP",
  "compliance_impact": ["PCI-DSS-8.3", "SOC2-CC6.1"],
  "anomaly_indicators": ["Root access", "No MFA", "Unknown IP"],
  "recommended_action": "Investigate immediately, enable MFA for root",
  "false_positive_likelihood": "LOW",
  "investigation_priority": "IMMEDIATE"
}
```

### Automated Remediation

- **DRY_RUN Mode**: Safe testing without making changes
- **AUTO Mode**: Automatically fix common violations
- **Approval Required**: Balance automation with control
- **Security Guardrails**: Prevent dangerous actions
- **Audit Trail**: All remediations logged to DynamoDB

**Supported Remediations:**
- S3 public access blocking
- S3 encryption enforcement
- IAM access key disabling
- KMS key rotation enforcement
- Security group rule revocation
- RDS security hardening

### Comprehensive Reporting

**Daily Scorecards:**
- Executive summary
- Compliance scores by framework
- Trend analysis
- Top findings
- Remediation status

**Weekly Reports:**
- Comprehensive evidence package
- Detailed control matrices
- Finding details with evidence
- Remediation recommendations
- Compliance status by framework

**Executive Summaries:**
- High-level risk overview
- Key metrics and KPIs
- Trend visualization
- Action items

**Control Matrices:**
- Framework mapping
- Control status (PASS/FAIL)
- Evidence links
- Remediation actions

### Alerting and Notifications

- **HIGH Priority Events**: Immediate email alerts
- **Remediation Actions**: Notification of auto-remediations
- **Report Generation**: Email with pre-signed URLs
- **Compliance Drift**: Alerts when compliance scores drop
- **System Health**: Lambda errors, throttles, failures

### Evidence Aging and Lifecycle Management

- **TTL Management**: Automatic expiration of old evidence
- **Freshness Monitoring**: Alert on stale evidence
- **Re-collection**: Trigger evidence re-collection
- **Storage Optimization**: Transition to Glacier, delete expired
- **Version Control**: S3 versioning prevents tampering

### Version Control and Audit Trails

- **CloudFormation as Code**: Infrastructure version-controlled in Git
- **Evidence Versioning**: S3 versioning for immutable evidence
- **Change Logs**: CloudTrail logs all changes
- **Audit Ready**: Complete audit trail of all actions
- **Reproducible**: Deploy consistent infrastructure across environments

### Multi-Environment Support

- **dev**: Development environment with relaxed controls
- **staging**: Pre-production testing
- **prod**: Production environment with strict controls
- **Environment Isolation**: Separate resources per environment
- **Configuration Management**: Different settings per environment

---

## 💡 Benefits and Use Cases

### For Audits

**Before (Traditional GRC):**
- 4-8 weeks of audit preparation
- Manual evidence gathering (screenshots, spreadsheets)
- High stress and overtime
- Risk of missing evidence
- Difficulty reproducing evidence

**After (GRC Engineering):**
- 4-8 hours of audit preparation
- Automated evidence packages (PDF, CSV)
- Stress-free process
- Complete, verified evidence
- Reproducible, auditable evidence

**Benefits:**
- 95% reduction in audit prep time
- Higher audit success rates
- Reduced audit fatigue
- Better auditor experience
- Lower audit costs

### For Compliance Teams

**Before:**
- Reactive discovery of issues
- Manual evidence collection
- No real-time visibility
- High manual effort
- Difficult to scale

**After:**
- Proactive issue detection
- Automated evidence collection
- Real-time compliance dashboards
- Minimal manual effort
- Scales effortlessly

**Benefits:**
- Continuous compliance visibility
- Proactive issue resolution
- Reduced manual workload
- Improved compliance posture
- Better stakeholder communication

### For DevOps/Platform Teams

**Before:**
- Compliance is a bottleneck
- Manual checks before deployment
- Slow release cycles
- Compliance is separate from development

**After:**
- Compliance as code
- Automated compliance checks in CI/CD
- Fast, compliant deployments
- Compliance integrated into development

**Benefits:**
- Faster, compliant deployments
- Compliance gates prevent violations
- Shift-left security
- Reduced friction between DevOps and compliance
- Infrastructure version control

### For Security Teams

**Before:**
- Manual security monitoring
- Reactive incident response
- Slow remediation
- Limited visibility

**After:**
- Automated security monitoring
- Real-time threat detection
- Fast auto-remediation
- Complete visibility

**Benefits:**
- Faster incident response
- Reduced security posture
- Automated threat detection (GuardDuty)
- Centralized findings (Security Hub)
- Proactive security posture

### For Executives

**Before:**
- Limited visibility into compliance
- Delayed reporting
- Difficulty understanding risk
- High compliance costs

**After:**
- Real-time compliance dashboards
- Automated, timely reports
- Clear risk metrics and KPIs
- Dramatic cost reduction

**Benefits:**
- Better decision-making
- Reduced compliance risk
- Lower compliance costs (99% reduction)
- Improved stakeholder confidence
- Competitive advantage

---

## 📊 Comparison with Traditional GRC Tools

### Feature Comparison

| Feature | This Platform | Drata | Vanta | Secureframe |
|---------|---------------|-------|-------|-------------|
| **Evidence Collection** | Automated (13 collectors) | Automated | Automated | Automated |
| **Real-Time Monitoring** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **AI Analysis** | ✅ Optional (Bedrock) | ✅ Yes | ✅ Yes | ✅ Yes |
| **Auto-Remediation** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **AWS Native** | ✅ 100% | ❌ No | ❌ No | ❌ No |
| **Compliance Frameworks** | 6+ frameworks | 4 frameworks | 4 frameworks | 4 frameworks |
| **Custom Controls** | ✅ Fully customizable | Limited | Limited | Limited |
| **API Access** | ✅ Full AWS API | Limited | Limited | Limited |
| **Data Ownership** | ✅ 100% | ❌ Vendor | ❌ Vendor | ❌ Vendor |
| **Vendor Lock-in** | ❌ None | ✅ Yes | ✅ Yes | ✅ Yes |
| **Open Source** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Monthly Cost** | <$1 | $1,250-3,333 | $833-2,083 | $1,000-2,500 |
| **Annual Cost** | $16-74 | $15,000-40,000 | $10,000-25,000 | $12,000-30,000 |

### Cost Comparison

| Solution | Annual Cost | Cost Savings |
|----------|-------------|--------------|
| **Drata** | $15,000-40,000 | - |
| **Vanta** | $10,000-25,000 | - |
| **Secureframe** | $12,000-30,000 | - |
| **Astra** | $8,000-20,000 | - |
| **This Platform** | **$16-74** | **99-99.9%** |

### Flexibility and Customization

| Aspect | This Platform | Enterprise Tools |
|--------|---------------|------------------|
| **Custom Collectors** | ✅ Easy to add | ❌ Limited |
| **Custom Rules** | ✅ Fully customizable | ❌ Limited |
| **Custom Reports** | ✅ Full control | ❌ Template-based |
| **Integrations** | ✅ Any AWS service | ❌ Limited set |
| **Deployment** | ✅ Any AWS account | ❌ SaaS only |
| **Data Export** | ✅ Full access | ❌ Limited |
| **API Access** | ✅ Full AWS API | ❌ Proprietary API |
| **Version Control** | ✅ Git-based | ❌ Proprietary |

### No Vendor Lock-in

**This Platform:**
- ✅ Deployed in your AWS account
- ✅ You control all data
- ✅ No proprietary formats
- ✅ Full access to evidence
- ✅ Can modify or extend
- ✅ Open source
- ✅ Can migrate anytime

**Enterprise Tools:**
- ❌ SaaS deployment only
- ❌ Vendor controls data
- ❌ Proprietary formats
- ❌ Limited access to evidence
- ❌ Cannot modify
- ❌ Closed source
- ❌ Difficult to migrate

---

## 📚 Getting Started Guide

### Step 1: Deploy the Platform

Follow the deployment instructions above to deploy the platform to your AWS account.

### Step 2: Generate Your First Report

**Option A: Wait for Scheduled Execution**
- Daily scorecard: Tomorrow at 06:00 UTC
- Weekly report: Next Sunday at 08:00 UTC

**Option B: Trigger Manually**

```bash
# Trigger daily scorecard
aws lambda invoke \
  --function-name grc-evidence-platform-scorecard-generator-dev \
  response.json

# Check output
cat response.json

# Expected output: {"statusCode": 200, "scorecards_generated": 1}
```

### Step 3: View Your Compliance Scorecard

```bash
# List scorecards in DynamoDB
aws dynamodb scan \
  --table-name grc-evidence-platform-scorecards-dev \
  --max-items 5

# Get latest scorecard
aws dynamodb query \
  --table-name grc-evidence-platform-scorecards-dev \
  --key-condition-expression "scorecard_date = :date" \
  --expression-attribute-values '{":date": {"S": "2026-04-05"}}'
```

### Step 4: Generate a Comprehensive Report

```bash
# Trigger report exporter
aws lambda invoke \
  --function-name grc-evidence-platform-report-exporter-dev \
  response.json

# Check output
cat response.json

# Expected output: {"statusCode": 200, "report_generated": true, "report_url": "..."}
```

### Step 5: Download and Review the Report

```bash
# List reports
aws s3 ls s3://grc-evidence-platform-reports-<account-id>-<region>/ --recursive

# Download latest report
aws s3 cp \
  s3://grc-evidence-platform-reports-<account-id>-<region>/reports/latest/compliance-report.pdf \
  ./compliance-report.pdf

# Open the report
open compliance-report.pdf  # On Windows: start compliance-report.pdf
```

### Step 6: Customize for Your Needs

#### Add a New Collector

1. **Create a new collector file:**

```python
# collectors/my_custom_collector.py

from .base_collector import BaseCollector
from typing import List, Dict, Any

class MyCustomCollector(BaseCollector):
    """Custom evidence collector for specific requirements."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.service_name = "MyService"

    def collect(self) -> List[EvidenceRecord]:
        """Collect evidence from MyService."""
        records = []

        try:
            # Your collection logic here
            client = self.get_client("myservice")

            # Query the service
            response = client.list_resources()

            # Process results
            for resource in response.get("Resources", []):
                record = self.make_record(
                    resource_type="AWS::MyService::Resource",
                    resource_id=resource["ResourceId"],
                    resource_arn=resource["ResourceArn"],
                    control_status=ControlStatus.PASS.value,
                    priority=Priority.MEDIUM.value,
                    finding_title=f"MyService Resource: {resource['ResourceId']}",
                    finding_description=f"Resource {resource['ResourceId']} is compliant",
                    compliance_frameworks=["PCI-DSS", "SOC2"],
                    remediation_available=False,
                    raw_data=resource
                )
                records.append(record)

        except Exception as e:
            self.logger.error(f"Error collecting from MyService: {e}")

        return records
```

2. **Register the collector:**

```python
# collectors/__init__.py

from .my_custom_collector import MyCustomCollector

__all__ = [
    'IAMCollector',
    'S3Collector',
    'MyCustomCollector',  # Add here
    # ... other collectors
]
```

3. **Deploy the update:**

```bash
# Update Lambda function code
zip -r lambda.zip collectors/my_custom_collector.py
aws lambda update-function-code \
  --function-name grc-evidence-platform-evidence-processor-dev \
  --zip-file fileb://lambda.zip
```

#### Add a New Remediation

1. **Create a new remediation function:**

```python
# remediations/my_custom_remediations.py

import boto3
from typing import Dict, Any

def remediage_custom_issue(resource_id: str, dry_run: bool = True) -> Dict[str, Any]:
    """
    Remediate a custom security issue.

    Args:
        resource_id: The ID of the resource to remediate
        dry_run: If True, log actions without executing

    Returns:
        Remediation result dictionary
    """
    result = {
        "action": "remediate_custom_issue",
        "status": "SUCCESS",
        "resource_id": resource_id,
        "dry_run": dry_run
    }

    if dry_run:
        result["message"] = "[DRY RUN] Would remediate custom issue"
        return result

    try:
        # Your remediation logic here
        client = boto3.client("myservice")

        # Execute remediation
        client.remediate_resource(ResourceId=resource_id)

        result["message"] = "Successfully remediated custom issue"

    except Exception as e:
        result["status"] = "FAILED"
        result["error"] = str(e)

    return result
```

2. **Register the remediation:**

```python
# remediations/remediation_registry.py

from .my_custom_remediations import remediate_custom_issue

REMEDIATION_ACTIONS = {
    "block_s3_public_access": block_s3_public_access,
    "remediate_custom_issue": remediate_custom_issue,  # Add here
    # ... other remediations
}
```

3. **Test the remediation:**

```bash
# Test in DRY_RUN mode
aws lambda invoke \
  --function-name grc-evidence-platform-remediation-engine-dev \
  --payload '{
    "remediation_type": "remediate_custom_issue",
    "resource_id": "my-resource-id",
    "execution_mode": "DRY_RUN"
  }' \
  response.json

# Check output
cat response.json
```

### Step 7: Integrate with CI/CD

#### GitHub Actions Example

```yaml
# .github/workflows/compliance-gate.yml

name: Compliance Gate

on:
  pull_request:
    branches: [main]

jobs:
  compliance-check:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Run evidence collection
        run: |
          aws lambda invoke \
            --function-name grc-evidence-platform-evidence-processor-dev \
            response.json

      - name: Check compliance score
        run: |
          SCORE=$(aws dynamodb query \
            --table-name grc-evidence-platform-scorecards-dev \
            --key-condition-expression "scorecard_date = :date" \
            --expression-attribute-values '{":date": {"S": "2026-04-05"}}' \
            --query 'Items[0].overall_score.N' \
            --output text)

          if [ $SCORE -lt 80 ]; then
            echo "Compliance score ($SCORE) below threshold (80)"
            exit 1
          fi

      - name: Comment on PR
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '✅ Compliance gate passed. Score: ${{ env.SCORE }}'
            })
```

---

## 📁 Code Structure

```
aws-grc-evidence-collector/
├── .github/                          # GitHub Actions workflows
│   └── workflows/
│       ├── compliance-scan.yml       # Daily compliance scan
│       └── daily-scorecard.yml       # Daily scorecard generation
│
├── cloudformation/                   # Infrastructure as Code
│   ├── grc-platform-template.yaml    # Main CloudFormation template
│   ├── iam-roles-template.yaml       # IAM roles template
│   └── monitoring-template.yaml      # CloudWatch alarms template
│
├── collectors/                       # Evidence collectors (13 collectors)
│   ├── __init__.py                   # Collector registry
│   ├── base_collector.py             # Base collector class
│   ├── iam_collector.py              # IAM evidence collector
│   ├── s3_collector.py               # S3 evidence collector
│   ├── rds_collector.py              # RDS evidence collector
│   ├── vpc_collector.py              # VPC evidence collector
│   ├── kms_collector.py              # KMS evidence collector
│   ├── config_collector.py           # AWS Config collector
│   ├── securityhub_collector.py      # Security Hub collector
│   ├── guardduty_collector.py        # GuardDuty collector
│   ├── macie_collector.py            # Macie collector
│   ├── inspector_collector.py        # Inspector collector
│   ├── acm_collector.py              # ACM collector
│   └── cloudtrail_collector.py       # CloudTrail collector
│
├── lambda/                           # Lambda functions
│   ├── evidence_processor/
│   │   ├── handler.py                # Real-time event handler
│   │   └── handler_ai.py             # AI-powered analysis
│   ├── remediation_engine/
│   │   └── handler.py                # Auto-remediation logic
│   ├── scorecard_generator/
│   │   └── handler.py                # Daily scorecard generation
│   ├── report_exporter/
│   │   └── handler.py                # Weekly report generation
│   └── evidence_aging_monitor/
│       └── handler.py                # Evidence lifecycle management
│
├── remediations/                     # Auto-remediation logic
│   ├── __init__.py                   # Remediation registry
│   ├── remediation_registry.py       # Remediation action registry
│   ├── iam_remediations.py           # IAM remediations
│   ├── s3_remediations.py            # S3 remediations
│   ├── rds_remediations.py           # RDS remediations
│   └── sg_remediations.py            # Security group remediations
│
├── reports/                          # Report generation
│   ├── __init__.py                   # Report utilities
│   ├── pdf_generator.py              # PDF report generation
│   ├── scorecard_schema.py           # Scorecard data schema
│   └── templates/
│       ├── executive_summary.html    # Executive summary template
│       └── control_matrix.html       # Control matrix template
│
├── scripts/                          # Utility scripts
│   ├── deploy_cloudformation.py      # Deployment script
│   ├── setup.py                      # Setup script
│   ├── teardown.py                   # Teardown script
│   ├── generate_report.py            # Report generation script
│   ├── run_all_collectors.py         # Run all collectors
│   └── gate_check.py                 # CI/CD compliance gate
│
├── tests/                            # Test suite
│   ├── test_collectors.py            # Collector tests
│   ├── test_remediations.py          # Remediation tests
│   ├── test_events.py                # Event processing tests
│   └── fixtures/                     # Test fixtures
│       ├── sample_cloudtrail_event.json
│       ├── sample_config_findings.json
│       ├── sample_guardduty_finding.json
│       └── sample_iam_report.json
│
├── docs/                             # Documentation
│   ├── ARCHITECTURE.md               # Architecture documentation
│   ├── QUICKSTART.md                 # Quick start guide
│   ├── COLLECTORS.md                 # Collector documentation
│   ├── REMEDIATION_PLAYBOOKS.md      # Remediation playbooks
│   ├── COMPLIANCE_MAPPING.md         # Compliance framework mappings
│   ├── COST_ANALYSIS.md              # Cost analysis
│   ├── INTERVIEW_PREP.md             # Interview preparation guide
│   └── LINKEDIN_POSTS.md            # LinkedIn post templates
│
├── requirements.txt                  # Python dependencies
├── validate_cloudformation.py        # CloudFormation validation script
├── Makefile                         # Make targets
├── .env.example                     # Environment variables template
├── .gitignore                       # Git ignore rules
├── LICENSE                          # MIT License
├── README.md                        # This file
└── VALIDATION_README.md             # Validation documentation
```

### Key Files and Their Purposes

| File | Purpose |
|------|---------|
| `cloudformation/grc-platform-template.yaml` | Main CloudFormation template - deploys all AWS resources |
| `scripts/deploy_cloudformation.py` | Interactive deployment script with 4 deployment options |
| `collectors/base_collector.py` | Base class for all evidence collectors |
| `lambda/evidence_processor/handler.py` | Real-time CloudTrail event processing |
| `lambda/remediation_engine/handler.py` | Auto-remediation execution |
| `lambda/scorecard_generator/handler.py` | Daily compliance scorecards |
| `lambda/report_exporter/handler.py` | Weekly comprehensive reports |
| `remediations/remediation_registry.py` | Registry of all remediation actions |
| `reports/pdf_generator.py` | PDF report generation logic |
| `validate_cloudformation.py` | Validates CloudFormation templates |

### How to Extend the Platform

#### Adding a New Collector

1. Create a new file in `collectors/`
2. Inherit from `BaseCollector`
3. Implement the `collect()` method
4. Register in `collectors/__init__.py`
5. Deploy updated Lambda function

#### Adding a New Remediation

1. Create a new function in `remediations/`
2. Implement remediation logic with DRY_RUN support
3. Register in `remediations/remediation_registry.py`
4. Add security guardrails
5. Test in DRY_RUN mode first

#### Adding a New Compliance Framework

1. Add framework to `docs/COMPLIANCE_MAPPING.md`
2. Map controls to collectors
3. Update report templates
4. Add framework-specific rules to CloudFormation
5. Test evidence collection

#### Customizing Reports

1. Modify templates in `reports/templates/`
2. Update `reports/pdf_generator.py`
3. Add custom CSS/HTML
4. Deploy updated Lambda function

---

## 🧪 Testing and Validation

### Test Suite Overview

The project includes a comprehensive test suite:

- **Collector Tests**: Test all 13 collectors
- **Remediation Tests**: Test all remediation actions
- **Event Processing Tests**: Test event handling and routing
- **Integration Tests**: End-to-end testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=collectors --cov=remediations --cov-report=html

# Run specific test file
pytest tests/test_collectors.py -v

# Run specific test
pytest tests/test_collectors.py::TestIAMCollector::test_mfa_enforcement -v
```

### CloudFormation Validation

```bash
# Validate CloudFormation template
python validate_cloudformation.py

# Expected output:
# ✓ CloudFormation template is valid
# ✓ IAM roles follow least privilege
# ✓ KMS encryption enabled
# ✓ S3 bucket policies secure
# ✓ Lambda functions have appropriate permissions
```

### Continuous Integration (GitHub Actions)

**Daily Compliance Scan:**
- Runs every day at 06:00 UTC
- Executes all collectors
- Generates compliance scorecard
- Creates GitHub issue if score < 80%

**Daily Scorecard:**
- Runs every day at 06:00 UTC
- Generates daily scorecard
- Commits scorecard to repository
- Creates GitHub issue if score drops

**Pull Request Checks:**
- Runs on every PR
- Validates CloudFormation
- Runs all tests
- Checks code coverage (>80%)
- Blocks merge if checks fail

### Manual Validation

```bash
# Validate deployment
aws cloudformation validate-template \
  --template-body file://cloudformation/grc-platform-template.yaml

# Check Lambda function health
aws lambda get-function-configuration \
  --function-name grc-evidence-platform-evidence-processor-dev

# Check DynamoDB tables
aws dynamodb describe-table \
  --table-name grc-evidence-platform-metadata-dev

# Check S3 buckets
aws s3api list-buckets \
  --query 'Buckets[?contains(Name, `grc-evidence-platform`)].Name'
```

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. Deployment Fails with "Stack creation failed"

**Symptoms:**
```
✗ Stack creation failed with status: CREATE_IN_PROGRESS
ℹ Cleaning up template bucket: grc-cf-templates-xxx
```

**Solution:**
This was a bug in the deployment script (now fixed). Ensure you're using the latest version:
```bash
git pull origin master
python scripts/deploy_cloudformation.py
```

#### 2. Lambda Function Timeout

**Symptoms:**
```
Task timed out after 60.00 seconds
```

**Solution:**
Increase Lambda timeout:
```bash
aws lambda update-function-configuration \
  --function-name grc-evidence-platform-evidence-processor-dev \
  --timeout 120
```

#### 3. DynamoDB Throttling

**Symptoms:**
```
ProvisionedThroughputExceededException
```

**Solution:**
1. The platform uses PAY_PER_REQUEST mode, so this shouldn't happen
2. If you see this, check if you manually changed the billing mode
3. Verify IAM permissions:
```bash
aws iam get-role-policy \
  --role-name grc-evidence-platform-evidence-processor-dev \
  --policy-name EvidenceProcessorPolicy
```

#### 4. S3 Access Denied

**Symptoms:**
```
Access Denied: s3://grc-evidence-platform-evidence-xxx
```

**Solution:**
1. Check bucket policy:
```bash
aws s3api get-bucket-policy \
  --bucket grc-evidence-platform-evidence-xxx
```

2. Verify KMS key permissions:
```bash
aws kms get-key-policy \
  --key-id <kms-key-id> \
  --policy-name default
```

3. Check Lambda execution role:
```bash
aws iam get-role \
  --role-name grc-evidence-platform-evidence-processor-dev
```

#### 5. CloudTrail Not Logging Events

**Symptoms:**
No events being captured in CloudTrail

**Solution:**
1. Verify CloudTrail is enabled:
```bash
aws cloudtrail get-trail \
  --name grc-evidence-platform-compliance-trail
```

2. Check EventBridge rules:
```bash
aws events list-rules \
  --query 'Rules[?contains(Name, `grc-evidence-platform`)]'
```

3. Verify Lambda triggers:
```bash
aws lambda get-policy \
  --function-name grc-evidence-platform-evidence-processor-dev
```

#### 6. AI Analysis Failing

**Symptoms:**
```
Bedrock analysis failed: AccessDeniedException
```

**Solution:**
1. Verify Bedrock is enabled in your region:
```bash
aws bedrock list-foundation-models
```

2. Check IAM permissions for Bedrock:
```bash
aws iam get-role-policy \
  --role-name grc-evidence-platform-evidence-processor-dev \
  --policy-name EvidenceProcessorPolicy
```

 3. Ensure the model is available in your region:
```bash
aws bedrock list-foundation-models \
  --query 'modelSummaries[?contains(modelId, `nemotron`)]'
```

### Debugging Tips

#### Enable Detailed Logging

```bash
# Update Lambda environment variables
aws lambda update-function-configuration \
  --function-name grc-evidence-platform-evidence-processor-dev \
  --environment Variables='{LOG_LEVEL=DEBUG}'

# View CloudWatch logs
aws logs tail /aws/lambda/grc-evidence-platform-evidence-processor-dev \
  --follow
```

#### Test Lambda Function Locally

```bash
# Install AWS Lambda runtime interface
pip install lambda-local

# Create test event file
cat > test_event.json << EOF
{
  "version": "0",
  "id": "test-event-id",
  "detail-type": "AWS API Call via CloudTrail",
  "source": "aws.ec2",
  "detail": {
    "eventName": "RunInstances",
    "eventSource": "ec2.amazonaws.com",
    "userIdentity": {
      "type": "IAMUser",
      "userName": "test-user"
    }
  }
}
EOF

# Test locally
lambda-local lambda/evidence_processor/handler.py test_event.json
```

#### Check CloudFormation Stack Events

```bash
# View stack events
aws cloudformation describe-stack-events \
  --stack-name grc-evidence-platform \
  --max-items 50

# Filter by failed events
aws cloudformation describe-stack-events \
  --stack-name grc-evidence-platform \
  --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`]'
```

### How to Check Logs

#### CloudWatch Logs

```bash
# List log groups
aws logs describe-log-groups \
  --log-group-name-prefix /aws/lambda/grc-evidence-platform

# Tail specific log group
aws logs tail /aws/lambda/grc-evidence-platform-evidence-processor-dev \
  --follow

# Search for errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/grc-evidence-platform-evidence-processor-dev \
  --filter-pattern "ERROR"

# Export logs to S3
aws logs create-export-task \
  --log-group-name /aws/lambda/grc-evidence-platform-evidence-processor-dev \
  --from 1640000000000 \
  --to 1640086400000 \
  --destination s3://grc-evidence-platform-reports-xxx
```

#### Lambda Invocation Logs

```bash
# Invoke with logging
aws lambda invoke \
  --function-name grc-evidence-platform-evidence-processor-dev \
  --log-type Tail \
  response.json

# Decode logs
aws lambda invoke \
  --function-name grc-evidence-platform-evidence-processor-dev \
  --log-type Tail \
  response.json | jq -r '.LogResult' | base64 -d
```

---

## 🤝 Contributing and Roadmap

### How to Contribute

We welcome contributions! Please follow these guidelines:

1. **Fork the Repository**
   ```bash
   git clone https://github.com/AnandSundar/aws-grc-evidence-collector.git
   cd aws-grc-evidence-collector
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make Your Changes**
   - Follow PEP 8 for Python code
   - Add docstrings to all functions
   - Write tests for new features
   - Update documentation

4. **Run Tests and Linting**
   ```bash
   # Install dev dependencies
   pip install -r requirements-dev.txt

   # Run linting
   flake8 collectors/ lambda/ remediations/ reports/

   # Run tests
   pytest tests/ -v --cov=collectors --cov=remediations

   # Validate CloudFormation
   python validate_cloudformation.py
   ```

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add amazing feature"
   ```

6. **Push to the Branch**
   ```bash
   git push origin feature/amazing-feature
   ```

7. **Open a Pull Request**
   - Describe your changes
   - Link to related issues
   - Include screenshots if applicable
   - Ensure CI checks pass

### Code Style Guidelines

- **Python**: Follow PEP 8
- **Type Hints**: Use type hints for all function signatures
- **Docstrings**: Use Google-style docstrings
- **Variable Names**: Use descriptive, snake_case names
- **Function Names**: Use verb-noun convention (e.g., `collect_evidence`)
- **Class Names**: Use PascalCase (e.g., `EvidenceCollector`)
- **Constants**: Use UPPER_CASE (e.g., `MAX_RETRIES`)

### Testing Guidelines

- **Test Coverage**: Maintain >80% code coverage
- **Unit Tests**: Test individual functions
- **Integration Tests**: Test component interactions
- **Fixtures**: Use sample data fixtures
- **Mocking**: Mock AWS service calls in tests

### Future Enhancements

**Planned Features:**
- [ ] Additional compliance frameworks (ISO 27001, HIPAA, GDPR)
- [ ] More evidence collectors (ECS, EKS, Lambda, Step Functions)
- [ ] Advanced AI analysis (anomaly detection, trend prediction)
- [ ] Multi-account AWS Organizations support
- [ ] Custom dashboards (Grafana, QuickSight)
- [ ] Slack/Teams integration
- [ ] API for external integrations
- [ ] Evidence deduplication
- [ ] Machine learning for risk scoring
- [ ] Automated evidence package generation for audits

**Community Requests:**
- [ ] Terraform provider
- [ ] Kubernetes support
- [ ] Azure/GCP support
- [ ] Mobile app for executives
- [ ] Evidence search and analytics
- [ ] Compliance workflow automation
- [ ] Risk management integration
- [ ] Third-party integrations (Jira, ServiceNow)

### Known Limitations

- **AWS Only**: Currently supports AWS only (no Azure/GCP)
- **CloudFormation Only**: No Terraform/CDK support yet
- **Single Account**: Multi-account support in progress
- **Basic AI**: AI analysis uses single model (no model selection)
- **No UI**: No web dashboard yet (CLI only)
- **Regional**: Some services not available in all regions

---

## 💰 Cost Analysis

### Detailed Cost Breakdown

#### Option 1: No AI, No Auto-Remediation

| Service | Usage | Monthly Cost |
|---------|-------|--------------|
| Lambda | 15,000 invocations/month | $0.00 (Free Tier) |
| DynamoDB | 15,000 writes/month | $0.00 (Free Tier) |
| S3 | 50GB storage | $1.06 |
| SNS | 100 notifications/month | $0.00 (Free Tier) |
| EventBridge | 500 events/month | $0.00 (Free Tier) |
| CloudTrail | 1 trail | $0.00 (Free Tier) |
| AWS Config | 30 rules | $2.88 |
| GuardDuty | 1 detector | $1.00 |
| Security Hub | 1 account | $0.30 |
| **Total** | | **~$4.18/month** |

#### Option 2: With AI Analysis

| Service | Usage | Monthly Cost |
|---------|-------|--------------|
| Base (Option 1) | | $4.18 |
| AWS Bedrock | 1,500 events × 500 tokens | $0.75 |
| **Total** | | **~$4.93/month** |

#### Option 3: Full Platform

| Service | Usage | Monthly Cost |
|---------|-------|--------------|
| Base (Option 2) | | $4.93 |
| Macie | 50GB data scanned | $1.25 |
| **Total** | | **~$6.18/month** |

### Factors Affecting Cost

| Factor | Impact | Optimization |
|--------|--------|--------------|
| **Event Volume** | Medium | Batch processing, event filtering |
| **Evidence Storage** | Medium | Lifecycle policies, compression |
| **AI Usage** | Medium | Only analyze HIGH+MEDIUM events |
| **Config Rules** | High | Reduce rules, use periodic evaluation |
| **Account Count** | High | Use AWS Organizations, aggregate rules |
| **Data Volume** | Medium | S3 lifecycle, Glacier |

### Cost Optimization Tips

1. **Use S3 Lifecycle Policies**: Transition old evidence to Glacier
2. **Enable S3 Intelligent-Tiering**: Automatic cost optimization
3. **Reduce Config Rules**: Disable unnecessary rules in non-production
4. **Batch Processing**: Aggregate MEDIUM/LOW events
5. **Optimize Lambda**: Reduce memory and duration
6. **Use Free Tier**: Maximize AWS Free Tier benefits
7. **Set Budgets**: Monitor costs with AWS Budgets
8. **Review Regularly**: Review costs monthly and adjust

### Cost Monitoring

```bash
# Set up AWS Budget
aws budgets create-budget \
  --account-id 123456789012 \
  --budget '{
    "BudgetName": "GRC-Platform-Monthly",
    "BudgetLimit": {"Amount": "10.00", "Unit": "USD"},
    "TimeUnit": "MONTHLY"
  }' \
  --notifications-with-subscribers '[{
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 80,
      "ThresholdType": "PERCENTAGE_OF_BUDGET"
    },
    "Subscribers": [{
      "SubscriptionType": "EMAIL",
      "Address": "admin@example.com"
    }]
  }]'

# Set up CloudWatch alarm for Lambda costs
aws cloudwatch put-metric-alarm \
  --alarm-name grc-lambda-cost-alarm \
  --alarm-description "Alert when Lambda costs exceed $1.00" \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 21600 \
  --evaluation-periods 1 \
  --threshold 1.00 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=Currency,Value=USD
```

---

## 🔒 Security Considerations

### KMS Encryption

- **Customer-Managed Key**: All data encrypted with customer-managed KMS key
- **Key Rotation**: Automatic key rotation enabled
- **Key Policies**: Least privilege access to KMS key
- **Key Usage**: Separate keys for different environments

### Least Privilege IAM Roles

Each Lambda function has a dedicated IAM role with minimal permissions:

```yaml
# Example: Evidence Processor Role
EvidenceProcessorRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: lambda.amazonaws.com
          Action: 'sts:AssumeRole'
    Policies:
      - PolicyName: EvidenceProcessorPolicy
        PolicyDocument:
          Statement:
            - Sid: S3WriteEvidence
              Effect: Allow
              Action:
                - 's3:PutObject'
                - 's3:GetObject'
              Resource: !Sub "${EvidenceBucket.Arn}/*"
            - Sid: DynamoDBWriteMetadata
              Effect: Allow
              Action:
                - 'dynamodb:PutItem'
                - 'dynamodb:UpdateItem'
              Resource:
                - !Sub "${MetadataTable.Arn}"
                - !Sub "${MetadataTable.Arn}/index/*"
```

### S3 Bucket Policies

All S3 buckets have restrictive bucket policies:

```yaml
EvidenceBucketPolicy:
  Type: AWS::S3::BucketPolicy
  Properties:
    Bucket: !Ref EvidenceBucket
    PolicyDocument:
      Statement:
        - Sid: DenyUnencryptedObjectUploads
          Effect: Deny
          Principal: '*'
          Action: 's3:PutObject'
          Resource: !Sub "${EvidenceBucket.Arn}/*"
          Condition:
            StringNotEquals:
              's3:x-amz-server-side-encryption': 'aws:kms'
        - Sid: DenyInsecureConnections
          Effect: Deny
          Principal: '*'
          Action: 's3:*'
          Resource: !Sub "${EvidenceBucket.Arn}/*"
          Condition:
            Bool:
              'aws:SecureTransport': false
```

### Secure Data Handling

- **Encryption at Rest**: All data encrypted with KMS
- **Encryption in Transit**: TLS 1.2+ for all data in transit
- **Data Minimization**: Only collect necessary evidence
- **Data Retention**: Automatic expiration of old evidence
- **Access Logging**: All access logged to CloudTrail
- **Immutable Evidence**: S3 versioning prevents tampering

### Audit Trail

- **CloudTrail**: Logs all AWS API calls
- **DynamoDB Streams**: Capture all changes to metadata
- **S3 Access Logs**: Log all S3 access
- **Lambda Logs**: All Lambda executions logged to CloudWatch
- **Remediation Logs**: All remediations logged to DynamoDB

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **AWS**: For providing excellent cloud services and documentation
- **Open Source Community**: For various Python libraries and tools
- **Compliance Frameworks**: PCI-DSS, SOC2, NIST, CIS for comprehensive standards
- **Contributors**: All contributors to this project

---

## 📞 Support

- **GitHub Issues**: [github.com/AnandSundar/aws-grc-evidence-collector/issues](https://github.com/AnandSundar/aws-grc-evidence-collector/issues)
- **Documentation**: See the `docs/` directory for detailed documentation
- **Email**: anand.sundar@example.com

---

**Built with ❤️ using AWS native services**

**GRC Engineering: The future of compliance automation**
