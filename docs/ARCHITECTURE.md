# GRC Evidence Platform v2.0 - Architecture Documentation

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Data Flow Walkthrough](#data-flow-walkthrough)
3. [Evidence Record Lifecycle](#evidence-record-lifecycle)
4. [Remediation Flow](#remediation-flow)
5. [Scorecard Generation Flow](#scorecard-generation-flow)
6. [CI/CD Pipeline Flow](#cicd-pipeline-flow)
7. [Component Details](#component-details)
8. [Security Considerations](#security-considerations)

---

## High-Level Architecture

### Overview

The GRC Evidence Platform v2.0 is an event-driven, serverless architecture that automatically collects, analyzes, and reports on AWS security compliance evidence. The platform supports multiple compliance frameworks (PCI-DSS, SOC2, CIS, NIST) and provides automated remediation capabilities.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    AWS ACCOUNT - GRC EVIDENCE PLATFORM v2.0                                  │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                             │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐                       │
│  │   AWS API    │─────▶│ CloudTrail   │─────▶│ EventBridge  │─────▶│  Lambda:     │                       │
│  │   Call Made  │      │   (Events)   │      │   (Rules)    │      │  Handler/    │                       │
│  └──────────────┘      └──────────────┘      └──────────────┘      │  Handler_AI  │                       │
│                                                                      └──────┬───────┘                       │
│                                                                             │                               │
│                                                                             ▼                               │
│  ┌──────────────────────────────────────────────────────────────────────────────────────┐                 │
│  │                          EVIDENCE COLLECTION LAYER                                  │                 │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │                 │
│  │  │   IAM    │  │    RDS   │  │    S3    │  │  Config  │  │Security  │  │Guard   │ │                 │
│  │  │Collector │  │Collector │  │Collector │  │Collector │  │   Hub    │  │  Duty  │ │                 │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘ │                 │
│  │       │             │             │             │             │            │      │                 │
│  │  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐  ┌───▼────┐ │                 │
│  │  │   VPC    │  │    KMS   │  │    ACM   │  │  Macie   │  │Inspector │  │Cloud   │ │                 │
│  │  │Collector │  │Collector │  │Collector │  │Collector │  │Collector │  │ Trail  │ │                 │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘ │                 │
│  └───────┼────────────┼────────────┼────────────┼────────────┼────────────┼───────┘                 │
│          │            │            │            │            │            │                         │
└──────────┼────────────┼────────────┼────────────┼────────────┼────────────┼─────────────────────────┘
           │            │            │            │            │            │
           ▼            ▼            ▼            ▼            ▼            ▼
           └────────────┴────────────┴────────────┴────────────┴────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    STORAGE & PROCESSING LAYER                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
           ┌────────────────┐            ┌────────────────┐
           │  S3 Bucket:    │            │  DynamoDB:     │
           │  Evidence      │            │  Metadata      │
           │  Storage       │            │  Table         │
           │  (JSON files)  │            │  (Index)       │
           └────────┬───────┘            └────────┬───────┘
                    │                             │
                    │                             │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    EVENT PROCESSING LAYER                                                   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
           ┌────────────────┐            ┌────────────────┐
           │  Lambda:       │            │  Lambda:       │
           │  Batch         │            │  Evidence      │
           │  Processor     │            │  Processor     │
           │  (MEDIUM/LOW)  │            │  (Aging)       │
           └────────┬───────┘            └────────┬───────┘
                    │                             │
                    │                             │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    REMEDIATION & NOTIFICATION LAYER                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
           ┌────────────────┐            ┌────────────────┐
           │  Lambda:       │            │  SNS Topic:    │
           │  Remediation   │            │  Alerts        │
           │  Engine        │            │  (Email/SMS)   │
           └────────┬───────┘            └────────┬───────┘
                    │                             │
                    │                             │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    REPORTING & ANALYTICS LAYER                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
           ┌────────────────┐            ┌────────────────┐
           │  Lambda:       │            │  Lambda:       │
           │  Scorecard     │            │  Report        │
           │  Generator     │            │  Exporter      │
           │  (Daily)       │            │  (PDF/CSV)     │
           └────────┬───────┘            └────────┬───────┘
                    │                             │
                    │                             │
                    ▼                             ▼
           ┌────────────────┐            ┌────────────────┐
           │  DynamoDB:     │            │  S3 Bucket:    │
           │  Scorecard     │            │  Reports       │
           │  Table         │            │  (PDF/CSV)     │
           └────────────────┘            └────────┬───────┘
                                                 │
                                                 ▼
                                        ┌────────────────┐
                                        │  Auditor:      │
                                        │  Pre-signed    │
                                        │  URL via Email │
                                        └────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    EXTERNAL SERVICES                                                       │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                    ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
                    │  AWS Bedrock │      │  AWS Config  │      │  AWS Guard   │
                    │  (AI Analysis│      │  (30 Rules)  │      │  Duty        │
                    │  Optional)   │      │              │      │              │
                    └──────────────┘      └──────────────┘      └──────────────┘

                    ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
                    │  AWS Security│      │  AWS Macie   │      │  AWS         │
                    │  Hub         │      │  (PII)       │      │  Inspector   │
                    │              │      │              │      │              │
                    └──────────────┘      └──────────────┘      └──────────────┘
```

### Component Summary

| Component | Type | Purpose |
|-----------|------|---------|
| CloudTrail | Service | Logs all AWS API calls |
| EventBridge | Service | Routes events to Lambda functions |
| Lambda Handler | Function | Processes HIGH priority events in real-time |
| Lambda Handler_AI | Function | Processes events with AI analysis |
| 12 Collectors | Python Modules | Collect compliance evidence from AWS services |
| S3 Bucket | Storage | Stores raw evidence JSON files |
| DynamoDB Metadata | Database | Indexes evidence for fast queries |
| Lambda Batch Processor | Function | Batches MEDIUM/LOW priority events |
| Lambda Evidence Processor | Function | Manages evidence aging and expiration |
| Lambda Remediation Engine | Function | Executes auto-remediation actions |
| SNS Topic | Messaging | Sends alerts via email/SMS |
| Lambda Scorecard Generator | Function | Generates daily compliance scorecards |
| Lambda Report Exporter | Function | Generates PDF/CSV audit reports |
| AWS Config | Service | Evaluates configuration compliance |
| AWS GuardDuty | Service | Threat detection and findings |
| AWS Security Hub | Service | Aggregates security findings |
| AWS Macie | Service | PII data discovery |
| AWS Inspector | Service | Vulnerability scanning |
| AWS Bedrock | Service | AI-powered risk analysis (optional) |

---

## Data Flow Walkthrough

### 24-Step Data Flow: From API Call to Audit Report

```
STEP 1: AWS API Call Made
        │
        ▼
STEP 2: CloudTrail Captures Event
        │
        ▼
STEP 3: EventBridge Rule Triggers
        │
        ▼
STEP 4: Lambda Handler/Handler_AI Invoked
        │
        ▼
STEP 5: Priority Determined (HIGH/MEDIUM/LOW)
        │
        ▼
STEP 6: Evidence Record Created (UUID assigned)
        │
        ▼
STEP 7: Compliance Tags Derived
        │
        ▼
STEP 8: AI Analysis (if enabled and HIGH/MEDIUM priority)
        │
        ▼
STEP 9: Evidence Stored in S3 (evidence/YYYY/MM/DD/UUID.json)
        │
        ▼
STEP 10: Metadata Stored in DynamoDB (with TTL)
        │
        ▼
STEP 11: If HIGH Priority → SNS Alert Sent Immediately
        │
        ▼
STEP 12: If MEDIUM/LOW Priority → Stored in Pending Events Table
        │
        ▼
STEP 13: Batch Processor Runs (Every 15 min for MEDIUM, 60 min for LOW)
        │
        ▼
STEP 14: Batch Processor Queries Pending Events
        │
        ▼
STEP 15: Batch Processor Aggregates Events
        │
        ▼
STEP 16: Batch Processor Sends Batched Email Alert
        │
        ▼
STEP 17: Evidence Processor Runs (Hourly)
        │
        ▼
STEP 18: Evidence Processor Checks Evidence Aging
        │
        ▼
STEP 19: Evidence Processor Updates Aging Status
        │
        ▼
STEP 20: Evidence Processor Expires Old Evidence (after 90 days)
        │
        ▼
STEP 21: Scorecard Generator Runs (Daily at midnight UTC)
        │
        ▼
STEP 22: Scorecard Generator Queries Evidence (Last 24h)
        │
        ▼
STEP 23: Scorecard Generator Calculates Compliance Scores
        │
        ▼
STEP 24: Report Exporter Generates PDF and Emails Pre-signed URL to Auditor
```

### Detailed Step Descriptions

**STEP 1: AWS API Call Made**
- User or service makes an AWS API call (e.g., `CreateUser`, `PutBucketPolicy`)
- Call originates from AWS Console, CLI, SDK, or application
- Event captured by AWS service

**STEP 2: CloudTrail Captures Event**
- CloudTrail records the API call as a management event
- Event includes: eventName, eventSource, eventTime, userIdentity, sourceIPAddress, requestParameters, responseElements
- Event is delivered to CloudWatch Logs and EventBridge in near real-time

**STEP 3: EventBridge Rule Triggers**
- EventBridge rule matches the event pattern
- Rule targets the Lambda Handler or Handler_AI function
- Event payload is passed to Lambda

**STEP 4: Lambda Handler/Handler_AI Invoked**
- Lambda function receives the event payload
- Function extracts event details from the payload
- Processing begins immediately

**STEP 5: Priority Determined (HIGH/MEDIUM/LOW)**
- Event name is checked against priority lists
- HIGH: Security-critical events (CreateUser, DeleteUser, CreateSecurityGroup, etc.)
- MEDIUM: Infrastructure changes (StartInstances, CreateSnapshot, etc.)
- LOW: Routine operations (CreateTag, etc.)
- Root console login is always HIGH priority

**STEP 6: Evidence Record Created (UUID assigned)**
- Unique evidence_id generated using UUID4
- Timestamp recorded in ISO 8601 UTC format
- All event metadata captured in structured format

**STEP 7: Compliance Tags Derived**
- Event name mapped to compliance frameworks
- Tags include: PCI-DSS, SOC2, CIS, NIST control references
- Example: "CreateUser" → ["PCI-DSS-8.3", "SOC2-CC6.1", "NIST-AC-2"]

**STEP 8: AI Analysis (if enabled and HIGH/MEDIUM priority)**
- AWS Bedrock Claude 3 Sonnet analyzes the event
- AI provides: risk_level, risk_score, summary, compliance_impact, anomaly_indicators, recommended_action, false_positive_likelihood, investigation_priority
- LOW priority events skip AI analysis for cost optimization

**STEP 9: Evidence Stored in S3 (evidence/YYYY/MM/DD/UUID.json)**
- Evidence record serialized to JSON
- Stored in S3 bucket with partitioned path by date
- Content-Type set to application/json
- S3 versioning enabled for audit trail

**STEP 10: Metadata Stored in DynamoDB (with TTL)**
- Metadata indexed for fast queries
- Includes: evidence_id, timestamp, event_type, priority, s3_key, ttl
- TTL set to 90 days (7,776,000 seconds)
- Enables automatic expiration of old records

**STEP 11: If HIGH Priority → SNS Alert Sent Immediately**
- SNS topic publishes alert message
- Message includes: event details, AI summary (if available), recommended action
- Email/SMS sent to configured recipients
- Immediate notification for critical security events

**STEP 12: If MEDIUM/LOW Priority → Stored in Pending Events Table**
- Event stored in DynamoDB pending events table
- Includes: event_id, timestamp, priority, processed flag, event details
- Expiry time set to 2x batch interval (30 min for MEDIUM, 120 min for LOW)
- Enables batch processing to reduce alert fatigue

**STEP 13: Batch Processor Runs (Every 15 min for MEDIUM, 60 min for LOW)**
- CloudWatch Events triggers Batch Processor Lambda
- Processor queries pending events by priority
- Rate limiting enforced (max 10 emails/hour)

**STEP 14: Batch Processor Queries Pending Events**
- DynamoDB query for unprocessed events
- Batch size configurable (default: 10 events per batch)
- Events marked as processed to avoid duplicates

**STEP 15: Batch Processor Aggregates Events**
- Events grouped by type and priority
- Summary statistics calculated
- HTML-formatted email body generated

**STEP 16: Batch Processor Sends Batched Email Alert**
- AWS SES sends aggregated email
- Subject includes count and priority level
- Body includes: summary table, event details, recommended actions
- Rate limit counter incremented

**STEP 17: Evidence Processor Runs (Hourly)**
- CloudWatch Events triggers Evidence Processor Lambda
- Processor scans all evidence records
- Checks aging status and compliance

**STEP 18: Evidence Processor Checks Evidence Aging**
- Calculates age of each evidence record
- Categories: FRESH (< 7 days), AGING (7-30 days), STALE (> 30 days)
- Updates aging status in DynamoDB

**STEP 19: Evidence Processor Updates Aging Status**
- Evidence records tagged with aging category
- Alerts generated for STALE evidence
- Helps identify gaps in evidence collection

**STEP 20: Evidence Processor Expires Old Evidence (after 90 days)**
- TTL automatically expires records in DynamoDB
- S3 lifecycle policy archives/deletes old files
- Ensures compliance with retention policies

**STEP 21: Scorecard Generator Runs (Daily at midnight UTC)**
- CloudWatch Events triggers Scorecard Generator Lambda
- Generator queries evidence from last 24 hours
- Calculates compliance metrics

**STEP 22: Scorecard Generator Queries Evidence (Last 24h)**
- DynamoDB query using timestamp GSI
- Filters by evidence creation time
- Retrieves all evidence records in time window

**STEP 23: Scorecard Generator Calculates Compliance Scores**
- Framework scores calculated (PCI-DSS, SOC2, CIS, NIST)
- Overall score computed as weighted average
- Top 5 risks identified by priority and count
- Trend analysis compared to previous day

**STEP 24: Report Exporter Generates PDF and Emails Pre-signed URL to Auditor**
- Report Exporter Lambda generates PDF report
- PDF includes: executive summary, control matrix, findings, scorecard
- PDF stored in S3 reports bucket
- Pre-signed URL generated (valid for 7 days)
- Email sent to auditor with download link

---

## Evidence Record Lifecycle

### Lifecycle Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              EVIDENCE RECORD LIFECYCLE                                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

     COLLECTED                    STORED                     AGED                      REPORTED                    EXPIRED
         │                          │                          │                          │                          │
         ▼                          ▼                          ▼                          ▼                          ▼
  ┌──────────┐              ┌──────────┐              ┌──────────┐              ┌──────────┐              ┌──────────┐
  │ Event    │              │ S3 +     │              │ Age:     │              │ Included │              │ TTL      │
  │ Captured │─────────────▶│ DynamoDB │─────────────▶│ 7-30     │─────────────▶│ in Daily │─────────────▶│ Expires  │
  │ by       │              │ Indexed  │              │ days     │              │ Scorecard│              │ (90      │
  │ Collector│              │ TTL: 90d │              │ Status:  │              │ & PDF    │              │ days)    │
  └──────────┘              └──────────┘              │ STALE    │              └──────────┘              └──────────┘
         │                          │                          │
         │                          │                          │
         │                          │                          ▼
         │                          │                   ┌──────────┐
         │                          │                   │ Alert:   │
         │                          │                   │ Evidence │
         │                          │                   │ Gap      │
         │                          │                   └──────────┘
         │                          │
         │                          │
         ▼                          ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  STATE TRANSITIONS:                                                                                    │
│  • COLLECTED → STORED: Evidence written to S3 and indexed in DynamoDB                                   │
│  • STORED → AGED: Evidence ages beyond 7 days, status updated to AGING or STALE                        │
│  • AGED → REPORTED: Evidence included in daily scorecard and PDF reports                               │
│  • REPORTED → EXPIRED: TTL expires, record removed from DynamoDB, S3 lifecycle deletes file             │
│  • AGED → ALERT: If evidence is STALE (> 30 days), alert generated for evidence gap                    │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Lifecycle States

| State | Duration | Description | Actions |
|-------|----------|-------------|---------|
| **COLLECTED** | Immediate | Event captured by collector or handler | Create evidence record, assign UUID |
| **STORED** | 0-7 days | Evidence in S3 and indexed in DynamoDB | Available for queries, real-time alerts |
| **AGED** | 7-30 days | Evidence aging, status updated | Included in trend analysis |
| **STALE** | > 30 days | Evidence old, potential gap | Alert generated, investigate missing data |
| **REPORTED** | Daily | Evidence included in reports | Part of scorecard and PDF generation |
| **EXPIRED** | 90 days | TTL expires, record removed | Archived or deleted per retention policy |

### Evidence Record Schema

```json
{
  "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
  "collected_at": "2026-04-05T05:24:24.390Z",
  "collector_name": "IAMCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::IAM::User",
  "resource_id": "john.doe",
  "resource_arn": "arn:aws:iam::123456789012:user/john.doe",
  "control_status": "FAIL",
  "priority": "HIGH",
  "finding_title": "IAM User Without MFA",
  "finding_description": "User john.doe does not have MFA enabled",
  "compliance_frameworks": ["PCI-DSS-8.3", "SOC2-CC6.1", "NIST-AC-2"],
  "remediation_available": true,
  "remediation_action": "Enable MFA for user",
  "raw_data": {
    "UserName": "john.doe",
    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
    "Arn": "arn:aws:iam::123456789012:user/john.doe",
    "CreateDate": "2026-01-15T10:30:00Z"
  },
  "ttl": 2592000,
  "ai_analysis": {
    "ai_analyzed": true,
    "risk_level": "HIGH",
    "risk_score": 8,
    "summary": "IAM user without MFA poses significant security risk",
    "compliance_impact": ["PCI-DSS-8.3", "SOC2-CC6.1"],
    "anomaly_indicators": ["No MFA device", "User has console access"],
    "recommended_action": "Enable MFA for user immediately",
    "false_positive_likelihood": "LOW",
    "investigation_priority": "IMMEDIATE"
  }
}
```

---

## Remediation Flow

### Remediation Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              REMEDIATION FLOW                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

     FINDING                       SNS                       LAMBDA                    REMEDIATION
   DETECTED                     ALERT                    INVOKED                    EXECUTED
        │                          │                          │                          │
        ▼                          ▼                          ▼                          ▼
  ┌──────────┐              ┌──────────┐              ┌──────────┐              ┌──────────┐
  │ Config   │─────────────▶│ Topic:   │─────────────▶│ Remediat │─────────────▶│ AWS API  │
  │ Rule or  │              │ GRC-     │              │ ion      │              │ Call     │
  │ Event    │              │ Alerts   │              │ Engine   │              │ Made     │
  │ Bridge   │              └──────────┘              └──────────┘              └──────────┘
  └──────────┘                    │                          │                          │
        │                          │                          │                          │
        │                          │                          │                          ▼
        │                          │                          │                   ┌──────────┐
        │                          │                          │                   │ Resource │
        │                          │                          │                   │ Fixed    │
        │                          │                          │                   └──────────┘
        │                          │                          │
        │                          │                          ▼
        │                          │                   ┌──────────┐
        │                          │                   │ Remediat │
        │                          │                   │ ion Log  │
        │                          │                   │ Written  │
        │                          │                   └──────────┘
        │                          │                          │
        │                          │                          ▼
        │                          │                   ┌──────────┐
        │                          │                   │ SNS      │
        │                          │                   │ Notificat │
        │                          │                   │ ion Sent │
        │                          │                   └──────────┘
        │                          │
        ▼                          ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  SAFETY MODES:                                                                                          │
│  • AUTO: Remediation executes immediately without approval                                              │
│  • APPROVAL_REQUIRED: Remediation requires manual approval before execution                             │
│  • DRY_RUN: Remediation logged but not executed (for testing)                                          │
│  • MANUAL: No automatic remediation, human intervention required                                       │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Remediation Trigger Sources

1. **AWS Config Rule Violation**
   - Config evaluates resource configuration
   - Rule fails → finding sent to EventBridge
   - EventBridge triggers Remediation Engine

2. **EventBridge Pattern Match**
   - Real-time event pattern matching
   - Security-critical events trigger immediate remediation
   - Examples: `PutBucketAcl`, `AuthorizeSecurityGroupIngress`, `CreateAccessKey`

### Remediation Safety Modes

| Safety Mode | Description | Use Case |
|-------------|-------------|----------|
| **AUTO** | Executes immediately without approval | Low-risk, non-disruptive actions (e.g., enable S3 encryption) |
| **APPROVAL_REQUIRED** | Requires manual approval before execution | High-risk actions (e.g., RDS encryption requires snapshot/restore) |
| **DRY_RUN** | Logs action but doesn't execute | Testing, validation, audit trails |
| **MANUAL** | No automatic execution, human intervention required | Complex or business-critical changes |

### Remediation Registry

The platform includes a comprehensive remediation registry mapping triggers to actions:

```python
REMEDIATION_REGISTRY = {
    "s3-bucket-public-read-prohibited": {
        "function": s3_remediations.block_s3_public_access,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6", "CIS-2.1.1"],
        "safety_mode": "AUTO",
    },
    "iam-user-mfa-enabled": {
        "function": iam_remediations.enforce_mfa_for_user,
        "trigger_type": "CONFIG_RULE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-8.4.2", "CIS-1.10", "SOC2-CC6.1"],
        "safety_mode": "AUTO",
    },
    # ... 20+ more remediations
}
```

See [`docs/REMEDIATION_PLAYBOOKS.md`](docs/REMEDIATION_PLAYBOOKS.md) for complete remediation documentation.

---

## Scorecard Generation Flow

### Scorecard Generation Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                           SCORECARD GENERATION FLOW (Daily at Midnight UTC)                                │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

     SCHEDULED                     QUERY                      ANALYZE                    GENERATE
     TRIGGER                    EVIDENCE                    SCORES                   SCORECARD
        │                          │                          │                          │
        ▼                          ▼                          ▼                          ▼
  ┌──────────┐              ┌──────────┐              ┌──────────┐              ┌──────────┐
  │ Cloud    │─────────────▶│ DynamoDB │─────────────▶│ Calculate│─────────────▶│ Create   │
  │ Watch    │              │ Query:   │              │ Framework│              │ Scorecard│
  │ Events   │              │ Last 24h │              │ Scores   │              │ Object   │
  └──────────┘              └──────────┘              └──────────┘              └──────────┘
        │                          │                          │                          │
        │                          │                          │                          ▼
        │                          │                          │                   ┌──────────┐
        │                          │                          │                   │ Store in │
        │                          │                          │                   │ DynamoDB │
        │                          │                          │                   └──────────┘
        │                          │                          │
        │                          │                          ▼
        │                          │                   ┌──────────┐
        │                          │                   │ Identify │
        │                          │                   │ Top 5    │
        │                          │                   │ Risks    │
        │                          │                   └──────────┘
        │                          │
        ▼                          ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  SCORECARD METRICS:                                                                                    │
│  • Overall Compliance Score: Weighted average of all framework scores                                   │
│  • Framework Scores: PCI-DSS, SOC2, CIS, NIST individual scores                                        │
│  • Evidence Counts: Total, Critical, High, Medium, Low                                                │
│  • Top 5 Risks: Highest priority findings by count and severity                                       │
│  • Evidence by Collector: Distribution across 12 collectors                                           │
│  • Remediation Summary: Available, Executed, Failed                                                   │
│  • SLA Adherence: Percentage of evidence collected within SLA                                          │
│  • Trend Analysis: Comparison to previous day's scorecard                                             │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Scorecard Data Structure

```python
@dataclass
class ComplianceScorecard:
    scorecard_date: str                    # "2026-04-05"
    generated_at: str                      # "2026-04-05T00:00:00Z"
    account_id: str                        # "123456789012"
    overall_score: float                   # 87.5
    overall_trend: Optional[str]           # "UP", "DOWN", "STABLE"
    framework_scores: List[FrameworkScore] # Individual framework scores
    total_evidence_count: int              # 1250
    critical_count: int                    # 5
    high_count: int                        # 23
    medium_count: int                      # 87
    low_count: int                         # 1135
    top_5_risks: List[Dict[str, Any]]      # Top 5 risk findings
    evidence_by_collector: Dict[str, int]  # Evidence count per collector
    remediation_summary: Dict[str, int]    # Remediation statistics
    sla_adherence: float                   # 98.2
```

### Scorecard Generation Process

1. **Scheduled Trigger**: CloudWatch Events triggers Lambda at midnight UTC daily
2. **Query Evidence**: DynamoDB query retrieves evidence from last 24 hours using timestamp GSI
3. **Calculate Scores**:
   - Group evidence by compliance framework
   - Calculate pass/fail ratios
   - Compute weighted average for overall score
4. **Identify Risks**: Sort findings by priority and count, select top 5
5. **Generate Scorecard**: Create ComplianceScorecard object with all metrics
6. **Store in DynamoDB**: Persist scorecard for historical tracking and trend analysis
7. **Trend Analysis**: Compare to previous day's scorecard, determine trend direction

See [`lambda/scorecard_generator/handler.py`](lambda/scorecard_generator/handler.py) for implementation details.

---

## CI/CD Pipeline Flow

### CI/CD Pipeline Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              CI/CD PIPELINE FLOW                                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

     PUSH                        BUILD                      TEST                     DEPLOY
     CODE                      ARTIFACTS                    CODE                   INFRASTRUCTURE
        │                          │                          │                          │
        ▼                          ▼                          ▼                          ▼
  ┌──────────┐              ┌──────────┐              ┌──────────┐              ┌──────────┐
  │ GitHub   │─────────────▶│ GitHub   │─────────────▶│ GitHub   │─────────────▶│ Cloud    │
  │ Push to  │              │ Actions  │              │ Actions  │              │ Formation│
  │ Main/PR  │              │: Build   │              │: Test    │              │ Deploy   │
  └──────────┘              └──────────┘              └──────────┘              └──────────┘
        │                          │                          │                          │
        │                          │                          │                          ▼
        │                          │                          │                   ┌──────────┐
        │                          │                          │                   │ Lambda   │
        │                          │                          │                   │ Functions│
        │                          │                          │                   │ Deployed│
        │                          │                          │                   └──────────┘
        │                          │                          │
        │                          │                          ▼
        │                          │                   ┌──────────┐
        │                          │                   │ Gate     │
        │                          │                   │ Check:   │
        │                          │                   │ Checkov, │
        │                          │                   │ cfn-lint │
        │                          │                   └──────────┘
        │                          │
        ▼                          ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  CI/CD STAGES:                                                                                          │
│  • Build: Install dependencies, package Lambda functions, build deployment artifacts                       │
│  • Test: Run unit tests, integration tests, collector tests                                              │
│  • Gate Check: Run Checkov (IaC security), cfn-lint (CloudFormation validation), compliance-as-code       │
│  • Deploy: Deploy CloudFormation stacks, update Lambda functions, configure infrastructure                 │
│  • Monitor: CloudWatch alarms, deployment health checks                                                  │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### CI/CD Pipeline Stages

#### Stage 1: Build
```yaml
# .github/workflows/deploy.yml
- name: Install dependencies
  run: |
    pip install -r requirements.txt
    
- name: Package Lambda functions
  run: |
    python scripts/package_lambdas.py
    
- name: Build CloudFormation templates
  run: |
    aws cloudformation package \
      --template-file cloudformation/grc-platform-template.yaml \
      --s3-bucket ${DEPLOYMENT_BUCKET} \
      --output-template-file packaged-template.yaml
```

#### Stage 2: Test
```yaml
- name: Run unit tests
  run: |
    pytest tests/test_collectors.py -v
    
- name: Run integration tests
  run: |
    pytest tests/test_events.py -v
    
- name: Run remediation tests
  run: |
    pytest tests/test_remediations.py -v
```

#### Stage 3: Gate Check
```yaml
- name: Run Checkov
  run: |
    checkov -f cloudformation/grc-platform-template.yaml \
      --framework cloudformation \
      --check CKV_AWS_1,CKV_AWS_2,CKV_AWS_3
    
- name: Run cfn-lint
  run: |
    cfn-lint cloudformation/grc-platform-template.yaml
    
- name: Run compliance gate check
  run: |
    python scripts/gate_check.py --compliance pci-dss,soc2,cis
```

#### Stage 4: Deploy
```yaml
- name: Deploy to CloudFormation
  run: |
    aws cloudformation deploy \
      --template-file packaged-template.yaml \
      --stack-name grc-evidence-platform \
      --capabilities CAPABILITY_IAM \
      --parameter-overrides \
        EnableAI=true \
        EnableMediumAlerts=true \
        EnableLowAlerts=true
```

### Compliance-as-Code

The platform implements compliance-as-code through:

1. **Checkov Integration**: Scans CloudFormation templates for security misconfigurations
2. **cfn-lint**: Validates CloudFormation syntax and best practices
3. **Custom Gate Check**: Validates compliance requirements before deployment

```python
# scripts/gate_check.py
def check_compliance(template_path: str, frameworks: List[str]) -> bool:
    """Validate CloudFormation template against compliance frameworks."""
    checks = {
        "pci-dss": check_pci_dss_compliance,
        "soc2": check_soc2_compliance,
        "cis": check_cis_compliance,
    }
    
    for framework in frameworks:
        if framework in checks:
            if not checks[framework](template_path):
                return False
    
    return True
```

---

## Component Details

### Lambda Functions

| Function | Purpose | Trigger | Runtime | Memory |
|----------|---------|---------|---------|--------|
| [`handler.py`](lambda/handler.py) | Process HIGH priority events | EventBridge | Python 3.11 | 256MB |
| [`handler_ai.py`](lambda/handler_ai.py) | Process events with AI analysis | EventBridge | Python 3.11 | 512MB |
| [`batch_processor.py`](lambda/batch_processor.py) | Batch MEDIUM/LOW priority events | CloudWatch Events (15/60 min) | Python 3.11 | 256MB |
| [`evidence_processor/handler.py`](lambda/evidence_processor/handler.py) | Manage evidence aging | CloudWatch Events (hourly) | Python 3.11 | 256MB |
| [`remediation_engine/handler.py`](lambda/remediation_engine/handler.py) | Execute auto-remediations | SNS Topic | Python 3.11 | 512MB |
| [`scorecard_generator/handler.py`](lambda/scorecard_generator/handler.py) | Generate daily scorecards | CloudWatch Events (daily) | Python 3.11 | 512MB |
| [`report_exporter/handler.py`](lambda/report_exporter/handler.py) | Generate PDF reports | SNS Topic | Python 3.11 | 1024MB |

### Collectors

| Collector | Checks | AWS Services | Compliance Frameworks |
|-----------|--------|--------------|----------------------|
| [`iam_collector.py`](collectors/iam_collector.py) | 10 | IAM | PCI-DSS, SOC2, CIS, NIST |
| [`rds_collector.py`](collectors/rds_collector.py) | 9 | RDS | PCI-DSS, SOC2, CIS, NIST |
| [`s3_collector.py`](collectors/s3_collector.py) | 7 | S3 | PCI-DSS, SOC2, CIS, NIST |
| [`config_collector.py`](collectors/config_collector.py) | 20 rules | Config | PCI-DSS, SOC2, CIS, NIST |
| [`securityhub_collector.py`](collectors/securityhub_collector.py) | Findings | Security Hub | PCI-DSS, SOC2, CIS, NIST |
| [`guardduty_collector.py`](collectors/guardduty_collector.py) | Findings | GuardDuty | PCI-DSS, SOC2, CIS, NIST |
| [`vpc_collector.py`](collectors/vpc_collector.py) | 6 | VPC, EC2 | PCI-DSS, SOC2, CIS, NIST |
| [`kms_collector.py`](collectors/kms_collector.py) | 3 | KMS | PCI-DSS, SOC2, CIS, NIST |
| [`acm_collector.py`](collectors/acm_collector.py) | Certificate expiry | ACM | PCI-DSS, SOC2, CIS, NIST |
| [`macie_collector.py`](collectors/macie_collector.py) | PII discovery | Macie | PCI-DSS, SOC2, HIPAA |
| [`inspector_collector.py`](collectors/inspector_collector.py) | CVE findings | Inspector | PCI-DSS, SOC2, CIS, NIST |
| [`cloudtrail_collector.py`](collectors/cloudtrail_collector.py) | Event streaming | CloudTrail | PCI-DSS, SOC2, CIS, NIST |

See [`docs/COLLECTORS.md`](docs/COLLECTORS.md) for detailed collector documentation.

### DynamoDB Tables

| Table | Purpose | Partition Key | Sort Key | GSI | TTL |
|-------|---------|---------------|----------|-----|-----|
| **Metadata Table** | Index evidence records | `evidence_id` | - | `timestamp-index` | 90 days |
| **Pending Events Table** | Store MEDIUM/LOW events for batching | `event_id` | - | `priority-timestamp-index` | 30-120 min |
| **Scorecard Table** | Store daily scorecards | `scorecard_date` | `account_id` | - | 1 year |
| **Rate Limit Table** | Track email rate limits | `hour` | - | - | 1 hour |

### S3 Buckets

| Bucket | Purpose | Versioning | Lifecycle Policy |
|--------|---------|------------|------------------|
| **Evidence Bucket** | Store raw evidence JSON | Enabled | Transition to Glacier after 30 days, delete after 90 days |
| **Reports Bucket** | Store PDF/CSV reports | Enabled | Transition to Glacier after 90 days, delete after 1 year |

---

## Security Considerations

### Data Protection

1. **Encryption at Rest**
   - S3 buckets use SSE-S3 or SSE-KMS encryption
   - DynamoDB tables use default encryption
   - KMS keys managed by AWS KMS

2. **Encryption in Transit**
   - All API calls use HTTPS/TLS 1.2+
   - S3 pre-signed URLs use HTTPS
   - Lambda functions communicate over encrypted channels

3. **Access Control**
   - Least privilege IAM roles for Lambda functions
   - S3 bucket policies restrict access
   - DynamoDB IAM policies for table access

### Audit Trail

1. **Evidence Immutability**
   - S3 versioning prevents evidence tampering
   - Evidence records include SHA-256 hashes
   - All changes logged in CloudTrail

2. **Remediation Logging**
   - Every remediation action logged to DynamoDB
   - Before/after state captured
   - Rollback procedures documented

3. **Compliance Evidence**
   - All evidence stored for 90 days minimum
   - Audit trails capture who accessed what and when
   - PDF reports include digital signatures

### Compliance Frameworks

The platform supports the following compliance frameworks:

| Framework | Version | Controls Covered | Auto-Remediation |
|-----------|---------|------------------|------------------|
| **PCI-DSS** | 4.0 | Requirements 1, 2, 3, 6, 7, 8, 10, 11, 12 | Yes |
| **SOC2** | Trust Service Criteria | CC6.1-CC6.8, CC7.1-CC7.3, A1.1-A1.3 | Yes |
| **CIS AWS Benchmark** | v1.5 | Sections 1-5 | Yes |
| **NIST 800-53** | Rev 5 | AC, AU, CM, IA, IR, SC, SI | Yes |
| **HIPAA** | - | 164.312(a)(1), 164.312(e)(1) | Partial |
| **ISO 27001** | 2013 | A.9, A.12, A.14 | Partial |

See [`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md) for complete control mapping.

---

## Summary

The GRC Evidence Platform v2.0 provides a comprehensive, event-driven architecture for automated compliance evidence collection, analysis, and reporting. Key architectural highlights:

- **Event-Driven**: Real-time processing of AWS API calls via CloudTrail and EventBridge
- **Serverless**: Fully serverless architecture using Lambda, DynamoDB, and S3
- **Scalable**: Auto-scaling Lambda functions handle variable workloads
- **Cost-Effective**: Pay-as-you-go pricing with free tier utilization
- **Comprehensive**: 12 collectors covering 50+ compliance controls across 4 frameworks
- **Automated**: Auto-remediation for 20+ common security misconfigurations
- **AI-Enhanced**: Optional AWS Bedrock integration for intelligent risk scoring
- **Auditor-Ready**: Daily scorecards and PDF reports with pre-signed URLs
- **CI/CD Integrated**: Compliance-as-code with gate checks in deployment pipeline

For deployment instructions, see [`docs/QUICKSTART.md`](docs/QUICKSTART.md).
For collector details, see [`docs/COLLECTORS.md`](docs/COLLECTORS.md).
For remediation playbooks, see [`docs/REMEDIATION_PLAYBOOKS.md`](docs/REMEDIATION_PLAYBOOKS.md).
For compliance mapping, see [`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md).
For cost analysis, see [`docs/COST_ANALYSIS.md`](docs/COST_ANALYSIS.md).
