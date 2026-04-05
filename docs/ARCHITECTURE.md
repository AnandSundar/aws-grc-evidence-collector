# System Architecture

## Architecture Diagram

```text
                    ┌─────────────────────────────────────────────────────┐
                    │              AWS GRC Evidence Collector              │
                    └─────────────────────────────────────────────────────┘

  Any AWS API Call
        │
        ▼
  ┌──────────────┐     ┌────────────────┐     ┌──────────────────────────┐
  │  CloudTrail  │────▶│  EventBridge   │────▶│  Lambda (Evidence        │
  │  (API Logs)  │     │  (Event Router)│     │  Processor)              │
  └──────────────┘     └────────────────┘     └──────────────┬───────────┘
                                                              │
                              ┌───────────────────────────────┤
                              │               │               │
                              ▼               ▼               ▼
                       ┌──────────┐   ┌──────────┐   ┌──────────────┐
                       │    S3    │   │ DynamoDB │   │     SNS      │
                       │(Evidence │   │(Metadata │   │  (Alerts for │
                       │ Storage) │   │  Index)  │   │  HIGH events)│
                       └──────────┘   └──────────┘   └──────────────┘
                                                              │
                                                    [Version 2 Only]
                                                              │
                                                              ▼
                                                    ┌──────────────────┐
                                                    │   AWS Bedrock    │
                                                    │ (Claude 3 Sonnet)│
                                                    │  AI Risk Scoring │
                                                    └──────────────────┘
```

## Data Flow Description

1. **API Call Execution:** A user or service makes an API call within the AWS account (e.g., `CreateUser`, `RunInstances`).
2. **CloudTrail Logging:** AWS CloudTrail captures the API call details as an event.
3. **Event Routing:** Amazon EventBridge intercepts the CloudTrail event based on a configured rule and routes it to the Evidence Processor Lambda function.
4. **Processing & Classification:** The Lambda function extracts relevant data (event name, user identity, IP address) and classifies the event priority (HIGH, MEDIUM, LOW) based on predefined rules.
5. **AI Analysis (Optional):** If enabled (Version 2) and the event is HIGH or MEDIUM priority, the Lambda function invokes AWS Bedrock (Claude 3 Sonnet) to perform a contextual risk assessment.
6. **Evidence Storage:** The complete event data, including compliance tags and AI analysis results, is saved as a JSON file in an encrypted, versioned S3 bucket. The path is date-partitioned (e.g., `evidence/YYYY/MM/DD/uuid.json`).
7. **Metadata Indexing:** Key metadata (evidence ID, timestamp, event type, priority, S3 key) is stored in a DynamoDB table for fast querying. A TTL is set to automatically expire records after 90 days.
8. **Alerting:** For HIGH priority events, an alert containing the event summary and AI recommendations is published to an SNS topic, notifying subscribed users (e.g., via email).

## Evidence Record Schema

```json
{
  "evidence_id": "123e4567-e89b-12d3-a456-426614174000",
  "collected_at": "2026-04-04T12:00:00.000000",
  "event_id": "abc123xyz",
  "event_name": "CreateUser",
  "event_source": "iam.amazonaws.com",
  "event_time": "2026-04-04T11:59:59Z",
  "user_identity": {
    "type": "IAMUser",
    "userName": "admin-user"
  },
  "source_ip": "192.168.1.100",
  "aws_region": "us-east-1",
  "request_parameters": {
    "userName": "new-employee"
  },
  "response_elements": {
    "user": {
      "userId": "AIDACKCEVSQ6C2EXAMPLE"
    }
  },
  "priority": "HIGH",
  "compliance_tags": [
    "PCI-DSS-8.3",
    "SOC2-CC6.1",
    "NIST-AC-2",
    "ISO27001-A.9"
  ],
  "raw_event": { ... },
  "ai_analysis": {
    "risk_level": "CRITICAL",
    "risk_score": 8,
    "summary": "An IAM user 'new-employee' was created by 'admin-user'.",
    "compliance_impact": ["SOC2: CC6.1 Logical Access Security"],
    "anomaly_indicators": [],
    "recommended_action": "Verify if the user creation was part of an approved onboarding ticket.",
    "false_positive_likelihood": "LOW",
    "investigation_priority": "IMMEDIATE",
    "ai_analyzed": true,
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "analyzed_at": "2026-04-04T12:00:02.000000"
  }
}
```

## Compliance Framework Mappings

| Event Category | Example Events | Compliance Tags |
|---|---|---|
| **Identity & Access (IAM)** | CreateUser, AttachRolePolicy | PCI-DSS-8.3, SOC2-CC6.1, NIST-AC-2, ISO27001-A.9 |
| **Data Protection (S3)** | PutBucketPolicy, DeleteBucketEncryption | PCI-DSS-3.4, SOC2-CC6.7 |
| **Network Security (VPC/EC2)** | AuthorizeSecurityGroupIngress | PCI-DSS-1.3, SOC2-CC6.6 |
| **Compute & Infrastructure** | RunInstances, CreateSnapshot | PCI-DSS-6.4, SOC2-CC7.1, NIST-CM-3 |
| **Read/Audit Activity** | DescribeInstances, ListBuckets | SOC2-CC6.8 |

## Cost Breakdown (Estimated Monthly)

| Service | Usage | Estimated Cost |
|---|---|---|
| **AWS Lambda** | < 10,000 invocations | $0.00 (Free Tier) |
| **Amazon S3** | < 1 GB storage, < 10,000 PUTs | $0.00 (Free Tier) |
| **Amazon DynamoDB** | < 10,000 WCU/RCU | $0.00 (Free Tier) |
| **Amazon SNS** | < 1,000 emails | $0.00 (Free Tier) |
| **Amazon EventBridge** | < 10,000 events | $0.00 (Free Tier) |
| **AWS CloudTrail** | 1 trail (management events) | $0.00 (First trail free) |
| **AWS Bedrock (Claude 3 Sonnet)** | ~100 HIGH/MEDIUM events | ~$0.78 |
| **Total (Version 1)** | | **$0.00** |
| **Total (Version 2)** | | **~$0.78** |
