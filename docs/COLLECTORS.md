# GRC Evidence Platform v2.0 - Collectors Documentation

This document provides comprehensive documentation for all 12 evidence collectors in the GRC Evidence Platform.

## Table of Contents

1. [Overview](#overview)
2. [IAM Collector](#1-iam-collector)
3. [RDS Collector](#2-rds-collector)
4. [S3 Collector](#3-s3-collector)
5. [Config Collector](#4-config-collector)
6. [Security Hub Collector](#5-security-hub-collector)
7. [GuardDuty Collector](#6-guardduty-collector)
8. [VPC Collector](#7-vpc-collector)
9. [KMS Collector](#8-kms-collector)
10. [ACM Collector](#9-acm-collector)
11. [Macie Collector](#10-macie-collector)
12. [Inspector Collector](#11-inspector-collector)
13. [CloudTrail Collector](#12-cloudtrail-collector)
14. [Collector Summary](#collector-summary)

---

## Overview

The GRC Evidence Platform includes 12 collectors that gather compliance evidence from various AWS services. Each collector implements specific security checks and produces evidence records that are stored in S3 and indexed in DynamoDB.

### Evidence Record Schema

All collectors produce evidence records following the canonical schema defined in [`collectors/base_collector.py`](collectors/base_collector.py):

```python
@dataclass
class EvidenceRecord:
    evidence_id: str                    # Unique UUID
    collected_at: str                  # ISO 8601 timestamp
    collector_name: str                # Collector name
    aws_account_id: str                # AWS account ID
    aws_region: str                    # AWS region
    resource_type: str                 # AWS resource type
    resource_id: str                   # Resource identifier
    resource_arn: str                  # Full ARN
    control_status: str                # PASS/FAIL/WARNING/UNKNOWN
    priority: str                      # CRITICAL/HIGH/MEDIUM/LOW/INFO
    finding_title: str                 # Human-readable title
    finding_description: str           # Detailed description
    compliance_frameworks: List[str]   # Compliance frameworks
    remediation_available: bool        # Whether remediation exists
    remediation_action: str            # Remediation description
    raw_data: Dict[str, Any]          # Raw API response
    ttl: int                          # Time-to-live (90 days)
    ai_analysis: Optional[str]         # AI analysis (optional)
```

### Running Collectors

```bash
# Run all collectors
python scripts/run_all_collectors.py

# Run specific collector
python -m collectors.iam_collector

# Run with verbose output
python -m collectors.s3_collector --verbose
```

---

## 1. IAM Collector

**File**: [`collectors/iam_collector.py`](collectors/iam_collector.py)

**Purpose**: Collects IAM security and compliance evidence, checking for identity and access management best practices.

**AWS Services Used**: IAM

**Checks Implemented** (10 total):

| # | Check | Description | Priority | Compliance Frameworks |
|---|-------|-------------|----------|----------------------|
| 1 | Root Account MFA | Verifies root account has MFA enabled | CRITICAL | PCI-DSS-8.3, SOC2-CC6.1, NIST-AC-2 |
| 2 | User MFA | Checks if IAM users have MFA enabled | HIGH | PCI-DSS-8.4.2, CIS-1.10, SOC2-CC6.1 |
| 3 | API-Only Users | Identifies users without console access | MEDIUM | PCI-DSS-8.2.4, CIS-1.14 |
| 4 | Password Policy | Validates IAM password policy compliance | HIGH | PCI-DSS-8.2.3, CIS-1.12, NIST-IA-5 |
| 5 | Access Key Rotation | Checks access keys older than 90 days | HIGH | PCI-DSS-8.2.4, CIS-1.14, SOC2-CC6.1 |
| 6 | Unused Access Keys | Identifies access keys unused for 90+ days | MEDIUM | PCI-DSS-8.2.6, CIS-1.15 |
| 7 | Unused Passwords | Identifies passwords unused for 90+ days | MEDIUM | PCI-DSS-8.2.6, CIS-1.15 |
| 8 | Unused Roles | Identifies IAM roles with no active usage | LOW | SOC2-CC6.3, NIST-AC-2 |
| 9 | Overly Permissive Policies | Detects policies with wildcard actions | HIGH | PCI-DSS-7.2, CIS-1.16, SOC2-CC6.3 |
| 10 | Empty Groups | Identifies IAM groups with no users | LOW | CIS-1.16, SOC2-CC6.3 |

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group", "AWS::IAM::Policy"
- `resource_id`: User name, role name, group name, or policy name
- `resource_arn`: Full IAM ARN
- `control_status`: Based on check result
- `priority`: CRITICAL/HIGH/MEDIUM/LOW based on risk
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, CIS, NIST controls
- `remediation_available`: True for most checks
- `remediation_action`: Specific remediation steps

**Example Output**:

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
  "finding_description": "User john.doe does not have MFA enabled. This violates PCI-DSS 8.3 and SOC2 CC6.1 requirements.",
  "compliance_frameworks": ["PCI-DSS-8.3", "SOC2-CC6.1", "NIST-AC-2"],
  "remediation_available": true,
  "remediation_action": "Enable MFA for user john.doe via AWS Console or CLI: aws iam enable-mfa-device --user-name john.doe --serial-number arn:aws:iam::123456789012:mfa/john.doe --authentication-code-1 123456 --authentication-code-2 789012",
  "raw_data": {
    "UserName": "john.doe",
    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
    "Arn": "arn:aws:iam::123456789012:user/john.doe",
    "CreateDate": "2026-01-15T10:30:00Z",
    "PasswordLastUsed": "2026-04-04T14:22:00Z"
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`_check_root_mfa()`](collectors/iam_collector.py:90) - Verifies root MFA
- [`_check_user_mfa()`](collectors/iam_collector.py:120) - Checks user MFA status
- [`_check_password_policy()`](collectors/iam_collector.py:180) - Validates password policy
- [`_check_access_key_rotation()`](collectors/iam_collector.py:220) - Checks key rotation
- [`_check_overly_permissive_policies()`](collectors/iam_collector.py:350) - Detects wildcard policies

---

## 2. RDS Collector

**File**: [`collectors/rds_collector.py`](collectors/rds_collector.py)

**Purpose**: Collects RDS database security and compliance evidence, checking for database security best practices.

**AWS Services Used**: RDS

**Checks Implemented** (9 total):

| # | Check | Description | Priority | Compliance Frameworks |
|---|-------|-------------|----------|----------------------|
| 1 | Encryption at Rest | Verifies RDS instances have encryption enabled | CRITICAL | PCI-DSS-3.4.1, SOC2-CC6.7, HIPAA-164.312 |
| 2 | Automated Backups | Checks if automated backups are enabled | HIGH | SOC2-A1.2, PCI-DSS-10.5.1 |
| 3 | Multi-AZ Deployment | Verifies multi-AZ for high availability | HIGH | SOC2-A1.2, PCI-DSS-1.3.2 |
| 4 | Public Accessibility | Ensures instances are not publicly accessible | CRITICAL | PCI-DSS-1.3.2, SOC2-CC6.6, CIS-2.3.2 |
| 5 | Minor Version Upgrade | Checks if automatic minor version upgrade is enabled | MEDIUM | SOC2-CC8.1, PCI-DSS-6.2 |
| 6 | Deletion Protection | Verifies deletion protection is enabled | MEDIUM | SOC2-CC7.3, PCI-DSS-12.3.4 |
| 7 | Enhanced Monitoring | Checks if enhanced monitoring is enabled | LOW | SOC2-CC6.8, PCI-DSS-10.2 |
| 8 | Performance Insights | Verifies Performance Insights is enabled | LOW | SOC2-CC6.8 |
| 9 | Snapshot Encryption | Checks if RDS snapshots are encrypted | HIGH | PCI-DSS-3.3, SOC2-CC6.6 |

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::RDS::DBInstance", "AWS::RDS::DBSnapshot"
- `resource_id`: DB instance identifier or snapshot identifier
- `resource_arn`: Full RDS ARN
- `control_status`: Based on check result
- `priority`: CRITICAL/HIGH/MEDIUM/LOW based on risk
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, CIS, NIST, HIPAA controls
- `remediation_available`: True for most checks
- `remediation_action`: Specific remediation steps

**Example Output**:

```json
{
  "evidence_id": "660e9500-f39c-52e5-b827-557766551111",
  "collected_at": "2026-04-05T05:24:25.390Z",
  "collector_name": "RDSCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::RDS::DBInstance",
  "resource_id": "production-db",
  "resource_arn": "arn:aws:rds:us-east-1:123456789012:db:production-db",
  "control_status": "FAIL",
  "priority": "CRITICAL",
  "finding_title": "RDS Instance Without Encryption",
  "finding_description": "RDS instance production-db does not have encryption at rest enabled. This violates PCI-DSS 3.4.1 and HIPAA 164.312(a)(2)(iv) requirements.",
  "compliance_frameworks": ["PCI-DSS-3.4.1", "SOC2-CC6.7", "HIPAA-164.312"],
  "remediation_available": true,
  "remediation_action": "Enable encryption for RDS instance. Note: This requires creating a snapshot, restoring from snapshot with encryption enabled, and updating application connection strings. See remediation playbook for detailed steps.",
  "raw_data": {
    "DBInstanceIdentifier": "production-db",
    "DBInstanceClass": "db.t3.medium",
    "Engine": "mysql",
    "DBInstanceStatus": "available",
    "StorageEncrypted": false,
    "PubliclyAccessible": false,
    "MultiAZ": true,
    "BackupRetentionPeriod": 7
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`_check_encryption_at_rest()`](collectors/rds_collector.py:85) - Verifies encryption
- [`_check_automated_backups()`](collectors/rds_collector.py:130) - Checks backup configuration
- [`_check_multi_az()`](collectors/rds_collector.py:170) - Verifies multi-AZ deployment
- [`_check_public_accessibility()`](collectors/rds_collector.py:210) - Checks public access
- [`_check_snapshot_encryption()`](collectors/rds_collector.py:370) - Verifies snapshot encryption

---

## 3. S3 Collector

**File**: [`collectors/s3_collector.py`](collectors/s3_collector.py)

**Purpose**: Collects S3 bucket security and compliance evidence, checking for storage security best practices.

**AWS Services Used**: S3

**Checks Implemented** (7 total):

| # | Check | Description | Priority | Compliance Frameworks |
|---|-------|-------------|----------|----------------------|
| 1 | Encryption Enabled | Verifies buckets have SSE-S3 or SSE-KMS encryption | HIGH | PCI-DSS-3.4, SOC2-CC6.7 |
| 2 | Versioning Enabled | Checks if bucket versioning is enabled | MEDIUM | SOC2-A1.3, PCI-DSS-12.3.4 |
| 3 | Public Access Blocked | Ensures public access is blocked | CRITICAL | PCI-DSS-1.3.2, SOC2-CC6.6, CIS-2.1.1 |
| 4 | Logging Enabled | Checks if server access logging is enabled | MEDIUM | PCI-DSS-10.2, SOC2-CC6.8 |
| 5 | Lifecycle Policies | Verifies lifecycle policies are configured | LOW | SOC2-CC6.8, PCI-DSS-12.3.4 |
| 6 | MFA Delete Enabled | Checks if MFA delete is enabled | MEDIUM | SOC2-CC7.3, PCI-DSS-12.3.4 |
| 7 | Default Encryption | Verifies default encryption configuration | HIGH | PCI-DSS-3.4, SOC2-CC6.7 |

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::S3::Bucket"
- `resource_id`: Bucket name
- `resource_arn`: S3 bucket ARN
- `control_status`: Based on check result
- `priority`: CRITICAL/HIGH/MEDIUM/LOW based on risk
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, CIS, NIST controls
- `remediation_available`: True for most checks
- `remediation_action`: Specific remediation steps

**Example Output**:

```json
{
  "evidence_id": "770ea600-g49d-63f6-c938-668877662222",
  "collected_at": "2026-04-05T05:24:26.390Z",
  "collector_name": "S3Collector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::S3::Bucket",
  "resource_id": "my-sensitive-bucket",
  "resource_arn": "arn:aws:s3:::my-sensitive-bucket",
  "control_status": "FAIL",
  "priority": "CRITICAL",
  "finding_title": "S3 Bucket Public Access Not Blocked",
  "finding_description": "S3 bucket my-sensitive-bucket has public access enabled. This violates PCI-DSS 1.3.2 and SOC2 CC6.6 requirements for data protection.",
  "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6", "CIS-2.1.1"],
  "remediation_available": true,
  "remediation_action": "Block public access for bucket: aws s3api put-public-access-block --bucket my-sensitive-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
  "raw_data": {
    "Name": "my-sensitive-bucket",
    "CreationDate": "2026-01-15T10:30:00Z",
    "PublicAccessBlockConfiguration": {
      "BlockPublicAcls": false,
      "IgnorePublicAcls": false,
      "BlockPublicPolicy": false,
      "RestrictPublicBuckets": false
    }
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`_check_encryption()`](collectors/s3_collector.py:105) - Verifies bucket encryption
- [`_check_versioning()`](collectors/s3_collector.py:145) - Checks versioning status
- [`_check_public_access()`](collectors/s3_collector.py:185) - Verifies public access blocked
- [`_check_logging()`](collectors/s3_collector.py:225) - Checks logging configuration
- [`_check_mfa_delete()`](collectors/s3_collector.py:305) - Verifies MFA delete

---

## 4. Config Collector

**File**: [`collectors/config_collector.py`](collectors/config_collector.py)

**Purpose**: Collects AWS Config rule compliance findings, aggregating configuration compliance status across all AWS services.

**AWS Services Used**: AWS Config

**Rules Evaluated** (20 total):

| # | Config Rule | Description | Priority | Compliance Frameworks |
|---|-------------|-------------|----------|----------------------|
| 1 | s3-bucket-server-side-encryption-enabled | S3 buckets have encryption enabled | HIGH | PCI-DSS-3.4, SOC2-CC6.7, CIS-2.1.1 |
| 2 | s3-bucket-public-read-prohibited | S3 buckets prohibit public read | CRITICAL | PCI-DSS-1.3.2, SOC2-CC6.6, CIS-2.1.1 |
| 3 | s3-bucket-public-write-prohibited | S3 buckets prohibit public write | CRITICAL | PCI-DSS-1.3.2, SOC2-CC6.6, CIS-2.1.1 |
| 4 | s3-bucket-ssl-requests-only | S3 buckets enforce SSL/TLS | HIGH | PCI-DSS-4.1, SOC2-CC6.6 |
| 5 | s3-bucket-versioning-enabled | S3 buckets have versioning enabled | MEDIUM | SOC2-A1.3, PCI-DSS-12.3.4 |
| 6 | s3-bucket-logging-enabled | S3 buckets have access logging enabled | MEDIUM | PCI-DSS-10.2, SOC2-CC6.8 |
| 7 | iam-user-no-policies-check | IAM users have no inline policies | MEDIUM | CIS-1.16, SOC2-CC6.3, NIST-AC-6 |
| 8 | iam-group-has-users-check | IAM groups have at least one user | LOW | CIS-1.16, SOC2-CC6.3 |
| 9 | iam-password-policy | IAM password policy meets requirements | HIGH | PCI-DSS-8.2.3, CIS-1.12, NIST-IA-5 |
| 10 | iam-root-access-key-check | Root account has no access keys | CRITICAL | PCI-DSS-8.2.4, CIS-1.1, SOC2-CC6.1 |
| 11 | iam-user-mfa-enabled | IAM users have MFA enabled | HIGH | PCI-DSS-8.4.2, CIS-1.10, SOC2-CC6.1 |
| 12 | iam-access-keys-rotated | IAM access keys rotated within 90 days | HIGH | PCI-DSS-8.2.4, CIS-1.14, SOC2-CC6.1 |
| 13 | rds-storage-encrypted | RDS instances have encryption enabled | CRITICAL | PCI-DSS-3.4.1, SOC2-CC6.7, HIPAA-164.312 |
| 14 | rds-instance-public-access-check | RDS instances not publicly accessible | CRITICAL | PCI-DSS-1.3.2, SOC2-CC6.6, CIS-2.3.2 |
| 15 | rds-automatic-minor-version-upgrade-check | RDS instances have auto minor version upgrade | MEDIUM | SOC2-CC8.1, PCI-DSS-6.2 |
| 16 | rds-snapshot-encrypted | RDS snapshots are encrypted | HIGH | PCI-DSS-3.3, SOC2-CC6.6 |
| 17 | vpc-sg-open-only-to-authorized-ports | Security groups restrict to authorized ports | CRITICAL | PCI-DSS-1.3.1, CIS-5.2, SOC2-CC6.6 |
| 18 | vpc-flow-logs-enabled | VPCs have flow logs enabled | MEDIUM | PCI-DSS-10.2, SOC2-CC6.8, CIS-4.1 |
| 19 | ec2-instance-no-public-ip | EC2 instances have no public IP | HIGH | PCI-DSS-1.3.2, SOC2-CC6.6, CIS-4.3 |
| 20 | ec2-instance-managed-by-systems-manager | EC2 instances managed by SSM | LOW | SOC2-CC6.8, CIS-4.4 |

**Evidence Record Fields Populated**:
- `resource_type`: Varies by Config rule (e.g., "AWS::S3::Bucket", "AWS::IAM::User")
- `resource_id`: Resource identifier from Config evaluation
- `resource_arn`: Resource ARN from Config evaluation
- `control_status`: Based on Config rule evaluation (COMPLIANT/NON_COMPLIANT)
- `priority`: Mapped from Config rule severity
- `compliance_frameworks`: Mapped from Config rule tags
- `remediation_available`: True if remediation exists in registry
- `remediation_action`: Remediation action from registry

**Example Output**:

```json
{
  "evidence_id": "880fb700-h59e-74g7-d149-779988773333",
  "collected_at": "2026-04-05T05:24:27.390Z",
  "collector_name": "ConfigCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::S3::Bucket",
  "resource_id": "my-bucket",
  "resource_arn": "arn:aws:s3:::my-bucket",
  "control_status": "FAIL",
  "priority": "CRITICAL",
  "finding_title": "Config Rule Violation: s3-bucket-public-read-prohibited",
  "finding_description": "AWS Config rule s3-bucket-public-read-prohibited evaluated to NON_COMPLIANT for bucket my-bucket. The bucket allows public read access.",
  "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6", "CIS-2.1.1"],
  "remediation_available": true,
  "remediation_action": "Block public access for bucket: aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
  "raw_data": {
    "configRuleName": "s3-bucket-public-read-prohibited",
    "resourceType": "AWS::S3::Bucket",
    "resourceId": "my-bucket",
    "compliance": {
      "complianceType": "NON_COMPLIANT",
      "resultRecordedTime": "2026-04-05T05:20:00Z",
      "resultRecordedTime": "2026-04-05T05:20:00Z"
    }
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`collect()`](collectors/config_collector.py:45) - Main collection method
- [`_query_config_findings()`](collectors/config_collector.py:85) - Queries Config for findings
- [`_map_config_rule_to_frameworks()`](collectors/config_collector.py:120) - Maps rules to frameworks

---

## 5. Security Hub Collector

**File**: [`collectors/securityhub_collector.py`](collectors/securityhub_collector.py)

**Purpose**: Collects security findings from AWS Security Hub, aggregating security alerts from multiple AWS services and third-party tools.

**AWS Services Used**: Security Hub

**Findings Collected**:

| Finding Type | Description | Severity | Compliance Frameworks |
|--------------|-------------|----------|----------------------|
| IAM Findings | IAM policy violations, access key issues | HIGH/CRITICAL | PCI-DSS, SOC2, CIS, NIST |
| EC2 Findings | Security group issues, public IPs | HIGH/CRITICAL | PCI-DSS, SOC2, CIS, NIST |
| S3 Findings | Bucket misconfigurations | HIGH/CRITICAL | PCI-DSS, SOC2, CIS, NIST |
| Network Findings | VPC misconfigurations, flow logs | MEDIUM/HIGH | PCI-DSS, SOC2, CIS, NIST |
| Encryption Findings | Unencrypted resources | HIGH/CRITICAL | PCI-DSS, SOC2, HIPAA |

**Evidence Record Fields Populated**:
- `resource_type`: From Security Hub finding (e.g., "AwsIamAccessKey", "AwsS3Bucket")
- `resource_id`: Resource identifier from finding
- `resource_arn`: Resource ARN from finding
- `control_status`: FAIL (all findings represent issues)
- `priority`: Mapped from Security Hub severity (CRITICAL/HIGH/MEDIUM/LOW)
- `compliance_frameworks`: Mapped from finding standards
- `remediation_available`: True if remediation exists
- `remediation_action`: Remediation recommendation from finding

**Example Output**:

```json
{
  "evidence_id": "990gc800-i69f-85h8-e250-880099884444",
  "collected_at": "2026-04-05T05:24:28.390Z",
  "collector_name": "SecurityHubCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AwsIamAccessKey",
  "resource_id": "AKIAIOSFODNN7EXAMPLE",
  "resource_arn": "arn:aws:iam::123456789012:access-key/AKIAIOSFODNN7EXAMPLE",
  "control_status": "FAIL",
  "priority": "HIGH",
  "finding_title": "Security Hub Finding: IAM Access Key Exposed",
  "finding_description": "AWS Security Hub detected that IAM access key AKIAIOSFODNN7EXAMPLE has been exposed or is older than 90 days without rotation.",
  "compliance_frameworks": ["PCI-DSS-8.2.4", "SOC2-CC6.1", "CIS-1.14"],
  "remediation_available": true,
  "remediation_action": "Disable the exposed access key and create a new one: aws iam update-access-key --user-name john.doe --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive",
  "raw_data": {
    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789012",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.1",
    "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"],
    "Severity": {"Label": "HIGH"},
    "Title": "IAM.1 Access keys should be rotated",
    "Description": "This control checks whether access keys are rotated every 90 days or less."
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`collect()`](collectors/securityhub_collector.py:30) - Main collection method
- [`_query_security_hub_findings()`](collectors/securityhub_collector.py:60) - Queries Security Hub API
- [`_map_severity_to_priority()`](collectors/securityhub_collector.py:100) - Maps severity to priority

---

## 6. GuardDuty Collector

**File**: [`collectors/guardduty_collector.py`](collectors/guardduty_collector.py)

**Purpose**: Collects threat detection findings from AWS GuardDuty, including malicious activity, compromised credentials, and anomalous behavior.

**AWS Services Used**: GuardDuty

**Findings Collected**:

| Finding Type | Description | Severity | Compliance Frameworks |
|--------------|-------------|----------|----------------------|
| Backdoor:EC2/C&CActivity.B | EC2 instance communicating with C&C server | HIGH | PCI-DSS, SOC2, CIS, NIST |
| CryptoCurrency:EC2/BitcoinTool.B | Bitcoin mining activity detected | HIGH | PCI-DSS, SOC2, CIS, NIST |
| IAMUser/AnomalousBehavior | Anomalous IAM user behavior | MEDIUM/HIGH | PCI-DSS, SOC2, CIS, NIST |
| PenTest:IAMUser/KaliLinux | Kali Linux usage detected | MEDIUM | PCI-DSS, SOC2, CIS, NIST |
| Policy:IAMUser/RootCredentialUsage | Root credentials used | CRITICAL | PCI-DSS, SOC2, CIS, NIST |
| Stealth:IAMUser/UserPermissions | IAM user with excessive permissions | MEDIUM | PCI-DSS, SOC2, CIS, NIST |
| Trojan:EC2/BlackholeTraffic | Blackhole traffic detected | HIGH | PCI-DSS, SOC2, CIS, NIST |
| UnauthorizedAccess:IAMUser/ConsoleLoginSuccess | Unauthorized console login attempt | HIGH | PCI-DSS, SOC2, CIS, NIST |

**Evidence Record Fields Populated**:
- `resource_type`: From GuardDuty finding (e.g., "Instance", "AccessKey", "User")
- `resource_id`: Resource identifier from finding
- `resource_arn`: Resource ARN from finding
- `control_status`: FAIL (all findings represent threats)
- `priority`: Mapped from GuardDuty severity (CRITICAL/HIGH/MEDIUM/LOW)
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, CIS, NIST
- `remediation_available`: True for most findings
- `remediation_action`: Incident response steps

**Example Output**:

```json
{
  "evidence_id": "aa0hd900-j79g-96i9-f361-991100995555",
  "collected_at": "2026-04-05T05:24:29.390Z",
  "collector_name": "GuardDutyCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "Instance",
  "resource_id": "i-0123456789abcdef0",
  "resource_arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
  "control_status": "FAIL",
  "priority": "HIGH",
  "finding_title": "GuardDuty Finding: Backdoor:EC2/C&CActivity.B",
  "finding_description": "AWS GuardDuty detected that EC2 instance i-0123456789abcdef0 is communicating with a known command and control (C&C) server, indicating potential backdoor activity.",
  "compliance_frameworks": ["PCI-DSS-10.2.7", "SOC2-CC6.6", "CIS-4.3", "NIST-IR-4"],
  "remediation_available": true,
  "remediation_action": "1. Isolate the EC2 instance from the network. 2. Terminate the instance if not critical. 3. Analyze instance logs for compromise indicators. 4. Rotate all credentials used on the instance.",
  "raw_data": {
    "Id": "12345678-1234-1234-1234-123456789012",
    "Title": "Backdoor:EC2/C&CActivity.B",
    "Description": "EC2 instance i-0123456789abcdef0 is attempting to communicate with a known command and control server.",
    "Severity": 7.0,
    "Type": "Backdoor:EC2/C&CActivity.B",
    "CreatedAt": "2026-04-05T05:20:00Z",
    "Resource": {
      "Type": "Instance",
      "InstanceId": "i-0123456789abcdef0",
      "InstanceType": "t3.medium",
      "Region": "us-east-1"
    },
    "Service": {
      "Action": {
        "ActionType": "NETWORK_CONNECTION",
        "NetworkConnectionAction": {
          "ConnectionDirection": "OUTBOUND",
          "RemoteIpDetails": {
            "IpAddressV4": "192.0.2.0",
            "Organization": {
              "Asn": -1,
              "AsnOrg": "Known C&C Server"
            }
          }
        }
      }
    }
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`collect()`](collectors/guardduty_collector.py:30) - Main collection method
- [`_query_guardduty_findings()`](collectors/guardduty_collector.py:60) - Queries GuardDuty API
- [`_map_severity_to_priority()`](collectors/guardduty_collector.py:100) - Maps severity to priority

---

## 7. VPC Collector

**File**: [`collectors/vpc_collector.py`](collectors/vpc_collector.py)

**Purpose**: Collects VPC network security evidence, checking for network security best practices and compliance requirements.

**AWS Services Used**: VPC, EC2

**Checks Implemented** (6 total):

| # | Check | Description | Priority | Compliance Frameworks |
|---|-------|-------------|----------|----------------------|
| 1 | VPC Flow Logs | Verifies VPCs have flow logs enabled | MEDIUM | PCI-DSS-10.2, SOC2-CC6.8, CIS-4.1 |
| 2 | Default Security Groups | Checks if default security groups have no rules | HIGH | CIS-5.4, PCI-DSS-1.3.1 |
| 3 | Open SSH Port | Detects SSH port 22 open to 0.0.0.0/0 | CRITICAL | PCI-DSS-1.3.1, CIS-5.2, SOC2-CC6.6 |
| 4 | Open RDP Port | Detects RDP port 3389 open to 0.0.0.0/0 | CRITICAL | PCI-DSS-1.3.1, CIS-5.3, SOC2-CC6.6 |
| 5 | Open Database Ports | Detects database ports open to 0.0.0.0/0 | CRITICAL | PCI-DSS-1.3.2, SOC2-CC6.6, CIS-5.5 |
| 6 | Overly Permissive Rules | Detects security groups with 0.0.0.0/0 rules | HIGH | PCI-DSS-1.3.1, SOC2-CC6.6, CIS-5.1 |

**Database Ports Monitored**:
- 3306: MySQL
- 5432: PostgreSQL
- 1433: MSSQL
- 1521: Oracle
- 5439: Redshift
- 8182: Cassandra
- 27017: MongoDB
- 6379: Redis
- 5672: RabbitMQ
- 9042: Cassandra

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::EC2::SecurityGroup", "AWS::EC2::VPC"
- `resource_id`: Security group ID or VPC ID
- `resource_arn`: Security group ARN or VPC ARN
- `control_status`: Based on check result
- `priority`: CRITICAL/HIGH/MEDIUM/LOW based on risk
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, CIS, NIST controls
- `remediation_available`: True for most checks
- `remediation_action`: Specific remediation steps

**Example Output**:

```json
{
  "evidence_id": "bb1iea00-k89h-07j0-g472-002211006666",
  "collected_at": "2026-04-05T05:24:30.390Z",
  "collector_name": "VPCCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::EC2::SecurityGroup",
  "resource_id": "sg-0123456789abcdef0",
  "resource_arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
  "control_status": "FAIL",
  "priority": "CRITICAL",
  "finding_title": "Security Group with Open SSH Port",
  "finding_description": "Security group sg-0123456789abcdef0 has SSH port 22 open to 0.0.0.0/0, allowing unrestricted remote access. This violates PCI-DSS 1.3.1 and CIS 5.2 requirements.",
  "compliance_frameworks": ["PCI-DSS-1.3.1", "SOC2-CC6.6", "CIS-5.2"],
  "remediation_available": true,
  "remediation_action": "Revoke the open SSH rule: aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 22 --cidr 0.0.0.0/0",
  "raw_data": {
    "GroupId": "sg-0123456789abcdef0",
    "GroupName": "my-security-group",
    "Description": "Security group for web servers",
    "VpcId": "vpc-0123456789abcdef0",
    "IpPermissions": [
      {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [
          {
            "CidrIp": "0.0.0.0/0"
          }
        ]
      }
    ]
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`_check_flow_logs()`](collectors/vpc_collector.py:84) - Verifies VPC flow logs
- [`_check_default_security_groups()`](collectors/vpc_collector.py:140) - Checks default security groups
- [`_check_security_group_rules()`](collectors/vpc_collector.py:190) - Checks security group rules

---

## 8. KMS Collector

**File**: [`collectors/kms_collector.py`](collectors/kms_collector.py)

**Purpose**: Collects KMS key management evidence, checking for encryption key security best practices.

**AWS Services Used**: KMS

**Checks Implemented** (3 total):

| # | Check | Description | Priority | Compliance Frameworks |
|---|-------|-------------|----------|----------------------|
| 1 | Key Rotation | Verifies KMS keys have automatic rotation enabled | MEDIUM | PCI-DSS-3.6.4, SOC2-CC6.7, NIST-AC-17 |
| 2 | Key Policy | Checks if key policies follow least privilege | HIGH | PCI-DSS-7.2, SOC2-CC6.3, NIST-AC-6 |
| 3 | Key Usage | Verifies keys are in use and not orphaned | LOW | SOC2-CC6.8, PCI-DSS-12.3.4 |

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::KMS::Key"
- `resource_id`: KMS key ID
- `resource_arn`: KMS key ARN
- `control_status`: Based on check result
- `priority`: HIGH/MEDIUM/LOW based on risk
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, CIS, NIST controls
- `remediation_available`: True for most checks
- `remediation_action`: Specific remediation steps

**Example Output**:

```json
{
  "evidence_id": "cc2jfb10-l90i-18k1-h583-113322117777",
  "collected_at": "2026-04-05T05:24:31.390Z",
  "collector_name": "KMSCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::KMS::Key",
  "resource_id": "12345678-1234-1234-1234-123456789012",
  "resource_arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
  "control_status": "FAIL",
  "priority": "MEDIUM",
  "finding_title": "KMS Key Without Rotation",
  "finding_description": "KMS key 12345678-1234-1234-1234-123456789012 does not have automatic key rotation enabled. This violates PCI-DSS 3.6.4 requirements for cryptographic key rotation.",
  "compliance_frameworks": ["PCI-DSS-3.6.4", "SOC2-CC6.7", "NIST-AC-17"],
  "remediation_available": true,
  "remediation_action": "Enable automatic key rotation: aws kms enable-key-rotation --key-id 12345678-1234-1234-1234-123456789012",
  "raw_data": {
    "KeyMetadata": {
      "AWSAccountId": "123456789012",
      "KeyId": "12345678-1234-1234-1234-123456789012",
      "Arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
      "CreationDate": "2026-01-15T10:30:00Z",
      "Enabled": true,
      "Description": "Customer managed key for S3 encryption",
      "KeyUsage": "ENCRYPT_DECRYPT",
      "Origin": "AWS_KMS",
      "KeyManager": "CUSTOMER",
      "KeyRotationEnabled": false
    }
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`_check_key_rotation()`](collectors/kms_collector.py:85) - Verifies key rotation
- [`_check_key_policy()`](collectors/kms_collector.py:125) - Checks key policies
- [`_check_key_usage()`](collectors/kms_collector.py:185) - Verifies key usage

---

## 9. ACM Collector

**File**: [`collectors/acm_collector.py`](collectors/acm_collector.py)

**Purpose**: Collects ACM certificate evidence, checking for certificate expiry and best practices.

**AWS Services Used**: ACM

**Checks Implemented** (1 primary check):

| # | Check | Description | Priority | Compliance Frameworks |
|---|-------|-------------|----------|----------------------|
| 1 | Certificate Expiry | Checks if certificates are expiring within 30 days | HIGH | PCI-DSS-4.1, SOC2-CC6.6, CIS-3.10 |

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::ACM::Certificate"
- `resource_id`: Certificate ARN
- `resource_arn`: Certificate ARN
- `control_status`: FAIL if expiring within 30 days, PASS otherwise
- `priority`: HIGH for expiring certificates, INFO otherwise
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, CIS controls
- `remediation_available`: True
- `remediation_action`: Renew certificate

**Example Output**:

```json
{
  "evidence_id": "dd3kgc20-m9j1-29l2-i694-224433228888",
  "collected_at": "2026-04-05T05:24:32.390Z",
  "collector_name": "ACMCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::ACM::Certificate",
  "resource_id": "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
  "resource_arn": "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
  "control_status": "FAIL",
  "priority": "HIGH",
  "finding_title": "ACM Certificate Expiring Soon",
  "finding_description": "ACM certificate 12345678-1234-1234-1234-123456789012 for domain example.com is expiring on 2026-04-20 (15 days from now). This violates PCI-DSS 4.1 requirements for certificate management.",
  "compliance_frameworks": ["PCI-DSS-4.1", "SOC2-CC6.6", "CIS-3.10"],
  "remediation_available": true,
  "remediation_action": "Renew the certificate before expiry: aws acm request-certificate --domain-name example.com --validation-method DNS",
  "raw_data": {
    "Certificate": {
      "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
      "DomainName": "example.com",
      "SubjectAlternativeNames": ["example.com", "www.example.com"],
      "DomainValidationOptions": [
        {
          "DomainName": "example.com",
          "ValidationDomain": "example.com"
        }
      ],
      "Subject": "CN=example.com",
      "Issuer": "Amazon",
      "CreatedAt": "2025-04-20T10:30:00Z",
      "IssuedAt": "2025-04-20T10:30:00Z",
      "Status": "ISSUED",
      "NotBefore": "2025-04-20T00:00:00Z",
      "NotAfter": "2026-04-20T23:59:59Z",
      "KeyAlgorithm": "RSA-2048",
      "SignatureAlgorithm": "SHA256WITHRSA",
      "InUseBy": [],
      "Type": "AMAZON_ISSUED",
      "RenewalEligibility": "ELIGIBLE"
    }
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`_check_certificate_expiry()`](collectors/acm_collector.py:85) - Checks certificate expiry

---

## 10. Macie Collector

**File**: [`collectors/macie_collector.py`](collectors/macie_collector.py)

**Purpose**: Collects Macie PII discovery findings, identifying sensitive data in S3 buckets.

**AWS Services Used**: Macie

**Findings Collected**:

| Finding Type | Description | Severity | Compliance Frameworks |
|--------------|-------------|----------|----------------------|
| S3Object/PII | PII data detected in S3 objects | HIGH/CRITICAL | PCI-DSS, SOC2, HIPAA, GDPR |
| S3Object/FinancialData | Financial data detected in S3 objects | HIGH | PCI-DSS, SOC2, HIPAA |
| S3Object/PersonalData | Personal data detected in S3 objects | MEDIUM/HIGH | GDPR, SOC2, HIPAA |

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::S3::Object"
- `resource_id`: S3 object key
- `resource_arn`: S3 object ARN
- `control_status`: FAIL (all findings represent data exposure)
- `priority`: Mapped from Macie severity (CRITICAL/HIGH/MEDIUM/LOW)
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, HIPAA, GDPR controls
- `remediation_available`: True for most findings
- `remediation_action`: Data protection steps

**Example Output**:

```json
{
  "evidence_id": "ee4lhd30-n0k2-39m3-j705-335544339999",
  "collected_at": "2026-04-05T05:24:33.390Z",
  "collector_name": "MacieCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::S3::Object",
  "resource_id": "sensitive-data/customer-records.csv",
  "resource_arn": "arn:aws:s3:::my-bucket/sensitive-data/customer-records.csv",
  "control_status": "FAIL",
  "priority": "HIGH",
  "finding_title": "Macie Finding: PII Data Detected",
  "finding_description": "AWS Macie detected personally identifiable information (PII) in S3 object sensitive-data/customer-records.csv, including credit card numbers and SSNs.",
  "compliance_frameworks": ["PCI-DSS-3.4", "SOC2-CC6.7", "HIPAA-164.312", "GDPR-Article-32"],
  "remediation_available": true,
  "remediation_action": "1. Encrypt the S3 object. 2. Restrict access to authorized users only. 3. Implement data retention policies. 4. Review data classification and handling procedures.",
  "raw_data": {
    "Id": "12345678-1234-1234-1234-123456789012",
    "Title": "PII data detected in S3 object",
    "Description": "Macie detected PII data including credit card numbers and SSNs in the S3 object.",
    "Severity": {"Label": "HIGH"},
    "Type": "SensitiveData:S3Object/Personal",
    "CreatedAt": "2026-04-05T05:20:00Z",
    "ResourcesAffected": [
      {
        "Type": "S3Object",
        "Details": {
          "BucketArn": "arn:aws:s3:::my-bucket",
          "ObjectArn": "arn:aws:s3:::my-bucket/sensitive-data/customer-records.csv",
          "ObjectKey": "sensitive-data/customer-records.csv",
          "ObjectType": "CSV_FILE"
        }
      }
    ],
    "SensitiveDataOccurrences": [
      {
        "Category": "PERSONAL_IDENTIFIABLE_INFORMATION",
        "Occurrences": [
          {
            "Type": "CREDIT_CARD_NUMBER",
            "Count": 150
          },
          {
            "Type": "US_SOCIAL_SECURITY_NUMBER",
            "Count": 200
          }
        ]
      }
    ]
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`collect()`](collectors/macie_collector.py:30) - Main collection method
- [`_query_macie_findings()`](collectors/macie_collector.py:60) - Queries Macie API
- [`_map_severity_to_priority()`](collectors/macie_collector.py:100) - Maps severity to priority

---

## 11. Inspector Collector

**File**: [`collectors/inspector_collector.py`](collectors/inspector_collector.py)

**Purpose**: Collects Amazon Inspector vulnerability findings, identifying CVEs and security issues in EC2 instances and container images.

**AWS Services Used**: Inspector

**Findings Collected**:

| Finding Type | Description | Severity | Compliance Frameworks |
|--------------|-------------|----------|----------------------|
| CVE | Common Vulnerabilities and Exposures | HIGH/CRITICAL | PCI-DSS, SOC2, CIS, NIST |
| Network Reachability | Unintended network exposure | MEDIUM/HIGH | PCI-DSS, SOC2, CIS, NIST |
| Package Vulnerability | Outdated or vulnerable packages | MEDIUM/HIGH | PCI-DSS, SOC2, CIS, NIST |

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::EC2::Instance", "AWS::ECS::Container"
- `resource_id`: Instance ID or container ARN
- `resource_arn`: Instance ARN or container ARN
- `control_status`: FAIL (all findings represent vulnerabilities)
- `priority`: Mapped from Inspector severity (CRITICAL/HIGH/MEDIUM/LOW)
- `compliance_frameworks`: Mapped to PCI-DSS, SOC2, CIS, NIST controls
- `remediation_available`: True for most findings
- `remediation_action`: Patch or remediation steps

**Example Output**:

```json
{
  "evidence_id": "ff5mie40-o1l3-49n4-k816-446655440000",
  "collected_at": "2026-04-05T05:24:34.390Z",
  "collector_name": "InspectorCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::EC2::Instance",
  "resource_id": "i-0123456789abcdef0",
  "resource_arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
  "control_status": "FAIL",
  "priority": "CRITICAL",
  "finding_title": "Inspector Finding: Critical CVE Detected",
  "finding_description": "Amazon Inspector detected critical CVE-2024-1234 in OpenSSL package on EC2 instance i-0123456789abcdef0. This vulnerability allows remote code execution.",
  "compliance_frameworks": ["PCI-DSS-6.2", "SOC2-CC8.1", "CIS-4.3", "NIST-RA-5"],
  "remediation_available": true,
  "remediation_action": "1. Patch OpenSSL to version 1.1.1k or later. 2. Restart affected services. 3. Verify patch was successful. 4. Monitor for exploitation attempts.",
  "raw_data": {
    "findingArn": "arn:aws:inspector:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789012",
    "title": "CVE-2024-1234 - OpenSSL Remote Code Execution",
    "description": "OpenSSL before 1.1.1k allows remote attackers to execute arbitrary code via a crafted certificate.",
    "severity": "CRITICAL",
    "type": "CVE",
    "firstObservedAt": "2026-04-05T05:20:00Z",
    "lastObservedAt": "2026-04-05T05:24:00Z",
    "inspectorScore": 9.8,
    "inspectorScoreDetails": {
      "adjustedCvss": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "source": "NVD"
      }
    },
    "packageVulnerabilityDetails": {
      "cvss": [
        {
          "baseScore": 9.8,
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
      ],
      "referenceUrls": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
      ],
      "source": "NVD",
      "sourceUrl": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
      "vendorCreatedAt": "2026-04-01T00:00:00Z",
      "vendorSeverity": "CRITICAL",
      "vendorUpdatedAt": "2026-04-01T00:00:00Z",
      "vulnerabilityId": "CVE-2024-1234",
      "vulnerablePackages": [
        {
          "name": "openssl",
          "epoch": 0,
          "release": "1.el8",
          "version": "1.1.1g",
          "arch": "x86_64",
          "filePath": "/usr/lib64/libssl.so.1.1",
          "layerArn": "",
          "layerHash": "",
          "fixAvailable": true,
          "fixedIn": [
            {
              "name": "openssl",
              "epoch": 0,
              "release": "1.el8",
              "version": "1.1.1k",
              "arch": "x86_64"
            }
          ]
        }
      ]
    },
    "resources": [
      {
        "type": "AWS_EC2_INSTANCE",
        "id": "i-0123456789abcdef0",
        "partition": "aws",
        "region": "us-east-1",
        "details": {
          "awsEc2Instance": {
            "type": "t3.medium",
            "imageId": "ami-0123456789abcdef0",
            "ipV4Addresses": ["192.0.2.0"],
            "keyName": "my-key-pair",
            "launchedAt": "2026-01-15T10:30:00Z",
            "platform": "LINUX",
            "tags": [
              {
                "key": "Name",
                "value": "web-server-1"
              }
            ]
          }
        }
      }
    ]
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`collect()`](collectors/inspector_collector.py:30) - Main collection method
- [`_query_inspector_findings()`](collectors/inspector_collector.py:60) - Queries Inspector API
- [`_map_severity_to_priority()`](collectors/inspector_collector.py:100) - Maps severity to priority

---

## 12. CloudTrail Collector

**File**: [`collectors/cloudtrail_collector.py`](collectors/cloudtrail_collector.py)

**Purpose**: Collects CloudTrail event streaming evidence, monitoring API activity for security and compliance.

**AWS Services Used**: CloudTrail

**Events Monitored**:

| Event Type | Description | Priority | Compliance Frameworks |
|------------|-------------|----------|----------------------|
| Management Events | All management API calls | VARIES | PCI-DSS, SOC2, CIS, NIST |
| Data Events | S3 object-level API calls | VARIES | PCI-DSS, SOC2, CIS, NIST |
| Sign-in Events | Console sign-in events | HIGH | PCI-DSS, SOC2, CIS, NIST |

**Evidence Record Fields Populated**:
- `resource_type`: "AWS::CloudTrail::Event"
- `resource_id`: Event ID
- `resource_arn`: N/A (events don't have ARNs)
- `control_status`: Based on event analysis
- `priority`: Determined by event type and user identity
- `compliance_frameworks`: Mapped from event name
- `remediation_available`: True for security-relevant events
- `remediation_action`: Investigation or remediation steps

**Example Output**:

```json
{
  "evidence_id": "006njf50-p2m4-59o5-l927-557766551111",
  "collected_at": "2026-04-05T05:24:35.390Z",
  "collector_name": "CloudTrailCollector",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "resource_type": "AWS::CloudTrail::Event",
  "resource_id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "resource_arn": "",
  "control_status": "FAIL",
  "priority": "HIGH",
  "finding_title": "CloudTrail Event: CreateUser",
  "finding_description": "CloudTrail captured CreateUser event. User john.doe created new IAM user test-user. This event requires review for compliance with access control policies.",
  "compliance_frameworks": ["PCI-DSS-8.3", "SOC2-CC6.1", "NIST-AC-2"],
  "remediation_available": true,
  "remediation_action": "1. Review the new user creation for authorization. 2. Verify the user has appropriate permissions. 3. Ensure MFA is enabled for the user. 4. Document the business justification.",
  "raw_data": {
    "eventVersion": "1.08",
    "userIdentity": {
      "type": "IAMUser",
      "principalId": "AIDACKCEVSQ6C2EXAMPLE",
      "arn": "arn:aws:iam::123456789012:user/john.doe",
      "accountId": "123456789012",
      "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "userName": "john.doe"
    },
    "eventTime": "2026-04-05T05:20:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateUser",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.0.2.0",
    "userAgent": "aws-cli/2.0.0 Python/3.9.0 Linux/5.4.0 botocore/2.0.0",
    "requestParameters": {
      "userName": "test-user"
    },
    "responseElements": {
      "user": {
        "userName": "test-user",
        "userId": "AIDACKCEVSQ6C3EXAMPLE",
        "arn": "arn:aws:iam::123456789012:user/test-user",
        "createDate": "2026-04-05T05:20:00Z"
      }
    },
    "requestID": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "eventID": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "123456789012",
    "eventCategory": "Management"
  },
  "ttl": 2592000
}
```

**Key Functions**:
- [`collect()`](collectors/cloudtrail_collector.py:30) - Main collection method
- [`_query_cloudtrail_events()`](collectors/cloudtrail_collector.py:60) - Queries CloudTrail API
- [`_analyze_event()`](collectors/cloudtrail_collector.py:100) - Analyzes event for compliance

---

## Collector Summary

### Quick Reference Table

| Collector | Checks | AWS Services | Primary Frameworks |
|-----------|--------|--------------|-------------------|
| IAM | 10 | IAM | PCI-DSS, SOC2, CIS, NIST |
| RDS | 9 | RDS | PCI-DSS, SOC2, CIS, NIST, HIPAA |
| S3 | 7 | S3 | PCI-DSS, SOC2, CIS, NIST |
| Config | 20 rules | Config | PCI-DSS, SOC2, CIS, NIST |
| Security Hub | Findings | Security Hub | PCI-DSS, SOC2, CIS, NIST |
| GuardDuty | Findings | GuardDuty | PCI-DSS, SOC2, CIS, NIST |
| VPC | 6 | VPC, EC2 | PCI-DSS, SOC2, CIS, NIST |
| KMS | 3 | KMS | PCI-DSS, SOC2, CIS, NIST |
| ACM | 1 | ACM | PCI-DSS, SOC2, CIS |
| Macie | Findings | Macie | PCI-DSS, SOC2, HIPAA, GDPR |
| Inspector | Findings | Inspector | PCI-DSS, SOC2, CIS, NIST |
| CloudTrail | Events | CloudTrail | PCI-DSS, SOC2, CIS, NIST |

### Total Coverage

- **Total Checks**: 60+ security checks across 12 collectors
- **Total Config Rules**: 20 AWS Config rules evaluated
- **Compliance Frameworks**: PCI-DSS 4.0, SOC2, CIS AWS Benchmark v1.5, NIST 800-53 Rev 5, HIPAA, GDPR
- **AWS Services Covered**: 15+ AWS services monitored
- **Evidence Types**: Configuration, findings, events, vulnerabilities, PII data

### Running All Collectors

```bash
# Run all collectors
python scripts/run_all_collectors.py

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

### Customizing Collectors

To customize or extend collectors:

1. **Add New Check**: Add a new method to the collector class
2. **Modify Existing Check**: Update the check logic in existing methods
3. **Add New Collector**: Create a new collector class extending [`BaseCollector`](collectors/base_collector.py:118)
4. **Update Compliance Mapping**: Modify compliance framework mappings in [`config_collector.py`](collectors/config_collector.py:22)

Example: Adding a new check to IAM Collector

```python
# In collectors/iam_collector.py

def _check_password_expiration(self) -> List[EvidenceRecord]:
    """Check if IAM users have passwords expiring soon."""
    records: List[EvidenceRecord] = []
    
    try:
        iam_client = self.get_client("iam")
        paginator = self.get_paginator("iam", "list_users")
        
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                password_last_used = user.get("PasswordLastUsed")
                
                if password_last_used:
                    days_since_change = (datetime.now(timezone.utc) - password_last_used).days
                    
                    if days_since_change > 90:
                        records.append(self.make_record(
                            resource_type="AWS::IAM::User",
                            resource_id=user_name,
                            resource_arn=user["Arn"],
                            control_status=ControlStatus.FAIL,
                            priority=Priority.MEDIUM,
                            finding_title="IAM User Password Expiring Soon",
                            finding_description=f"User {user_name} password last changed {days_since_change} days ago",
                            compliance_frameworks=["PCI-DSS-8.2.4", "CIS-1.14"],
                            remediation_available=True,
                            remediation_action="Require user to change password at next login",
                            raw_data=user
                        ))
    
    except ClientError as e:
        logger.error(f"Error checking password expiration: {e}")
    
    return records
```

---

For more information on specific collectors, refer to the source code in the [`collectors/`](collectors/) directory.
