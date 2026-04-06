# GRC Evidence Platform v2.0 - Remediation Playbooks

This document provides comprehensive documentation for all auto-remediation capabilities in the GRC Evidence Platform.

## Table of Contents

1. [Overview](#overview)
2. [S3 Remediations](#s3-remediations)
3. [IAM Remediations](#iam-remediations)
4. [RDS Remediations](#rds-remediations)
5. [Security Group Remediations](#security-group-remediations)
6. [Remediation Safety Modes](#remediation-safety-modes)
7. [Executing Remediations](#executing-remediations)
8. [Remediation Registry](#remediation-registry)
9. [Best Practices](#best-practices)

---

## Overview

The GRC Evidence Platform includes automated remediation capabilities for common AWS security and compliance violations. Remediations are triggered by:

1. **AWS Config Rule Violations**: Config rules evaluate resource configuration and trigger remediation when non-compliant
2. **EventBridge Pattern Matches**: Real-time event patterns trigger immediate remediation for security-critical events

### Remediation Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Config Rule   │─────▶│   EventBridge   │─────▶│   SNS Topic     │
│   Violation     │      │   Pattern Match │      │   GRC-Alerts    │
└─────────────────┘      └─────────────────┘      └────────┬────────┘
                                                         │
                                                         ▼
                                              ┌─────────────────┐
                                              │   Lambda:       │
                                              │   Remediation   │
                                              │   Engine       │
                                              └────────┬────────┘
                                                       │
                              ┌────────────────────────┼────────────────────────┐
                              │                        │                        │
                              ▼                        ▼                        ▼
                       ┌──────────┐            ┌──────────┐            ┌──────────┐
                       │   S3     │            │   IAM    │            │   RDS    │
                       │Remediat  │            │Remediat  │            │Remediat  │
                       │  ions    │            │  ions    │            │  ions    │
                       └──────────┘            └──────────┘            └──────────┘
```

### Remediation Log Schema

All remediations produce a standardized log entry:

```python
{
    "action_taken": "remediation_function_name",
    "before_state": {...},           # State before remediation
    "after_state": {...},            # State after remediation
    "success": True/False,           # Remediation success status
    "error": None or "error_message", # Error message if failed
    "timestamp": "2026-04-05T05:24:24.390Z",
    "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6"],
    "resource_id": "resource-identifier",
    "resource_type": "aws_resource_type",
    "trigger": "config_rule_name or event_pattern",
    "safety_mode": "AUTO/APPROVAL_REQUIRED/DRY_RUN"
}
```

---

## S3 Remediations

**File**: [`remediations/s3_remediations.py`](remediations/s3_remediations.py)

### 1. Block S3 Public Access

**Function**: [`block_s3_public_access()`](remediations/s3_remediations.py:32)

**Trigger**: Config Rule `s3-bucket-public-read-prohibited` or `s3-bucket-public-write-prohibited`

**Action Taken**: Enables all four public access block flags on the S3 bucket:
- `BlockPublicAcls`: Blocks new public ACLs
- `IgnorePublicAcls`: Ignores existing public ACLs
- `BlockPublicPolicy`: Blocks new public bucket policies
- `RestrictPublicBuckets`: Restricts public and cross-account access to public buckets

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-1.3, SOC2-CC6.6, CIS-2.1.5

**Before State**:
```json
{
  "BlockPublicAcls": false,
  "IgnorePublicAcls": false,
  "BlockPublicPolicy": false,
  "RestrictPublicBuckets": false
}
```

**After State**:
```json
{
  "BlockPublicAcls": true,
  "IgnorePublicAcls": true,
  "BlockPublicPolicy": true,
  "RestrictPublicBuckets": true
}
```

**Rollback Procedure**:
```bash
# Revert public access block (not recommended)
aws s3api delete-public-access-block --bucket my-bucket
```

**Example Execution**:
```python
from remediations import s3_remediations

result = s3_remediations.block_s3_public_access(
    bucket_name="my-sensitive-bucket",
    region="us-east-1"
)

print(result)
# {
#     "action_taken": "block_s3_public_access",
#     "before_state": {"BlockPublicAcls": false, ...},
#     "after_state": {"BlockPublicAcls": true, ...},
#     "success": true,
#     "timestamp": "2026-04-05T05:24:24.390Z",
#     "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6", "CIS-2.1.5"],
#     "resource_id": "my-sensitive-bucket"
# }
```

---

### 2. Enable S3 Encryption

**Function**: [`enable_s3_encryption()`](remediations/s3_remediations.py:150)

**Trigger**: Config Rule `s3-bucket-server-side-encryption-enabled`

**Action Taken**: Enables default server-side encryption on the S3 bucket using AES-256 (SSE-S3) or AWS KMS (SSE-KMS).

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-3.4, SOC2-CC6.7

**Before State**:
```json
{
  "Rules": []
}
```

**After State**:
```json
{
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }
  ]
}
```

**Rollback Procedure**:
```bash
# Remove default encryption (not recommended)
aws s3api delete-bucket-encryption --bucket my-bucket
```

---

### 3. Enable S3 Versioning

**Function**: [`enable_s3_versioning()`](remediations/s3_remediations.py:220)

**Trigger**: Config Rule `s3-bucket-versioning-enabled`

**Action Taken**: Enables versioning on the S3 bucket to protect against accidental deletion or overwrites.

**Safety Mode**: AUTO

**Compliance Frameworks**: SOC2-A1.3, PCI-DSS-12.3.4

**Before State**:
```json
{
  "Status": "Suspended"
}
```

**After State**:
```json
{
  "Status": "Enabled",
  "MFADelete": "Disabled"
}
```

**Rollback Procedure**:
```bash
# Suspend versioning (not recommended)
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Suspended
```

---

### 4. Enable S3 Logging

**Function**: [`enable_s3_logging()`](remediations/s3_remediations.py:290)

**Trigger**: Config Rule `s3-bucket-logging-enabled`

**Action Taken**: Enables server access logging for the S3 bucket, logging all requests to a target bucket.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-10.2, SOC2-CC6.8

**Before State**:
```json
{
  "TargetBucket": "",
  "TargetPrefix": ""
}
```

**After State**:
```json
{
  "TargetBucket": "my-logging-bucket",
  "TargetPrefix": "my-bucket-logs/"
}
```

**Rollback Procedure**:
```bash
# Disable logging
aws s3api put-bucket-logging \
  --bucket my-bucket \
  --bucket-logging-status {}
```

---

### 5. Remove S3 Public ACL

**Function**: [`remove_s3_public_acl()`](remediations/s3_remediations.py:360)

**Trigger**: EventBridge pattern `PutBucketAcl`

**Action Taken**: Removes public ACLs from the S3 bucket and replaces with private ACL.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-1.3, SOC2-CC6.6

**Before State**:
```json
{
  "Grants": [
    {
      "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
      "Permission": "READ"
    }
  ]
}
```

**After State**:
```json
{
  "Grants": [
    {
      "Grantee": {"Type": "CanonicalUser", "DisplayName": "bucket-owner"},
      "Permission": "FULL_CONTROL"
    }
  ]
}
```

**Rollback Procedure**:
```bash
# Revert ACL (not recommended)
aws s3api put-bucket-acl \
  --bucket my-bucket \
  --access-control-policy file://public-acl.json
```

---

### 6. Delete S3 Public Policy

**Function**: [`delete_s3_public_policy()`](remediations/s3_remediations.py:430)

**Trigger**: EventBridge pattern `PutBucketPolicy`

**Action Taken**: Deletes the bucket policy if it contains public access statements.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-1.3, SOC2-CC6.6

**Before State**:
```json
{
  "Policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\n    \"Effect\": \"Allow\",\n    \"Principal\": \"*\",\n    \"Action\": \"s3:GetObject\",\n    \"Resource\": \"arn:aws:s3:::my-bucket/*\"\n  }]\n}"
}
```

**After State**:
```json
{
  "Policy": ""
}
```

**Rollback Procedure**:
```bash
# Restore policy (not recommended)
aws s3api put-bucket-policy \
  --bucket my-bucket \
  --policy file://public-policy.json
```

---

## IAM Remediations

**File**: [`remediations/iam_remediations.py`](remediations/iam_remediations.py)

### 1. Disable IAM Access Key

**Function**: [`disable_iam_access_key()`](remediations/iam_remediations.py:33)

**Trigger**: Config Rule `iam-access-keys-rotated` or EventBridge pattern `CreateAccessKey`

**Action Taken**: Disables the IAM access key without deleting it, allowing for recovery if needed.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-8.2.4, CIS-1.14, SOC2-CC6.1

**Before State**:
```json
{
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "Status": "Active",
  "CreateDate": "2026-01-15T10:30:00Z"
}
```

**After State**:
```json
{
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "Status": "Inactive",
  "CreateDate": "2026-01-15T10:30:00Z"
}
```

**Rollback Procedure**:
```bash
# Re-enable access key (use with caution)
aws iam update-access-key \
  --user-name john.doe \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Active
```

---

### 2. Enforce MFA for User

**Function**: [`enforce_mfa_for_user()`](remediations/iam_remediations.py:180)

**Trigger**: Config Rule `iam-user-mfa-enabled`

**Action Taken**: Adds an IAM policy that denies all actions unless MFA is present in the request context.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-8.4.2, CIS-1.10, SOC2-CC6.1

**Before State**:
```json
{
  "UserName": "john.doe",
  "MFADevices": []
}
```

**After State**:
```json
{
  "UserName": "john.doe",
  "MFADevices": [],
  "AttachedPolicies": [
    {
      "PolicyName": "EnforceMFA"
    }
  ]
}
```

**Policy Applied**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllWithoutMFA",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

**Rollback Procedure**:
```bash
# Remove MFA enforcement policy (not recommended)
aws iam detach-user-policy \
  --user-name john.doe \
  --policy-arn arn:aws:iam::aws:policy/EnforceMFA
```

---

### 3. Delete IAM User Inline Policy

**Function**: [`delete_iam_user_inline_policy()`](remediations/iam_remediations.py:280)

**Trigger**: Config Rule `iam-user-inline-policies`

**Action Taken**: Deletes inline policies from IAM users, promoting use of managed policies instead.

**Safety Mode**: AUTO

**Compliance Frameworks**: CIS-1.16, SOC2-CC6.3, NIST-AC-6

**Before State**:
```json
{
  "UserName": "john.doe",
  "UserPolicyList": [
    {
      "PolicyName": "MyInlinePolicy"
    }
  ]
}
```

**After State**:
```json
{
  "UserName": "john.doe",
  "UserPolicyList": []
}
```

**Rollback Procedure**:
```bash
# Restore inline policy (not recommended)
aws iam put-user-policy \
  --user-name john.doe \
  --policy-name MyInlinePolicy \
  --policy-document file://inline-policy.json
```

---

### 4. Detach IAM User Policy

**Function**: [`detach_iam_user_policy()`](remediations/iam_remediations.py:350)

**Trigger**: Config Rule `iam-user-no-policies-check`

**Action Taken**: Detaches managed policies from IAM users that should not have direct policy attachments.

**Safety Mode**: AUTO

**Compliance Frameworks**: CIS-1.16, SOC2-CC6.3

**Before State**:
```json
{
  "UserName": "john.doe",
  "AttachedPolicies": [
    {
      "PolicyName": "AdministratorAccess",
      "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
  ]
}
```

**After State**:
```json
{
  "UserName": "john.doe",
  "AttachedPolicies": []
}
```

**Rollback Procedure**:
```bash
# Re-attach policy (use with caution)
aws iam attach-user-policy \
  --user-name john.doe \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

---

### 5. Rotate IAM Access Key

**Function**: [`rotate_iam_access_key()`](remediations/iam_remediations.py:420)

**Trigger**: Config Rule `iam-access-keys-rotated`

**Action Taken**: Creates a new access key and disables the old one (does not delete it).

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-8.2.4, CIS-1.14, SOC2-CC6.1

**Before State**:
```json
{
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "Status": "Active",
  "CreateDate": "2026-01-15T10:30:00Z"
}
```

**After State**:
```json
{
  "OldKey": {
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "Status": "Inactive"
  },
  "NewKey": {
    "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
    "Status": "Active",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}
```

**Rollback Procedure**:
```bash
# Re-enable old key and disable new key (use with caution)
aws iam update-access-key \
  --user-name john.doe \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Active
aws iam update-access-key \
  --user-name john.doe \
  --access-key-id AKIAI44QH8DHBEXAMPLE \
  --status Inactive
```

---

### 6. Delete IAM Access Key

**Function**: [`delete_iam_access_key()`](remediations/iam_remediations.py:500)

**Trigger**: Config Rule `iam-user-unused-credentials-check`

**Action Taken**: Deletes IAM access keys that have been unused for 90+ days.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-8.2.6, CIS-1.15

**Before State**:
```json
{
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "Status": "Active",
  "CreateDate": "2026-01-15T10:30:00Z",
  "LastUsedDate": "2025-12-15T10:30:00Z"
}
```

**After State**:
```json
{
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "Status": "Deleted"
}
```

**Rollback Procedure**:
```bash
# Cannot restore deleted access keys
# Must create new access key instead
aws iam create-access-key --user-name john.doe
```

---

## RDS Remediations

**File**: [`remediations/rds_remediations.py`](remediations/rds_remediations.py)

### 1. Enable RDS Encryption

**Function**: [`enable_rds_encryption()`](remediations/rds_remediations.py:32)

**Trigger**: Config Rule `rds-storage-encrypted`

**Action Taken**: Schedules a snapshot and restore operation to enable encryption for an RDS instance. **Note: This requires approval as it replaces the instance.**

**Safety Mode**: APPROVAL_REQUIRED

**Compliance Frameworks**: PCI-DSS-3.4.1, SOC2-CC6.7, HIPAA-164.312

**Before State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "StorageEncrypted": false,
  "KmsKeyId": null,
  "Engine": "mysql",
  "DBInstanceClass": "db.t3.medium"
}
```

**After State**:
```json
{
  "DBInstanceIdentifier": "production-db-encrypted",
  "StorageEncrypted": true,
  "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
  "Engine": "mysql",
  "DBInstanceClass": "db.t3.medium",
  "SnapshotId": "production-db-snapshot-20260405"
}
```

**Rollback Procedure**:
```bash
# Restore from original snapshot (before encryption)
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier production-db-restored \
  --db-snapshot-identifier production-db-snapshot-20260405

# Update application connection strings to point to restored instance
```

**Important Notes**:
- This remediation requires a snapshot and restore operation
- The instance will be replaced with a new encrypted instance
- Application connection strings must be updated
- This action requires approval before execution
- Plan for downtime during the restore operation

---

### 2. Disable RDS Public Access

**Function**: [`disable_rds_public_access()`](remediations/rds_remediations.py:180)

**Trigger**: Config Rule `rds-instance-public-access-check` or EventBridge pattern `ModifyDBInstance`

**Action Taken**: Disables public accessibility for the RDS instance.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-1.3.2, SOC2-CC6.6, CIS-2.3.2

**Before State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "PubliclyAccessible": true,
  "Endpoint": {
    "Address": "production-db.abc123.us-east-1.rds.amazonaws.com",
    "Port": 3306
  }
}
```

**After State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "PubliclyAccessible": false,
  "Endpoint": {
    "Address": "production-db.abc123.us-east-1.rds.amazonaws.com",
    "Port": 3306
  }
}
```

**Rollback Procedure**:
```bash
# Re-enable public access (not recommended)
aws rds modify-db-instance \
  --db-instance-identifier production-db \
  --publicly-accessible \
  --apply-immediately
```

---

### 3. Enable RDS Multi-AZ

**Function**: [`enable_rds_multi_az()`](remediations/rds_remediations.py:250)

**Trigger**: Config Rule `rds-multi-az-support`

**Action Taken**: Enables Multi-AZ deployment for high availability.

**Safety Mode**: AUTO

**Compliance Frameworks**: SOC2-A1.2

**Before State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "MultiAZ": false,
  "AvailabilityZone": "us-east-1a"
}
```

**After State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "MultiAZ": true,
  "AvailabilityZone": "us-east-1a",
  "SecondaryAvailabilityZone": "us-east-1b"
}
```

**Rollback Procedure**:
```bash
# Disable Multi-AZ (not recommended for production)
aws rds modify-db-instance \
  --db-instance-identifier production-db \
  --no-multi-az \
  --apply-immediately
```

---

### 4. Enable RDS Deletion Protection

**Function**: [`enable_rds_deletion_protection()`](remediations/rds_remediations.py:320)

**Trigger**: Config Rule `rds-instance-deletion-protection-enabled`

**Action Taken**: Enables deletion protection to prevent accidental deletion of the RDS instance.

**Safety Mode**: AUTO

**Compliance Frameworks**: SOC2-CC7.3

**Before State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "DeletionProtection": false
}
```

**After State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "DeletionProtection": true
}
```

**Rollback Procedure**:
```bash
# Disable deletion protection (use with caution)
aws rds modify-db-instance \
  --db-instance-identifier production-db \
  --no-deletion-protection \
  --apply-immediately
```

---

### 5. Update RDS CA Certificate

**Function**: [`update_rds_ca_certificate()`](remediations/rds_remediations.py:390)

**Trigger**: Config Rule `rds-instance-certificate-expiry`

**Action Taken**: Updates the CA certificate to the latest version.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-4.1, SOC2-CC6.6

**Before State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "CACertificateIdentifier": "rds-ca-2019"
}
```

**After State**:
```json
{
  "DBInstanceIdentifier": "production-db",
  "CACertificateIdentifier": "rds-ca-rsa2048-g1"
}
```

**Rollback Procedure**:
```bash
# Revert to previous CA certificate (not recommended)
aws rds modify-db-instance \
  --db-instance-identifier production-db \
  --ca-certificate-identifier rds-ca-2019 \
  --apply-immediately
```

---

### 6. Revoke RDS Snapshot Public Access

**Function**: [`revoke_rds_snapshot_public_access()`](remediations/rds_remediations.py:460)

**Trigger**: Config Rule `rds-snapshot-public-prohibited`

**Action Taken**: Removes public access from RDS snapshots.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-3.3, SOC2-CC6.6

**Before State**:
```json
{
  "DBSnapshotIdentifier": "production-db-snapshot",
  "SnapshotType": "manual",
  "AttributeValues": [
    {
      "AttributeName": "restore",
      "AttributeValues": ["all"]
    }
  ]
}
```

**After State**:
```json
{
  "DBSnapshotIdentifier": "production-db-snapshot",
  "SnapshotType": "manual",
  "AttributeValues": []
}
```

**Rollback Procedure**:
```bash
# Restore public access (not recommended)
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier production-db-snapshot \
  --attribute-name restore \
  --values-to-add all
```

---

## Security Group Remediations

**File**: [`remediations/sg_remediations.py`](remediations/sg_remediations.py)

### 1. Revoke Open SSH Rule

**Function**: [`revoke_open_ssh_rule()`](remediations/sg_remediations.py:32)

**Trigger**: Config Rule `restricted-ssh` or EventBridge pattern `AuthorizeSecurityGroupIngress`

**Action Taken**: Revokes security group rules that allow SSH (port 22) access from 0.0.0.0/0.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-1.3.1, CIS-5.2, SOC2-CC6.6

**Before State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
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
}
```

**After State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "IpPermissions": []
}
```

**Rollback Procedure**:
```bash
# Re-add SSH rule (use with caution)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
```

---

### 2. Revoke Open RDP Rule

**Function**: [`revoke_open_rdp_rule()`](remediations/sg_remediations.py:120)

**Trigger**: Config Rule `restricted-rdp`

**Action Taken**: Revokes security group rules that allow RDP (port 3389) access from 0.0.0.0/0.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-1.3.1, CIS-5.3

**Before State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 3389,
      "ToPort": 3389,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0"
        }
      ]
    }
  ]
}
```

**After State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "IpPermissions": []
}
```

**Rollback Procedure**:
```bash
# Re-add RDP rule (use with caution)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 3389 \
  --cidr 0.0.0.0/0
```

---

### 3. Revoke Open Database Ports

**Function**: [`revoke_open_database_rule()`](remediations/sg_remediations.py:210)

**Trigger**: Config Rule `restricted-common-ports`

**Action Taken**: Revokes security group rules that allow database ports (3306, 5432, 1433, 1521, etc.) access from 0.0.0.0/0.

**Safety Mode**: AUTO

**Compliance Frameworks**: PCI-DSS-1.3.2, SOC2-CC6.6

**Before State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 3306,
      "ToPort": 3306,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0"
        }
      ]
    }
  ]
}
```

**After State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "IpPermissions": []
}
```

**Rollback Procedure**:
```bash
# Re-add database port rule (use with caution)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 3306 \
  --cidr 0.0.0.0/0
```

---

### 4. Revoke All from Default Security Group

**Function**: [`revoke_all_ingress_from_default_sg()`](remediations/sg_remediations.py:300)

**Trigger**: Config Rule `default-security-group-closed`

**Action Taken**: Revokes all ingress rules from the default VPC security group.

**Safety Mode**: AUTO

**Compliance Frameworks**: CIS-5.4, PCI-DSS-1.3.1

**Before State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "GroupName": "default",
  "IpPermissions": [
    {
      "IpProtocol": "-1",
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0"
        }
      ]
    }
  ]
}
```

**After State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "GroupName": "default",
  "IpPermissions": []
}
```

**Rollback Procedure**:
```bash
# Re-add default rules (use with caution)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol -1 \
  --cidr 0.0.0.0/0
```

---

### 5. Add Description to Security Group Rule

**Function**: [`add_sg_rule_description()`](remediations/sg_remediations.py:380)

**Trigger**: Config Rule `sg-rules-have-description`

**Action Taken**: Adds a description to security group rules that are missing one.

**Safety Mode**: AUTO

**Compliance Frameworks**: CIS-5.1

**Before State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 80,
      "ToPort": 80,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0"
        }
      ]
    }
  ]
}
```

**After State**:
```json
{
  "GroupId": "sg-0123456789abcdef0",
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 80,
      "ToPort": 80,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0",
          "Description": "HTTP web traffic"
        }
      ]
    }
  ]
}
```

**Rollback Procedure**:
```bash
# Remove description (not recommended)
# Must revoke and re-add rule without description
aws ec2 revoke-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0
```

---

## Remediation Safety Modes

The platform supports multiple safety modes to control how remediations are executed:

### AUTO

**Description**: Remediation executes immediately without any human intervention or approval.

**Use Cases**:
- Low-risk, non-disruptive actions
- Actions that can be easily reversed
- Well-tested remediations with minimal impact

**Examples**:
- Enable S3 encryption
- Block S3 public access
- Disable IAM access key
- Revoke open security group rules

**Configuration**:
```python
# In remediation_registry.py
"s3-bucket-public-read-prohibited": {
    "function": s3_remediations.block_s3_public_access,
    "safety_mode": "AUTO",
}
```

---

### APPROVAL_REQUIRED

**Description**: Remediation requires manual approval before execution. The system logs the proposed action and waits for approval.

**Use Cases**:
- High-risk actions that could disrupt production
- Actions that require downtime
- Actions that modify critical infrastructure

**Examples**:
- Enable RDS encryption (requires snapshot/restore)
- Delete IAM resources
- Modify security groups for production databases

**Configuration**:
```python
# In remediation_registry.py
"rds-storage-encrypted": {
    "function": rds_remediations.enable_rds_encryption,
    "safety_mode": "APPROVAL_REQUIRED",
}
```

**Approval Process**:
1. Remediation triggered
2. System logs proposed action
3. SNS notification sent to approvers
4. Approver reviews and approves/rejects
5. If approved, remediation executes
6. If rejected, remediation is skipped

---

### DRY_RUN

**Description**: Remediation is logged but not executed. Useful for testing and validation.

**Use Cases**:
- Testing remediation logic
- Validating before/after states
- Auditing what would happen
- Training and demonstration

**Examples**:
- All remediations support dry run mode

**Execution**:
```python
from remediations import remediation_registry

# Execute in dry run mode
result = remediation_registry.execute_remediation(
    trigger="s3-bucket-public-read-prohibited",
    resource_id="my-bucket",
    region="us-east-1",
    dry_run=True  # This is the key parameter
)

# Result will show what would happen without executing
print(result)
# {
#     "action_taken": "DRY_RUN",
#     "success": True,
#     "message": "Would execute remediation for trigger: s3-bucket-public-read-prohibited on resource: my-bucket"
# }
```

---

### MANUAL

**Description**: No automatic remediation. Human intervention is required to resolve the issue.

**Use Cases**:
- Complex issues requiring investigation
- Business-critical changes
- Situations where context matters

**Examples**:
- Complex IAM policy modifications
- Database schema changes
- Application-level security issues

**Configuration**:
```python
# Not in remediation registry
# These are handled manually by security team
```

---

## Executing Remediations

### Using the Remediation Registry

The remediation registry provides a centralized way to execute remediations:

```python
from remediations import remediation_registry

# Execute a remediation
result = remediation_registry.execute_remediation(
    trigger="s3-bucket-public-read-prohibited",
    resource_id="my-bucket",
    region="us-east-1"
)

print(result)
# {
#     "action_taken": "block_s3_public_access",
#     "before_state": {...},
#     "after_state": {...},
#     "success": True,
#     "timestamp": "2026-04-05T05:24:24.390Z",
#     "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6"],
#     "resource_id": "my-bucket"
# }
```

### Using Lambda Function

The remediation engine Lambda function can be invoked via SNS:

```bash
# Publish remediation request to SNS
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:123456789012:grc-remediation \
  --message '{
    "trigger": "s3-bucket-public-read-prohibited",
    "resource_id": "my-bucket",
    "region": "us-east-1",
    "dry_run": false
  }'
```

### Manual Execution

You can also execute remediations manually using Python scripts:

```python
from remediations import s3_remediations

# Execute S3 remediation directly
result = s3_remediations.block_s3_public_access(
    bucket_name="my-bucket",
    region="us-east-1"
)

print(result)
```

---

## Remediation Registry

The remediation registry maps triggers to remediation functions:

```python
REMEDIATION_REGISTRY = {
    # S3 Remediations
    "s3-bucket-public-read-prohibited": {
        "function": s3_remediations.block_s3_public_access,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.2", "SOC2-CC6.6", "CIS-2.1.1"],
        "safety_mode": "AUTO",
    },
    
    # IAM Remediations
    "iam-access-keys-rotated": {
        "function": iam_remediations.disable_iam_access_key,
        "trigger_type": "CONFIG_RULE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-8.2.4", "CIS-1.14", "SOC2-CC6.1"],
        "safety_mode": "AUTO",
    },
    
    # RDS Remediations
    "rds-storage-encrypted": {
        "function": rds_remediations.enable_rds_encryption,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-3.4.1", "SOC2-CC6.7", "HIPAA-164.312"],
        "safety_mode": "APPROVAL_REQUIRED",
    },
    
    # Security Group Remediations
    "restricted-ssh": {
        "function": sg_remediations.revoke_open_ssh_rule,
        "trigger_type": "CONFIG_RULE",
        "priority": "CRITICAL",
        "compliance_frameworks": ["PCI-DSS-1.3.1", "CIS-5.2", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
    
    # EventBridge Pattern Mappings
    "PutBucketAcl": {
        "function": s3_remediations.remove_s3_public_acl,
        "trigger_type": "EVENT_BRIDGE",
        "priority": "HIGH",
        "compliance_frameworks": ["PCI-DSS-1.3", "SOC2-CC6.6"],
        "safety_mode": "AUTO",
    },
    
    # ... 20+ more remediations
}
```

See [`remediations/remediation_registry.py`](remediations/remediation_registry.py:38) for the complete registry.

---

## Best Practices

### 1. Test Remediations in Non-Production

Always test remediations in a non-production environment first:

```python
# Test in dry run mode
result = remediation_registry.execute_remediation(
    trigger="s3-bucket-public-read-prohibited",
    resource_id="test-bucket",
    region="us-east-1",
    dry_run=True
)

# Verify the result before executing in production
if result["success"]:
    print("Dry run successful, ready for production execution")
```

### 2. Monitor Remediation Execution

Set up CloudWatch alarms to monitor remediation execution:

```python
# CloudWatch alarm for failed remediations
aws cloudwatch put-metric-alarm \
  --alarm-name grc-remediation-failures \
  --alarm-description "Alert on failed remediations" \
  --metric-name RemediationFailures \
  --namespace GRC/Remediation \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1
```

### 3. Review Remediation Logs Regularly

Review remediation logs to ensure they're working as expected:

```bash
# Query CloudWatch Logs for remediation logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/grc-remediation-engine \
  --filter-pattern "action_taken" \
  --start-time $(date -d '24 hours ago' +%s)000
```

### 4. Use Approval Required for High-Risk Actions

Always use `APPROVAL_REQUIRED` safety mode for high-risk actions:

```python
"rds-storage-encrypted": {
    "function": rds_remediations.enable_rds_encryption,
    "safety_mode": "APPROVAL_REQUIRED",  # Always require approval
}
```

### 5. Document Rollback Procedures

Always document rollback procedures for each remediation:

```python
def enable_rds_encryption(db_instance_identifier, region="us-east-1"):
    """
    Enable encryption for an RDS instance.
    
    Rollback Procedure:
    1. Identify the original snapshot created before encryption
    2. Restore the instance from the original snapshot
    3. Update application connection strings
    4. Verify the restored instance is working correctly
    """
    # ... implementation
```

### 6. Implement Rate Limiting

Implement rate limiting to prevent remediation storms:

```python
# In remediation_engine/handler.py
MAX_REMEDIATIONS_PER_MINUTE = 10

def check_rate_limit():
    """Check if we've exceeded the remediation rate limit."""
    # Implementation
    pass
```

### 7. Use Dry Run for Testing

Always use dry run mode when testing new remediations:

```python
# Test new remediation in dry run mode
result = remediation_registry.execute_remediation(
    trigger="new-remediation-trigger",
    resource_id="test-resource",
    region="us-east-1",
    dry_run=True
)
```

### 8. Notify Stakeholders

Send notifications when remediations are executed:

```python
# Send SNS notification after remediation
sns.publish(
    TopicArn=ALERT_TOPIC_ARN,
    Subject=f"Remediation Executed: {result['action_taken']}",
    Message=json.dumps(result, indent=2)
)
```

### 9. Track Remediation Metrics

Track metrics to measure remediation effectiveness:

```python
# Track remediation success rate
cloudwatch.put_metric_data(
    Namespace='GRC/Remediation',
    MetricData=[
        {
            'MetricName': 'RemediationSuccessRate',
            'Value': success_rate,
            'Unit': 'Percent'
        }
    ]
)
```

### 10. Regularly Review and Update Remediations

Regularly review and update remediations to ensure they're still relevant:

```python
# Schedule regular review of remediations
# Update safety modes as needed
# Add new remediations for emerging threats
# Remove deprecated remediations
```

---

## Summary

The GRC Evidence Platform provides comprehensive auto-remediation capabilities for common AWS security and compliance violations:

- **20+ Remediations**: Covering S3, IAM, RDS, and Security Groups
- **Multiple Safety Modes**: AUTO, APPROVAL_REQUIRED, DRY_RUN, MANUAL
- **Comprehensive Logging**: Before/after states, timestamps, compliance frameworks
- **Flexible Execution**: Via registry, Lambda, or manual execution
- **Rollback Procedures**: Documented for each remediation
- **Best Practices**: Tested, monitored, and reviewed regularly

For more information, see:
- [`remediations/remediation_registry.py`](remediations/remediation_registry.py) - Complete remediation registry
- [`remediations/s3_remediations.py`](remediations/s3_remediations.py) - S3 remediations
- [`remediations/iam_remediations.py`](remediations/iam_remediations.py) - IAM remediations
- [`remediations/rds_remediations.py`](remediations/rds_remediations.py) - RDS remediations
- [`remediations/sg_remediations.py`](remediations/sg_remediations.py) - Security Group remediations
