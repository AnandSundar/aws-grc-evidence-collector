# [CRITICAL AUDIT] GRC Platform Notification Gap Analysis

**Audit Date**: April 6, 2026
**Auditor**: Claude (GRC Platform Code Review)
**Scope**: Complete review of all remediation functions, EventBridge rules, and SNS notifications

---

## [EXECUTIVE SUMMARY] 🚨 CRITICAL ISSUE FOUND

### Current Status: **NOTIFICATIONS ARE BROKEN** ❌

**Root Cause**: Lambda function has `ALERT_TOPIC_ARN: ""` (empty string)
- SNS topic EXISTS: ✅ `arn:aws:sns:us-east-1:348342704892:grc-evidence-platform-alerts-dev`
- Email subscription EXISTS: ✅ `anandaws0001@gmail.com`
- Lambda variable: ❌ `ALERT_TOPIC_ARN: ""` (EMPTY)

**Impact**: **ZERO notifications will be sent** for ANY remediation, even though everything is set up correctly.

---

## DETAILED FINDINGS

### 1. Remediation Registry (25 Functions Total)

The codebase has **25 remediation functions** defined in the registry:

#### S3 Remediations (6 functions)
1. `block_s3_public_access` - S3 public read/write
2. `enable_s3_encryption` - S3 encryption missing
3. `enable_s3_versioning` - S3 versioning disabled
4. `enable_s3_logging` - S3 access logging disabled
5. `remove_s3_public_acl` - Remove public ACL
6. `delete_s3_public_policy` - Delete public bucket policy

#### IAM Remediations (5 functions)
1. `disable_iam_access_key` - Keys >90 days old
2. `enforce_mfa_for_user` - **MFA not enabled** (NOTIFICATION ONLY)
3. `delete_iam_user_inline_policy` - Inline policy found
4. `detach_iam_user_policy` - User has managed policies
5. `delete_iam_access_key` - Unused credentials

#### RDS Remediations (6 functions)
1. `enable_rds_encryption` - RDS not encrypted
2. `disable_rds_public_access` - RDS publicly accessible
3. `enable_rds_multi_az` - RDS not Multi-AZ
4. `enable_rds_deletion_protection` - Deletion protection disabled
5. `enable_rds_enhanced_monitoring` - Enhanced monitoring disabled (placeholder)
6. `revoke_rds_snapshot_public_access` - Public RDS snapshot

#### Security Group Remediations (4 functions)
1. `revoke_open_ssh_rule` - SSH open to 0.0.0.0/0
2. `revoke_open_rdp_rule` - RDP open to 0.0.0.0/0
3. `revoke_open_database_rule` - Database ports open
4. `revoke_all_ingress_from_default_sg` - Default SG has rules

#### Additional Functions (4 functions)
- EventBridge pattern mappings for real-time triggers
- Various auto-remediation scenarios

---

### 2. EventBridge Rules (8 Rules Total)

**AUTOMATIC REMEDIATION TRIGGERS** ✅ Deployed and Enabled:

| Rule Name | Triggers When | Remediation Function | Status |
|-----------|---------------|---------------------|---------|
| `remediate-s3-public-read` | S3 public read detected | `block_s3_public_access` | ✅ ENABLED |
| `remediate-s3-public-write` | S3 public write detected | `block_s3_public_access` | ✅ ENABLED |
| `remediate-s3-encryption` | S3 encryption missing | `enable_s3_encryption` | ✅ ENABLED |
| `remediate-open-ssh` | SSH open to 0.0.0.0/0 | `revoke_open_ssh_rule` | ✅ ENABLED |
| `remediate-open-rdp` | RDP open to 0.0.0.0/0 | `revoke_open_rdp_rule` | ✅ ENABLED |
| `remediate-rds-public` | RDS publicly accessible | `disable_rds_public_access` | ✅ ENABLED |
| `remediate-iam-keys` | IAM keys >90 days old | `disable_iam_access_key` | ✅ ENABLED |
| `remediate-missing-mfa` | MFA not enabled | `enforce_mfa_for_user` | ✅ ENABLED |

**Coverage**: 8 out of 25 remediation functions have automatic triggers (32%)

---

### 3. SNS Notification Functions (1 Function Only)

**ONLY MFA function sends notifications** ❌:

```python
# File: remediations/iam_remediations.py:203-220
# Send SNS notification to admin team
sns_topic_arn = os.getenv("ALERT_TOPIC_ARN")  # ← This is EMPTY!
if sns_topic_arn:
    sns_client.publish(...)
```

**All other 24 functions**:
- Execute remediation actions (block public access, revoke rules, etc.)
- ❌ Do NOT send any notifications
- ❌ Do NOT alert about what was done
- ❌ Silent execution

---

### 4. Critical Infrastructure Issue

#### Lambda Environment Variables:
```json
{
  "REMEDIATION_MODE": "AUTO",
  "ALERT_TOPIC_ARN": "",           ← ❌ EMPTY!
  "REMEDIATION_LOG_TABLE": "grc-evidence-platform-remediation-logs-dev",
  "EVIDENCE_BUCKET": "grc-evidence-platform-evidence-348342704892-us-east-1"
}
```

#### SNS Topic Status:
- **Topic ARN**: `arn:aws:sns:us-east-1:348342704892:grc-evidence-platform-alerts-dev`
- **Status**: ✅ EXISTS
- **Subscriptions**: ✅ `anandaws0001@gmail.com` subscribed and confirmed

#### The Problem:
CloudFormation template has:
```yaml
ALERT_TOPIC_ARN: !If [HasAlertEmail, !Ref AlertTopic, ""]
```

If no `--alert-email` was provided during initial deployment, it's set to empty string.

---

## GAP ANALYSIS

### What's Working ✅

1. **EventBridge Rules**: All 8 rules deployed and enabled
2. **Remediation Functions**: All 25 functions coded and registered
3. **Lambda Functions**: Remediation engine deployed and working
4. **SNS Topic**: Exists and ready to receive messages
5. **Email Subscription**: `anandaws0001@gmail.com` is subscribed

### What's Broken ❌

1. **Lambda Environment Variable**: `ALERT_TOPIC_ARN` is empty string
2. **MFA Notifications**: Function exists but can't send notifications (no ARN)
3. **All Other Notifications**: 24/25 functions don't even have notification code

---

## COMPLETE REMEDIATION COVERAGE

### Remediations with Automatic Triggers (8):
1. ✅ S3 Public Read → Auto-blocks, ❌ No notification
2. ✅ S3 Public Write → Auto-blocks, ❌ No notification
3. ✅ S3 Encryption → Auto-enables, ❌ No notification
4. ✅ SSH Open → Auto-revokes, ❌ No notification
5. ✅ RDP Open → Auto-revokes, ❌ No notification
6. ✅ RDS Public → Auto-disables, ❌ No notification
7. ✅ IAM Keys >90 days → Auto-disables, ❌ No notification
8. ✅ MFA Missing → Should notify, ❌ Broken (no ARN)

### Remediations WITHOUT Automatic Triggers (17):
9. ❌ S3 Versioning - No trigger, no notification
10. ❌ S3 Logging - No trigger, no notification
11. ❌ S3 Public ACL - No trigger, no notification
12. ❌ S3 Public Policy - No trigger, no notification
13. ❌ IAM Inline Policies - No trigger, no notification
14. ❌ IAM Managed Policies - No trigger, no notification
15. ❌ IAM Unused Credentials - No trigger, no notification
16. ❌ RDS Encryption - No trigger, no notification
17. ❌ RDS Multi-AZ - No trigger, no notification
18. ❌ RDS Deletion Protection - No trigger, no notification
19. ❌ RDS Enhanced Monitoring - No trigger, no notification
20. ❌ RDS Snapshot Public - No trigger, no notification
21. ❌ Default SG Rules - No trigger, no notification
22. ❌ Database Ports Open - No trigger, no notification
23. ❌ EventBridge: PutBucketAcl - No trigger, no notification
24. ❌ EventBridge: PutBucketPolicy - No trigger, no notification
25. ❌ EventBridge: AuthorizeSecurityGroupIngress - No trigger, no notification

---

## RECOMMENDED FIXES

### [CRITICAL] Fix #1: Set ALERT_TOPIC_ARN in Lambda

**Option A: Update Lambda Environment Variable**
```bash
aws lambda update-function-configuration \
  --function-name grc-evidence-platform-remediation-engine-dev \
  --environment Variables={
    REMEDIATION_MODE=AUTO,
    ALERT_TOPIC_ARN=arn:aws:sns:us-east-1:348342704892:grc-evidence-platform-alerts-dev,
    REMEDIATION_LOG_TABLE=grc-evidence-platform-remediation-logs-dev,
    EVIDENCE_BUCKET=grc-evidence-platform-evidence-348342704892-us-east-1
  }
```

**Option B: Re-deploy with Alert Email Parameter**
```bash
make deploy
# Select: Update existing stack
# Provide email: anandaws0001@gmail.com
```

### [IMPORTANT] Fix #2: Add Notifications to All Remediations

Add SNS notification calls to all 24 other remediation functions:

```python
# Add to each remediation function
if os.getenv("ALERT_TOPIC_ARN"):
    sns_client.publish(
        TopicArn=os.getenv("ALERT_TOPIC_ARN"),
        Subject=f"GRC Alert: {action_taken} on {resource_id}",
        Message=f"Remediation executed: {description}"
    )
```

### [ENHANCEMENT] Fix #3: Add EventBridge Rules for Remaining 17 Remediations

Create EventBridge rules for the 17 remediations that currently have no automatic trigger.

---

## TEST SCENARIOS

### Current Behavior (Broken):
1. User "test" has no MFA
2. AWS Config detects non-compliance
3. EventBridge triggers remediation
4. Lambda executes `enforce_mfa_for_user()`
5. Function tries to send SNS notification
6. ❌ **Fails silently** because `ALERT_TOPIC_ARN` is empty
7. ❌ No email sent to `anandaws0001@gmail.com`

### Expected Behavior (After Fix):
1. User "test" has no MFA
2. AWS Config detects non-compliance
3. EventBridge triggers remediation
4. Lambda executes `enforce_mfa_for_user()`
5. ✅ Sends SNS notification to `anandaws0001@gmail.com`
6. ✅ Email received within 1-2 minutes

---

## COMPLIANCE IMPACT

### Current Compliance Posture:
- **Detection**: ✅ Working (AWS Config detects violations)
- **Remediation**: ✅ Partial (8/25 functions have auto-triggers)
- **Notification**: ❌ **BROKEN** (0/25 functions can send notifications)

### Risk Assessment:
- **High**: Security issues fixed silently without audit trail
- **High**: No visibility into what auto-remediation is doing
- **High**: Cannot prove compliance to auditors (no notification logs)
- **Medium**: MFA violations detected but no notification sent

---

## SUMMARY

### What I Forgot to Set Up:

1. ❌ **SNS notifications for 24/25 remediation functions** - Only MFA has notification code
2. ❌ **ALERT_TOPIC_ARN environment variable** - Set to empty string during deployment
3. ❌ **EventBridge rules for 17/25 remediations** - Only 8 have automatic triggers
4. ❌ **Notification logging** - No record of what notifications were sent
5. ❌ **Notification failure handling** - Silent failures when ARN is empty

### What's Actually Working:

1. ✅ 8 automatic remediation triggers
2. ✅ Remediation actions execute successfully
3. ✅ SNS topic exists
4. ✅ Email subscription exists
5. ✅ Remediation logs written to DynamoDB

### Critical Path to Fix:

**Immediate Priority**:
1. Fix `ALERT_TOPIC_ARN` environment variable (5 minutes)
2. Test MFA notification for "test" user (5 minutes)

**Short-term Priority**:
3. Add notification code to all 24 other remediation functions (2-3 hours)
4. Add EventBridge rules for remaining 17 remediations (1-2 hours)

**Long-term Priority**:
5. Implement notification retry logic
6. Add notification failure alerts
7. Create notification audit dashboard

---

**Next Steps**: Shall I implement Fix #1 (set the ALERT_TOPIC_ARN) immediately so MFA notifications work?
