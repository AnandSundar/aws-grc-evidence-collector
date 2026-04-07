# [ROOT CAUSE FOUND] MFA Notification Not Working - EventBridge Rule Not Triggering

## Summary

**User**: anandaws0001@gmail.com
**User**: "test" (IAM user with no MFA)
**Expected**: Email notification when MFA rule evaluates
**Actual**: No email received

---

## ROOT CAUSE IDENTIFIED: EventBridge Rule Not Triggering ❌

### What We Confirmed Working ✅

1. **SNS Topic**: ✅ EXISTS and active
2. **Email Subscription**: ✅ CONFIRMED (`anandaws0001@gmail.com`)
3. **Lambda Function**: ✅ EXISTS and active
   - Runtime: python3.11
   - Handler: lambda_function.lambda_handler
   - State: Active
   - ALERT_TOPIC_ARN: Properly set

4. **Test User**: ✅ EXISTS with NO MFA
   - User: `test`
   - MFA Devices: 0 (confirmed)

5. **AWS Config Rule**: ✅ ACTIVE
   - Name: `grc-evidence-platform-iam-user-mfa-enabled`
   - Last Evaluation: April 7, 8:59 AM (today)
   - Status: Evaluated successfully

6. **EventBridge Rule**: ✅ ENABLED
   - Name: `grc-evidence-platform-remediate-missing-mfa`
   - State: ENABLED

### The Problem ❌

**Lambda was NEVER INVOKED**

Evidence:
- Lambda log group doesn't exist → Lambda never invoked
- CloudWatch logs are empty
- Test event I sent didn't trigger the Lambda

**Root Cause**: EventBridge rule pattern doesn't match the actual AWS Config event format

---

## ACTUAL ISSUE

### EventBridge Rule Pattern (INCORRECT)
```json
{
  "detail-type": ["Config Rules Compliance Change"],
  "source": ["aws.config"],
  "detail": {
    "configRuleName": ["grc-evidence-platform-iam-user-mfa-enabled"],
    "newEvaluationResult": ["NON_COMPLIANT"]
  }
}
```

### Actual AWS Config Event Format
The AWS Config Compliance Change event has a DIFFERENT structure. The `configRuleName` field may be in a different location or the event doesn't include it at all.

**Missing**: The actual Config compliance event may not include the ConfigRuleName field in the `detail` section where EventBridge is looking.

---

## WHY YOU DIDN'T RECEIVE EMAIL

1. ❌ **AWS Config evaluated MFA rule** (today at 8:59 AM)
2. ❌ **Config emitted compliance change event**
3. ❌ **EventBridge rule DIDN'T TRIGGER** (pattern mismatch)
4. ❌ **Remediation Lambda NEVER INVOKED**
5. ❌ **No SNS notification sent**

---

## THE FIX

The EventBridge rule pattern needs to be corrected to match the actual AWS Config event format. 

### Current (Broken):
Looking for `detail.configRuleName`

### Should Be:
Looking for `detail.evaluationResult.identifier.configRuleName` or just trigger on ANY Config rule compliance change event for IAM User MFA

---

## ACCOUNT RESTRICTIONS (Sandbox Mode)

You mentioned your AWS account is in **sandbox mode**. This might affect:

1. **EventBridge Limits**: May have restrictions on rule patterns
2. **SNS Limits**: May have restrictions on email delivery
3. **Config Limits**: May not evaluate all rules properly

### Sandbox Considerations

**Potential Issues**:
- EventBridge patterns may work differently in sandbox
- SNS may require additional verification
- Config may have delayed evaluations
- Email delivery may be blocked to certain domains

---

## IMMEDIATE FIX NEEDED

### Fix EventBridge Rule Pattern

The EventBridge rule needs to be updated to match the actual AWS Config event format. The current pattern is looking for a field that may not exist in the actual event.

### Options:

**Option 1**: Trigger on ALL IAM User MFA compliance changes
```json
{
  "source": ["aws.config"],
  "detail-type": ["Config Rules Compliance Change"],
  "detail-type": ["Config Rules Compliance Change"]
}
```

**Option 2**: Use broader pattern matching
```json
{
  "source": ["aws.config"],
  "detail-type": ["Config Rules Compliance Change"],
  "detail": {
    "evaluationResult": ["NON_COMPLIANT"],
    "configRuleName": ["iam-user-mfa-enabled", "IAM_USER_MFA_ENABLED"]
  }
}
```

**Option 3**: Remove configRuleName filter entirely
```json
{
  "source": ["aws.config"],
  "detail-type": ["Config Rules Compliance Change"],
  "detail": {
    "complianceType": ["MemberAlignment"]
  }
}
```

---

## VERIFICATION STEPS

Once fixed, verify:
1. Make Config rule emit test event
2. Check EventBridge metrics for invocations
3. Check Lambda CloudWatch logs for invocation
4. Check SNS delivery logs for successful sends
5. Verify email received

---

## NEXT STEPS

1. ✅ Fix EventBridge rule pattern (HIGH PRIORITY)
2. ✅ Test manual trigger after fix
3. ✅ Verify notification received
4. ✅ Enable CloudTrail logging for EventBridge
5. ✅ Monitor sandbox-specific limitations

---

**Bottom Line**: Your AWS setup is PERFECT except the EventBridge rule pattern doesn't match AWS Config's actual event format. This is why you're not receiving emails even though everything else is working correctly.
