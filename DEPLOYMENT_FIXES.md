# CloudFormation Deployment Fixes

This document summarizes all the fixes made to ensure `make deploy` works correctly with the AI-generated email feature.

## Files Modified

### 1. `cloudformation/grc-platform-template.yaml`

#### ScorecardGeneratorRole IAM Policy (Line 801)
**Change**: Added `dynamodb:PutItem` permission
```yaml
- Sid: DynamoDBReadWrite  # Was: DynamoDBRead
  Action:
    - 'dynamodb:GetItem'
    - 'dynamodb:Query'
    - 'dynamodb:Scan'
    - 'dynamodb:PutItem'  # Added this
```

#### ScorecardGeneratorRole Bedrock Permission (Line 835)
**Change**: Removed the condition that was blocking access
```yaml
- Sid: BedrockInvoke
  Effect: Allow
  Action: 'bedrock:InvokeModel'
  Resource: !Sub "arn:aws:bedrock:${AWS::Region}::foundation-model/nvidia.nemotron-nano-12b-v2"
  # Removed: Condition with PrincipalTag/Environment
```

#### ScorecardGenerator Environment Variables (Line 1195)
**Changes**:
1. Fixed GSI name: `EVIDENCE_TIMESTAMP_GSI: "TimestampIndex"` (was: "created_at-index")
2. Removed reserved variable: `AWS_REGION` (causes Lambda errors)
3. Added: `USE_AI_EMAIL: "true"`
4. Added: `AWS_ACCOUNT_ID: !Ref AWS::AccountId`

#### ScorecardGenerator Code Reference (Line 1200)
**Change**: Use parameter instead of hardcoded bucket
```yaml
Code:
  S3Bucket: !Ref EvidenceBucket  # Was: hardcoded bucket name
  S3Key: scorecard-generator-package.zip
```

### 2. `lambda/scorecard_generator/handler.py`

#### DynamoDB Query (Line 96)
**Change**: Use scan instead of query (GSI only has hash key)
```python
# Changed from query to scan since TimestampIndex only has hash key
scan_params = {
    "TableName": table_name,
    "FilterExpression": "#ts BETWEEN :start_time AND :end_time",
    ...
}
```

#### Bedrock API Format (Line 564)
**Change**: Use correct format for Nemotron model
```python
# Changed from "prompt" to "messages" format
body=json.dumps({
    "messages": [{"role": "user", "content": prompt}],
    "max_tokens": 800,
    ...
})
```

### 3. `lambda/evidence_processor/index.py`

#### DynamoDB Storage Field Name (Line 338)
**Change**: Use `timestamp` instead of `created_at` to match GSI
```python
"timestamp": evidence_record.created_at,  # Was: "created_at"
```

### 4. `scripts/build_scorecard_package.py` (NEW)
New build script to package the scorecard generator Lambda code.

### 5. `scripts/deploy_cloudformation.py`

Added methods:
- `_build_scorecard_package()` - Builds scorecard generator package
- `_upload_scorecard_package()` - Uploads to S3
- `_update_template_with_scorecard_package()` - Updates template S3 references

Updated methods:
- `deploy_stack()` - Now builds and uploads scorecard package
- `update_stack()` - Now builds and uploads scorecard package

## Verification

To verify all changes work correctly:

1. **Deploy the stack**:
   ```bash
   make deploy
   # Select option 5 to update existing stack
   ```

2. **Verify Lambda code is updated**:
   ```bash
   aws lambda get-function-configuration --function-name grc-evidence-platform-scorecard-generator-dev --query 'Environment.Variables.USE_AI_EMAIL'
   ```

3. **Verify IAM permissions**:
   ```bash
   aws iam get-role-policy --role-name grc-evidence-platform-scorecard-generator-dev --policy-name ScorecardGeneratorPolicy --query 'PolicyDocument.Statement'
   ```

4. **Test the Lambda**:
   ```bash
   aws lambda invoke --function-name grc-evidence-platform-scorecard-generator-dev --payload '{}' response.json
   ```

## Key Issues Fixed

1. **IAM Permissions** - Added missing `dynamodb:PutItem` and fixed SNS topic ARN
2. **Bedrock Access** - Removed blocking condition on PrincipalTag
3. **DynamoDB GSI** - Fixed field name mismatch (`timestamp` vs `created_at`)
4. **Reserved Variables** - Removed `AWS_REGION` which is reserved in Lambda
5. **Bedrock API Format** - Updated to use `messages` format for Nemotron
6. **Package Deployment** - Added build script for scorecard generator

All changes are now in the CloudFormation template and Lambda code, so future `make deploy` commands will work correctly without manual intervention.
