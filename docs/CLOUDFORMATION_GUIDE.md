# CloudFormation & Bedrock Guide

This guide details the deployment of Version 2 of the AWS GRC Evidence Collector, which utilizes AWS CloudFormation for Infrastructure as Code (IaC) and AWS Bedrock for AI-powered risk analysis.

## Prerequisites

1. **AWS Bedrock Model Access:**
   Before deploying with AI enabled, you must request access to the NVIDIA Nemotron Nano 12B v2 model in the AWS Bedrock console.
   - Go to AWS Console -> Amazon Bedrock -> Model access.
   - Request access to `NVIDIA Nemotron Nano 12B v2`.
   - Wait for access to be granted (usually instant).

2. **Python Dependencies:**
   ```bash
   pip install boto3
   ```

## Deployment via Script

The `deploy_cloudformation.py` script provides an interactive menu to manage the CloudFormation stack.

```bash
python deploy_cloudformation.py
```

### Menu Options:

1. **Deploy WITHOUT AI (Free Tier, $0/month):**
   Deploys the CloudFormation stack with `EnableAIAnalysis` set to `false`. The Lambda function will process events but skip the Bedrock API call.

2. **Deploy WITH AI (Bedrock, ~$0.78/month):**
   Deploys the stack with `EnableAIAnalysis` set to `true`. You will also be prompted to enter an optional email address for SNS alerts.

3. **Update existing stack:**
   If you modify the `cloudformation/grc-collector-template.yaml` file, use this option to apply the changes to the existing stack.

4. **Delete stack (teardown):**
   Safely deletes the CloudFormation stack. It automatically empties the S3 bucket before deletion to prevent stack deletion failures.

5. **View stack outputs:**
   Prints the outputs of the deployed stack, including the S3 Bucket Name, DynamoDB Table Name, and Lambda Function ARN.

## Manual Deployment (AWS CLI)

You can also deploy the CloudFormation template directly using the AWS CLI:

```bash
aws cloudformation deploy \
  --template-file cloudformation/grc-collector-template.yaml \
  --stack-name grc-evidence-collector-dev \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Environment=dev EnableAIAnalysis=true AlertEmail=your-email@example.com
```

## Testing

After deployment, use the `test_events.py` script to verify functionality. The script will automatically detect the CloudFormation stack outputs and send test events to the deployed Lambda function.

```bash
python test_events.py
```
