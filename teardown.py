import boto3
import json
import os
import sys
import time
from botocore.exceptions import ClientError

GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_success(msg):
    print(f"{GREEN}✅ {msg}{RESET}")


def print_error(msg):
    print(f"{RED}❌ {msg}{RESET}")


def print_info(msg):
    print(f"{BLUE}ℹ️  {msg}{RESET}")


def print_warning(msg):
    print(f"{YELLOW}⚠️  {msg}{RESET}")


def bucket_exists(bucket_name, profile=None):
    """
    Check if an S3 bucket exists.

    Args:
        bucket_name: Name of the bucket to check
        profile: AWS profile name (optional)

    Returns:
        True if bucket exists, False otherwise
    """
    session = boto3.Session(profile_name=profile)
    s3 = session.client("s3")
    try:
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "404" or error_code == "NoSuchBucket":
            return False
        raise


def empty_bucket(bucket_name, profile=None, max_retries=3):
    """
    Empty an S3 bucket by deleting all objects, versions, and delete markers.

    Args:
        bucket_name: Name of the bucket to empty
        profile: AWS profile name (optional)
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        True if successful, False otherwise
    """
    session = boto3.Session(profile_name=profile)
    s3 = session.resource("s3")
    bucket = s3.Bucket(bucket_name)

    for attempt in range(max_retries):
        try:
            # Delete all objects and their versions
            bucket.object_versions.delete()
            print_success(f"Emptied S3 bucket: {bucket_name}")
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                print_warning(
                    f"Attempt {attempt + 1}/{max_retries} failed to empty bucket {bucket_name}: {e}"
                )
                time.sleep(2**attempt)  # Exponential backoff
            else:
                print_error(
                    f"Failed to empty bucket {bucket_name} after {max_retries} attempts: {e}"
                )
                return False


def delete_bucket(bucket_name, profile=None, max_retries=3):
    """
    Delete an S3 bucket after emptying it.

    Args:
        bucket_name: Name of the bucket to delete
        profile: AWS profile name (optional)
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        True if successful, False otherwise
    """
    session = boto3.Session(profile_name=profile)
    s3 = session.client("s3")

    # First, empty the bucket
    if not empty_bucket(bucket_name, profile, max_retries):
        return False

    # Then delete the bucket
    for attempt in range(max_retries):
        try:
            s3.delete_bucket(Bucket=bucket_name)
            print_success(f"Deleted S3 bucket: {bucket_name}")
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "NoSuchBucket":
                print_warning(f"Bucket {bucket_name} does not exist, skipping deletion")
                return True
            if attempt < max_retries - 1:
                print_warning(
                    f"Attempt {attempt + 1}/{max_retries} failed to delete bucket {bucket_name}: {e}"
                )
                time.sleep(2**attempt)  # Exponential backoff
            else:
                print_error(
                    f"Failed to delete bucket {bucket_name} after {max_retries} attempts: {e}"
                )
                return False
        except Exception as e:
            if attempt < max_retries - 1:
                print_warning(
                    f"Attempt {attempt + 1}/{max_retries} failed to delete bucket {bucket_name}: {e}"
                )
                time.sleep(2**attempt)  # Exponential backoff
            else:
                print_error(
                    f"Failed to delete bucket {bucket_name} after {max_retries} attempts: {e}"
                )
                return False


def verify_bucket_deleted(bucket_name, profile=None, max_attempts=5):
    """
    Verify that a bucket has been deleted.

    Args:
        bucket_name: Name of the bucket to verify
        profile: AWS profile name (optional)
        max_attempts: Maximum number of verification attempts (default: 5)

    Returns:
        True if bucket is deleted, False otherwise
    """
    for attempt in range(max_attempts):
        if not bucket_exists(bucket_name, profile):
            print_success(f"Verified bucket {bucket_name} is deleted")
            return True
        print_info(
            f"Waiting for bucket {bucket_name} to be deleted (attempt {attempt + 1}/{max_attempts})..."
        )
        time.sleep(2)

    print_error(
        f"Bucket {bucket_name} still exists after {max_attempts} verification attempts"
    )
    return False


def get_lambda_code_bucket_name(stack_name, profile=None):
    """
    Construct the Lambda code bucket name from the stack name.

    Args:
        stack_name: CloudFormation stack name
        profile: AWS profile name (optional)

    Returns:
        Lambda code bucket name or None if environment cannot be determined
    """
    # Extract environment from stack name
    # Stack name format: grc-collector-{environment}
    parts = stack_name.split("-")
    if len(parts) < 3 or parts[0] != "grc" or parts[1] != "collector":
        print_warning(f"Could not determine environment from stack name: {stack_name}")
        return None

    environment = "-".join(parts[2:])

    # Get account ID
    try:
        session = boto3.Session(profile_name=profile)
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        lambda_code_bucket = f"grc-lambda-code-{account_id}-{environment}"
        return lambda_code_bucket
    except Exception as e:
        print_error(f"Failed to get account ID: {e}")
        return None


def cleanup_lambda_code_bucket(stack_name, profile=None):
    """
    Clean up the Lambda code bucket created outside of CloudFormation.

    Args:
        stack_name: CloudFormation stack name
        profile: AWS profile name (optional)

    Returns:
        True if successful or bucket doesn't exist, False otherwise
    """
    lambda_code_bucket = get_lambda_code_bucket_name(stack_name, profile)
    if not lambda_code_bucket:
        return False

    print_info(f"Checking for Lambda code bucket: {lambda_code_bucket}")

    if not bucket_exists(lambda_code_bucket, profile):
        print_info(
            f"Lambda code bucket {lambda_code_bucket} does not exist, skipping cleanup"
        )
        return True

    print_info(f"Deleting Lambda code bucket: {lambda_code_bucket}")
    if delete_bucket(lambda_code_bucket, profile):
        verify_bucket_deleted(lambda_code_bucket, profile)
        return True
    else:
        print_error(f"Failed to delete Lambda code bucket: {lambda_code_bucket}")
        return False


def teardown_boto3(profile=None):
    if not os.path.exists("grc_config.json"):
        print_error("No grc_config.json found.")
        return

    with open("grc_config.json", "r") as f:
        config = json.load(f)

    session = boto3.Session(profile_name=profile)
    s3 = session.client("s3")
    dynamodb = session.client("dynamodb")
    sns = session.client("sns")
    iam = session.client("iam")
    lambda_client = session.client("lambda")
    events = session.client("events")
    cloudtrail = session.client("cloudtrail")

    # 1. CloudTrail
    if "CloudTrailName" in config:
        try:
            cloudtrail.stop_logging(Name=config["CloudTrailName"])
            cloudtrail.delete_trail(Name=config["CloudTrailName"])
            print_success(f"Deleted CloudTrail: {config['CloudTrailName']}")
        except Exception as e:
            print_error(f"Failed to delete CloudTrail: {e}")

    # 2. EventBridge
    if "EventBridgeRule" in config:
        try:
            events.remove_targets(Rule=config["EventBridgeRule"], Ids=["1"])
            events.delete_rule(Name=config["EventBridgeRule"])
            print_success(f"Deleted EventBridge rule: {config['EventBridgeRule']}")
        except Exception as e:
            print_error(f"Failed to delete EventBridge rule: {e}")

    # 3. Lambda
    if "LambdaFunctionName" in config:
        try:
            lambda_client.delete_function(FunctionName=config["LambdaFunctionName"])
            print_success(f"Deleted Lambda function: {config['LambdaFunctionName']}")
        except Exception as e:
            print_error(f"Failed to delete Lambda function: {e}")

    # 4. IAM Role
    if "LambdaRoleArn" in config:
        role_name = config["LambdaRoleArn"].split("/")[-1]
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="GRC-Lambda-Policy")
            iam.delete_role(RoleName=role_name)
            print_success(f"Deleted IAM role: {role_name}")
        except Exception as e:
            print_error(f"Failed to delete IAM role: {e}")

    # 5. SNS
    if "AlertTopicArn" in config:
        try:
            sns.delete_topic(TopicArn=config["AlertTopicArn"])
            print_success(f"Deleted SNS topic: {config['AlertTopicArn']}")
        except Exception as e:
            print_error(f"Failed to delete SNS topic: {e}")

    # 6. DynamoDB
    if "MetadataTable" in config:
        try:
            dynamodb.delete_table(TableName=config["MetadataTable"])
            print_success(f"Deleted DynamoDB table: {config['MetadataTable']}")
        except Exception as e:
            print_error(f"Failed to delete DynamoDB table: {e}")

    # 7. S3
    if "EvidenceBucket" in config:
        try:
            delete_bucket(config["EvidenceBucket"], profile)
        except Exception as e:
            print_error(f"Failed to delete S3 bucket: {e}")

    os.remove("grc_config.json")
    print_success("Removed grc_config.json")


def teardown_cf(stack_name, profile=None):
    session = boto3.Session(profile_name=profile)
    cf = session.client("cloudformation")
    print_warning(f"Deleting stack {stack_name}...")

    # Step 1: Get EvidenceBucket from stack outputs
    evidence_bucket = None
    try:
        response = cf.describe_stacks(StackName=stack_name)
        outputs = response["Stacks"][0].get("Outputs", [])
        evidence_bucket = next(
            (
                o["OutputValue"]
                for o in outputs
                if o["OutputKey"] == "EvidenceBucketName"
            ),
            None,
        )
        if evidence_bucket:
            print_info(f"Found EvidenceBucket from stack: {evidence_bucket}")
    except Exception as e:
        print_warning(f"Could not get stack outputs (stack might not exist): {e}")

    # Step 2: Clean up Lambda code bucket (created outside CloudFormation)
    lambda_code_bucket = get_lambda_code_bucket_name(stack_name, profile)
    if lambda_code_bucket and lambda_code_bucket != evidence_bucket:
        print_info(
            f"Cleaning up Lambda code bucket (not part of CloudFormation stack): {lambda_code_bucket}"
        )
        cleanup_lambda_code_bucket(stack_name, profile)
    elif lambda_code_bucket == evidence_bucket:
        print_info(
            f"Lambda code bucket is the same as EvidenceBucket, will be cleaned with EvidenceBucket"
        )
    else:
        print_info(f"Could not determine Lambda code bucket name, skipping cleanup")

    # Step 3: Empty EvidenceBucket if it exists and is different from Lambda code bucket
    if evidence_bucket and evidence_bucket != lambda_code_bucket:
        if bucket_exists(evidence_bucket, profile):
            print_info(f"Emptying EvidenceBucket: {evidence_bucket}")
            empty_bucket(evidence_bucket, profile)
        else:
            print_warning(f"EvidenceBucket {evidence_bucket} does not exist, skipping")

    # Step 4: Delete the CloudFormation stack
    try:
        cf.delete_stack(StackName=stack_name)
        print_info(f"Waiting for stack {stack_name} to be deleted...")
        waiter = cf.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 10, "MaxAttempts": 60})
        print_success(f"Stack {stack_name} deleted successfully.")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "ValidationError":
            print_warning(f"Stack {stack_name} does not exist, skipping deletion")
        else:
            print_error(f"Failed to delete stack: {e}")
    except Exception as e:
        print_error(f"Failed to delete stack: {e}")

    # Step 5: Verify EvidenceBucket is deleted (CloudFormation should have deleted it)
    if evidence_bucket and evidence_bucket != lambda_code_bucket:
        if bucket_exists(evidence_bucket, profile):
            print_warning(
                f"EvidenceBucket {evidence_bucket} still exists after stack deletion, attempting manual cleanup"
            )
            delete_bucket(evidence_bucket, profile)
            verify_bucket_deleted(evidence_bucket, profile)

    # Step 6: Final verification of Lambda code bucket
    if lambda_code_bucket and lambda_code_bucket != evidence_bucket:
        if bucket_exists(lambda_code_bucket, profile):
            print_warning(
                f"Lambda code bucket {lambda_code_bucket} still exists, attempting final cleanup"
            )
            delete_bucket(lambda_code_bucket, profile)
            verify_bucket_deleted(lambda_code_bucket, profile)


import argparse


def main():
    parser = argparse.ArgumentParser(description="GRC Evidence Collector — Teardown")
    parser.add_argument("--stack-name", type=str, help="CloudFormation stack name")
    parser.add_argument("--profile", type=str, help="AWS CLI profile name")
    args = parser.parse_args()

    print(f"{BOLD}GRC Evidence Collector — Teardown{RESET}")
    print("========================================")

    if args.stack_name:
        confirm = input(
            f"This will DELETE all GRC resources in stack {args.stack_name}. Type 'yes' to confirm: "
        )
        if confirm.lower() == "yes":
            teardown_cf(args.stack_name, args.profile)
    else:
        confirm = input(
            "This will DELETE all GRC resources from grc_config.json. Type 'yes' to confirm: "
        )
        if confirm.lower() == "yes":
            teardown_boto3(args.profile)


if __name__ == "__main__":
    main()
