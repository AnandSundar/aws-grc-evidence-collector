import boto3
import time
import sys
import os
import zipfile

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


def upload_batch_processor_to_s3(s3_client, bucket_name, profile=None):
    """Upload the batch_processor.py Lambda function to S3."""
    print_info("Packaging and uploading batch processor Lambda function to S3...")

    try:
        # Create a zip file with the batch_processor.py
        zip_path = "batch_processor_lambda.zip"
        with zipfile.ZipFile(zip_path, "w") as zipf:
            zipf.write("lambda/batch_processor.py", "batch_processor.py")

        # Upload to S3
        with open(zip_path, "rb") as f:
            s3_client.upload_fileobj(
                f,
                bucket_name,
                "lambda/batch_processor.zip",
                ExtraArgs={"ContentType": "application/zip"},
            )

        # Clean up the zip file
        os.remove(zip_path)
        print_success("Batch processor Lambda function uploaded to S3")
        return True
    except Exception as e:
        print_error(f"Failed to upload batch processor to S3: {e}")
        if os.path.exists("batch_processor_lambda.zip"):
            os.remove("batch_processor_lambda.zip")
        return False


def poll_stack_events(cf, stack_name, action):
    print_info(f"Waiting for stack {action} to complete...")
    waiter_name = (
        "stack_create_complete" if action == "create" else "stack_update_complete"
    )
    waiter = cf.get_waiter(waiter_name)

    try:
        waiter.wait(StackName=stack_name)
        print_success(f"Stack {action} completed successfully!")

        response = cf.describe_stacks(StackName=stack_name)
        outputs = response["Stacks"][0].get("Outputs", [])
        print(f"\n{BOLD}Stack Outputs:{RESET}")
        for output in outputs:
            print(f"  {output['OutputKey']}: {output['OutputValue']}")

    except Exception as e:
        print_error(f"Stack {action} failed: {e}")
        response = cf.describe_stack_events(StackName=stack_name)
        for event in response["StackEvents"]:
            if "FAILED" in event["ResourceStatus"]:
                print_error(
                    f"{event['LogicalResourceId']}: {event['ResourceStatusReason']}"
                )


def deploy_stack(
    enable_ai: bool,
    alert_email: str = "",
    environment: str = "dev",
    profile: str = None,
    report_enabled: bool = False,
    report_email: str = "",
    report_schedule: str = "rate(1 day)",
    enable_medium_alerts: bool = True,
    enable_low_alerts: bool = True,
    medium_batch_size: int = 10,
    low_batch_size: int = 10,
    medium_batch_interval: int = 15,
    low_batch_interval: int = 60,
    max_emails_per_hour: int = 10,
    use_batching: bool = True,
):
    session = boto3.Session(profile_name=profile)
    cf = session.client("cloudformation")
    s3 = session.client("s3")
    stack_name = f"grc-evidence-collector-{environment}"

    with open("cloudformation/grc-collector-template.yaml", "r", encoding="utf-8") as f:
        template_body = f.read()

    # Check if stack exists to determine if we're creating or updating
    stack_exists = False
    s3_bucket_name = None

    try:
        response = cf.describe_stacks(StackName=stack_name)
        stack_exists = True
        # Get the S3 bucket name from stack outputs
        outputs = response["Stacks"][0].get("Outputs", [])
        for output in outputs:
            if output["OutputKey"] == "EvidenceBucketName":
                s3_bucket_name = output["OutputValue"]
                break
    except cf.exceptions.ClientError as e:
        if "does not exist" not in str(e):
            raise

    # Upload batch processor Lambda code to S3
    lambda_code_bucket = None
    if use_batching:
        if s3_bucket_name:
            # Update scenario: use existing EvidenceBucket
            lambda_code_bucket = s3_bucket_name
            if not upload_batch_processor_to_s3(s3, lambda_code_bucket, profile):
                print_error("Failed to upload batch processor, aborting deployment")
                return
        else:
            # Create scenario: create a dedicated bucket for Lambda code
            lambda_code_bucket = f"grc-lambda-code-{session.client('sts').get_caller_identity()['Account']}-{environment}"
            try:
                print_info(f"Creating S3 bucket for Lambda code: {lambda_code_bucket}")
                region = session.region_name or "us-east-1"
                if region == "us-east-1":
                    s3.create_bucket(Bucket=lambda_code_bucket)
                else:
                    s3.create_bucket(
                        Bucket=lambda_code_bucket,
                        CreateBucketConfiguration={"LocationConstraint": region},
                    )

                if not upload_batch_processor_to_s3(s3, lambda_code_bucket, profile):
                    print_error("Failed to upload batch processor, aborting deployment")
                    # Clean up bucket
                    try:
                        s3.delete_bucket(Bucket=lambda_code_bucket)
                    except:
                        pass
                    return

                print_success(
                    f"Created S3 bucket for Lambda code: {lambda_code_bucket}"
                )
            except Exception as e:
                print_error(f"Failed to create S3 bucket for Lambda code: {e}")
                return

    parameters = [
        {"ParameterKey": "Environment", "ParameterValue": environment},
        {"ParameterKey": "EnableAIAnalysis", "ParameterValue": str(enable_ai).lower()},
        {"ParameterKey": "AlertEmail", "ParameterValue": alert_email},
        {
            "ParameterKey": "ReportEnabled",
            "ParameterValue": str(report_enabled).lower(),
        },
        {"ParameterKey": "ReportEmail", "ParameterValue": report_email},
        {"ParameterKey": "ReportSchedule", "ParameterValue": report_schedule},
        {
            "ParameterKey": "EnableMediumAlerts",
            "ParameterValue": str(enable_medium_alerts).lower(),
        },
        {
            "ParameterKey": "EnableLowAlerts",
            "ParameterValue": str(enable_low_alerts).lower(),
        },
        {"ParameterKey": "MediumBatchSize", "ParameterValue": str(medium_batch_size)},
        {"ParameterKey": "LowBatchSize", "ParameterValue": str(low_batch_size)},
        {
            "ParameterKey": "MediumBatchInterval",
            "ParameterValue": str(medium_batch_interval),
        },
        {"ParameterKey": "LowBatchInterval", "ParameterValue": str(low_batch_interval)},
        {
            "ParameterKey": "MaxEmailsPerHour",
            "ParameterValue": str(max_emails_per_hour),
        },
        {"ParameterKey": "UseBatching", "ParameterValue": str(use_batching).lower()},
        {
            "ParameterKey": "LambdaCodeBucket",
            "ParameterValue": lambda_code_bucket or "",
        },
    ]

    try:
        cf.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=parameters,
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        )
        action = "create"
    except cf.exceptions.AlreadyExistsException:
        try:
            cf.update_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=parameters,
                Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            )
            action = "update"
        except Exception as e:
            if "No updates are to be performed" in str(e):
                print_info("No updates are to be performed.")
                return
            else:
                raise e

    poll_stack_events(cf, stack_name, action)


def delete_stack(environment: str = "dev", profile: str = None):
    session = boto3.Session(profile_name=profile)
    cf = session.client("cloudformation")
    stack_name = f"grc-evidence-collector-{environment}"
    print_warning(f"Deleting stack {stack_name}...")

    # Empty S3 bucket first
    try:
        response = cf.describe_stacks(StackName=stack_name)
        outputs = response["Stacks"][0].get("Outputs", [])
        bucket_name = next(
            (
                o["OutputValue"]
                for o in outputs
                if o["OutputKey"] == "EvidenceBucketName"
            ),
            None,
        )

        if bucket_name:
            s3 = session.resource("s3")
            bucket = s3.Bucket(bucket_name)
            bucket.object_versions.delete()
            print_info(f"Emptied bucket {bucket_name}")
    except Exception as e:
        print_warning(f"Could not empty bucket (might not exist): {e}")

    cf.delete_stack(StackName=stack_name)
    waiter = cf.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name)
    print_success(f"Stack {stack_name} deleted successfully.")


def view_outputs(environment: str = "dev", profile: str = None):
    session = boto3.Session(profile_name=profile)
    cf = session.client("cloudformation")
    stack_name = f"grc-evidence-collector-{environment}"
    try:
        response = cf.describe_stacks(StackName=stack_name)
        outputs = response["Stacks"][0].get("Outputs", [])
        print(f"\n{BOLD}Stack Outputs:{RESET}")
        for output in outputs:
            print(f"  {output['OutputKey']}: {output['OutputValue']}")
    except Exception as e:
        print_error(f"Could not retrieve outputs: {e}")


import argparse


def main():
    parser = argparse.ArgumentParser(
        description="GRC Evidence Collector — CloudFormation Deployment"
    )
    parser.add_argument("--ai", action="store_true", help="Deploy with AI enabled")
    parser.add_argument("--no-ai", action="store_true", help="Deploy without AI")
    parser.add_argument(
        "--email", type=str, default="", help="Alert email for HIGH priority events"
    )
    parser.add_argument("--delete", action="store_true", help="Delete the stack")
    parser.add_argument("--outputs", action="store_true", help="View stack outputs")
    parser.add_argument(
        "--env", type=str, default="dev", help="Environment (dev/staging/prod)"
    )
    parser.add_argument("--profile", type=str, help="AWS CLI profile name")
    parser.add_argument(
        "--report-email",
        type=str,
        default="",
        help="Email address for scheduled reports",
    )
    parser.add_argument(
        "--report-schedule",
        type=str,
        default="rate(1 day)",
        help="Schedule expression for reports (e.g., 'rate(1 day)', 'cron(0 9 * * ? *)')",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Disable scheduled reports (default)",
    )
    # Batching configuration arguments
    parser.add_argument(
        "--enable-medium-alerts",
        action="store_true",
        help="Enable MEDIUM priority batched alerts (default)",
    )
    parser.add_argument(
        "--no-medium-alerts",
        action="store_true",
        help="Disable MEDIUM priority batched alerts",
    )
    parser.add_argument(
        "--enable-low-alerts",
        action="store_true",
        help="Enable LOW priority batched alerts (default)",
    )
    parser.add_argument(
        "--no-low-alerts",
        action="store_true",
        help="Disable LOW priority batched alerts",
    )
    parser.add_argument(
        "--medium-batch-size",
        type=int,
        default=10,
        help="Number of MEDIUM events to batch before sending (default: 10)",
    )
    parser.add_argument(
        "--low-batch-size",
        type=int,
        default=10,
        help="Number of LOW events to batch before sending (default: 10)",
    )
    parser.add_argument(
        "--medium-batch-interval",
        type=int,
        default=15,
        help="Minutes to wait before sending MEDIUM batch (default: 15)",
    )
    parser.add_argument(
        "--low-batch-interval",
        type=int,
        default=60,
        help="Minutes to wait before sending LOW batch (default: 60)",
    )
    parser.add_argument(
        "--max-emails-per-hour",
        type=int,
        default=10,
        help="Maximum emails per hour (rate limiting, default: 10)",
    )
    parser.add_argument(
        "--no-batching",
        action="store_true",
        help="Disable batching for MEDIUM/LOW events",
    )

    args = parser.parse_args()

    if args.delete:
        confirm = input(
            f"This will DELETE all GRC resources in stack grc-evidence-collector-{args.env}. Type 'yes' to confirm: "
        )
        if confirm.lower() == "yes":
            delete_stack(args.env, args.profile)
        return

    if args.outputs:
        view_outputs(args.env, args.profile)
        return

    if args.ai or args.no_ai:
        report_enabled = not args.no_report and bool(args.report_email)
        enable_medium_alerts = not args.no_medium_alerts
        enable_low_alerts = not args.no_low_alerts
        use_batching = not args.no_batching
        deploy_stack(
            args.ai,
            args.email,
            args.env,
            args.profile,
            report_enabled=report_enabled,
            report_email=args.report_email,
            report_schedule=args.report_schedule,
            enable_medium_alerts=enable_medium_alerts,
            enable_low_alerts=enable_low_alerts,
            medium_batch_size=args.medium_batch_size,
            low_batch_size=args.low_batch_size,
            medium_batch_interval=args.medium_batch_interval,
            low_batch_interval=args.low_batch_interval,
            max_emails_per_hour=args.max_emails_per_hour,
            use_batching=use_batching,
        )
        return

    print(f"{BOLD}GRC Evidence Collector — CloudFormation Deployment{RESET}")
    print("================================================")
    print("1. Deploy WITHOUT AI (Free Tier, $0/month)")
    print("2. Deploy WITH AI (Bedrock, ~$0.78/month)")
    print("3. Update existing stack")
    print("4. Delete stack (teardown)")
    print("5. View stack outputs")

    choice = input("Enter choice (1-5): ")

    if choice in ["1", "2", "3"]:
        enable_ai = choice == "2"
        alert_email = input(
            "Enter alert email (optional, press Enter to skip): "
        ).strip()

        # Ask about scheduled reports
        report_choice = (
            input("Enable scheduled summary reports? (y/N): ").strip().lower()
        )
        report_enabled = report_choice == "y"
        report_email = ""
        report_schedule = "rate(1 day)"

        if report_enabled:
            report_email = input("Enter report email (required): ").strip()
            if not report_email:
                print_warning("No report email provided, disabling scheduled reports")
                report_enabled = False
            else:
                schedule_input = input(
                    "Enter report schedule (default: rate(1 day)): "
                ).strip()
                if schedule_input:
                    report_schedule = schedule_input

        # Ask about batching configuration
        batching_choice = (
            input("Enable batched alerts for MEDIUM/LOW priority events? (Y/n): ")
            .strip()
            .lower()
        )
        use_batching = batching_choice != "n"

        enable_medium_alerts = True
        enable_low_alerts = True
        medium_batch_size = 10
        low_batch_size = 10
        medium_batch_interval = 15
        low_batch_interval = 60
        max_emails_per_hour = 10

        if use_batching:
            medium_alerts_choice = (
                input("Enable MEDIUM priority alerts? (Y/n): ").strip().lower()
            )
            enable_medium_alerts = medium_alerts_choice != "n"

            low_alerts_choice = (
                input("Enable LOW priority alerts? (Y/n): ").strip().lower()
            )
            enable_low_alerts = low_alerts_choice != "n"

            if enable_medium_alerts:
                batch_size_input = input("MEDIUM batch size (default: 10): ").strip()
                if batch_size_input:
                    medium_batch_size = int(batch_size_input)

                batch_interval_input = input(
                    "MEDIUM batch interval in minutes (default: 15): "
                ).strip()
                if batch_interval_input:
                    medium_batch_interval = int(batch_interval_input)

            if enable_low_alerts:
                batch_size_input = input("LOW batch size (default: 10): ").strip()
                if batch_size_input:
                    low_batch_size = int(batch_size_input)

                batch_interval_input = input(
                    "LOW batch interval in minutes (default: 60): "
                ).strip()
                if batch_interval_input:
                    low_batch_interval = int(batch_interval_input)

            max_emails_input = input("Max emails per hour (default: 10): ").strip()
            if max_emails_input:
                max_emails_per_hour = int(max_emails_input)

        deploy_stack(
            enable_ai,
            alert_email,
            args.env,
            args.profile,
            report_enabled=report_enabled,
            report_email=report_email,
            report_schedule=report_schedule,
            enable_medium_alerts=enable_medium_alerts,
            enable_low_alerts=enable_low_alerts,
            medium_batch_size=medium_batch_size,
            low_batch_size=low_batch_size,
            medium_batch_interval=medium_batch_interval,
            low_batch_interval=low_batch_interval,
            max_emails_per_hour=max_emails_per_hour,
            use_batching=use_batching,
        )
    elif choice == "4":
        confirm = input("This will DELETE all GRC resources. Type 'yes' to confirm: ")
        if confirm.lower() == "yes":
            delete_stack(args.env, args.profile)
    elif choice == "5":
        view_outputs(args.env, args.profile)
    else:
        print_error("Invalid choice.")


if __name__ == "__main__":
    main()
