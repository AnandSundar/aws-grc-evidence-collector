#!/usr/bin/env python3
"""
GRC Evidence Platform v2.0 - CloudFormation Deployment Script

This script provides an interactive menu for deploying the GRC Evidence Platform
using CloudFormation templates. It supports multiple deployment configurations
with cost estimates and real-time event streaming.

Usage:
    python scripts/deploy_cloudformation.py

Author: GRC Platform Team
Version: 2.0
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("grc_cloudformation.log"),
    ],
)
logger = logging.getLogger(__name__)


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_colored(message: str, color: str = Colors.RESET) -> None:
    """
    Print a colored message to the terminal.

    Args:
        message: The message to print
        color: ANSI color code to use
    """
    print(f"{color}{message}{Colors.RESET}")


def print_success(message: str) -> None:
    """Print a success message in green."""
    print_colored(f"✓ {message}", Colors.GREEN)


def print_error(message: str) -> None:
    """Print an error message in red."""
    print_colored(f"✗ {message}", Colors.RED)


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    print_colored(f"⚠ {message}", Colors.YELLOW)


def print_info(message: str) -> None:
    """Print an info message in cyan."""
    print_colored(f"ℹ {message}", Colors.CYAN)


def print_header(message: str) -> None:
    """Print a header message in bold blue."""
    print_colored(f"\n{'=' * 70}", Colors.BLUE)
    print_colored(f"{message}", Colors.BOLD + Colors.BLUE)
    print_colored(f"{'=' * 70}\n", Colors.BLUE)


# Cost estimates for different configurations (per month)
COST_ESTIMATES = {
    "no_ai_no_remediation": {
        "name": "No AI, No Auto-Remediation",
        "cost": 0.00,
        "breakdown": {
            "Lambda (invocations)": "$0.00",
            "EventBridge (rules)": "$0.00",
            "S3 (storage)": "$0.00",
            "DynamoDB (on-demand)": "$0.00",
            "CloudWatch (logs)": "$0.00",
            "Total": "$0.00/month",
        },
    },
    "ai_only": {
        "name": "With AI Analysis only",
        "cost": 0.78,
        "breakdown": {
            "Lambda (invocations)": "$0.20",
            "EventBridge (rules)": "$0.08",
            "S3 (storage)": "$0.10",
            "DynamoDB (on-demand)": "$0.20",
            "CloudWatch (logs)": "$0.20",
            "Total": "$0.78/month",
        },
    },
    "remediation_only": {
        "name": "With Auto-Remediation only",
        "cost": 0.00,
        "breakdown": {
            "Lambda (invocations)": "$0.00",
            "EventBridge (rules)": "$0.00",
            "S3 (storage)": "$0.00",
            "DynamoDB (on-demand)": "$0.00",
            "CloudWatch (logs)": "$0.00",
            "Total": "$0.00/month",
        },
    },
    "full_platform": {
        "name": "Full Platform — AI + Auto-Remediation",
        "cost": 0.78,
        "breakdown": {
            "Lambda (invocations)": "$0.20",
            "EventBridge (rules)": "$0.08",
            "S3 (storage)": "$0.10",
            "DynamoDB (on-demand)": "$0.20",
            "CloudWatch (logs)": "$0.20",
            "Total": "$0.78/month",
        },
    },
}


class CloudFormationDeployer:
    """
    Main class for CloudFormation deployment operations.

    This class provides methods to deploy, update, delete, and manage
    CloudFormation stacks for the GRC Evidence Platform.
    """

    STACK_NAME = "grc-evidence-platform"
    TEMPLATE_PATH = "cloudformation/grc-platform-template.yaml"

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize the CloudFormation Deployer.

        Args:
            region: AWS region to deploy to (default: from environment or us-east-1)
            profile: AWS profile name to use (default: default)
        """
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.session = boto3.Session(region_name=self.region, profile_name=profile)

        # Initialize AWS clients
        self.cf_client = self.session.client("cloudformation")
        self.sts_client = self.session.client("sts")
        self.s3_client = self.session.client("s3")

        # Get account ID
        self.account_id = self._get_account_id()

        print_header(f"GRC Evidence Platform v2.0 - CloudFormation Deployment")
        print_info(f"Account ID: {self.account_id}")
        print_info(f"Region: {self.region}")

    def _get_account_id(self) -> str:
        """
        Get the current AWS account ID.

        Returns:
            AWS account ID as string
        """
        try:
            response = self.sts_client.get_caller_identity()
            return response["Account"]
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to get account ID: {e}")
            raise

    def _upload_template_to_s3(self) -> str:
        """
        Upload the CloudFormation template to S3 and return its URL.

        This method creates a temporary S3 bucket for template storage if needed,
        uploads the template file, and returns the S3 URL for CloudFormation to use.

        Returns:
            S3 URL of the uploaded template

        Raises:
            Exception: If template upload fails
        """
        import uuid
        from botocore.exceptions import ClientError

        # Generate a unique bucket name for template storage
        self.template_bucket_name = (
            f"grc-cf-templates-{self.account_id}-{uuid.uuid4().hex[:8]}"
        )
        template_key = f"templates/{os.path.basename(self.TEMPLATE_PATH)}"

        try:
            # Create S3 bucket for template storage
            print_info(
                f"Creating S3 bucket for template storage: {self.template_bucket_name}"
            )

            if self.region == "us-east-1":
                # us-east-1 has a special LocationConstraint
                self.s3_client.create_bucket(Bucket=self.template_bucket_name)
            else:
                self.s3_client.create_bucket(
                    Bucket=self.template_bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": self.region},
                )

            # Note: Bucket is private by default, no need to set ACL
            # AWS is deprecating ACLs in favor of bucket policies

            # Upload the template file
            print_info(f"Uploading template to S3...")
            self.s3_client.upload_file(
                self.TEMPLATE_PATH,
                self.template_bucket_name,
                template_key,
                ExtraArgs={"ContentType": "application/x-yaml"},
            )

            # Generate the S3 URL
            template_url = f"https://{self.template_bucket_name}.s3.{self.region}.amazonaws.com/{template_key}"
            print_success(f"Template uploaded to: {template_url}")

            return template_url

        except ClientError as e:
            logger.error(f"Failed to create/upload S3 bucket: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during template upload: {e}")
            raise

    def _cleanup_template_bucket(self) -> None:
        """
        Clean up the temporary S3 bucket used for template storage.

        This method deletes all objects in the template bucket and then
        deletes the bucket itself. It handles errors gracefully.
        """
        if not hasattr(self, "template_bucket_name") or not self.template_bucket_name:
            return

        try:
            print_info(f"Cleaning up template bucket: {self.template_bucket_name}")

            # Delete all objects in the bucket
            objects = self.s3_client.list_objects_v2(Bucket=self.template_bucket_name)
            if "Contents" in objects:
                delete_keys = [{"Key": obj["Key"]} for obj in objects["Contents"]]
                self.s3_client.delete_objects(
                    Bucket=self.template_bucket_name, Delete={"Objects": delete_keys}
                )

            # Delete the bucket
            self.s3_client.delete_bucket(Bucket=self.template_bucket_name)
            print_success(f"Template bucket cleaned up successfully")

        except Exception as e:
            logger.warning(
                f"Failed to cleanup template bucket (this is non-critical): {e}"
            )
            print_warning(
                f"Could not cleanup template bucket: {self.template_bucket_name}"
            )

    def _load_template(self) -> str:
        """
        Load the CloudFormation template and upload to S3.

        This method uploads the template to S3 and returns the S3 URL
        to avoid CloudFormation's 51,200 byte template body limit.

        Returns:
            S3 URL of the uploaded template

        Raises:
            FileNotFoundError: If template file doesn't exist
            Exception: If template upload fails
        """
        if not os.path.exists(self.TEMPLATE_PATH):
            raise FileNotFoundError(f"Template file not found: {self.TEMPLATE_PATH}")

        # Upload template to S3 and return URL
        return self._upload_template_to_s3()

    def _stream_stack_events(self, stack_name: str) -> None:
        """
        Stream CloudFormation stack events in real-time.

        Args:
            stack_name: Name of the stack to monitor
        """
        print_info("Streaming stack events...")
        print()

        seen_events = set()
        last_timestamp = None

        while True:
            try:
                # Get stack status
                stack = self.cf_client.describe_stacks(StackName=stack_name)["Stacks"][
                    0
                ]
                stack_status = stack["StackStatus"]

                # Get events
                events = self.cf_client.describe_stack_events(StackName=stack_name)[
                    "StackEvents"
                ]

                # Print new events
                for event in reversed(events):
                    event_id = event["EventId"]
                    timestamp = event["Timestamp"]

                    if event_id not in seen_events:
                        event_time = timestamp.strftime("%H:%M:%S")
                        resource_type = event["ResourceType"]
                        logical_id = event["LogicalResourceId"]
                        resource_status = event["ResourceStatus"]

                        # Color code based on status
                        if "FAILED" in resource_status or "ERROR" in resource_status:
                            color = Colors.RED
                            symbol = "✗"
                        elif "COMPLETE" in resource_status:
                            color = Colors.GREEN
                            symbol = "✓"
                        elif "IN_PROGRESS" in resource_status:
                            color = Colors.YELLOW
                            symbol = "⟳"
                        else:
                            color = Colors.CYAN
                            symbol = "•"

                        print_colored(
                            f"[{event_time}] {symbol} {logical_id} ({resource_type}): {resource_status}",
                            color,
                        )

                        seen_events.add(event_id)
                        last_timestamp = timestamp

                # Check if stack operation is complete
                if stack_status.endswith("COMPLETE") or stack_status.endswith("FAILED"):
                    print()
                    break

                # Wait before next poll
                time.sleep(5)

            except ClientError as e:
                if e.response["Error"]["Code"] == "ValidationError":
                    # Stack doesn't exist yet
                    time.sleep(2)
                    continue
                raise

    def _print_stack_outputs(self, stack_name: str) -> None:
        """
        Print all stack outputs in a formatted table.

        Args:
            stack_name: Name of the stack
        """
        try:
            stack = self.cf_client.describe_stacks(StackName=stack_name)["Stacks"][0]
            outputs = stack.get("Outputs", [])

            if not outputs:
                print_warning("No outputs available for this stack.")
                return

            print_header("Stack Outputs")

            # Calculate column widths
            max_key_len = max(len(output.get("OutputKey", "")) for output in outputs)
            max_value_len = max(
                len(output.get("OutputValue", "")) for output in outputs
            )
            max_desc_len = max(len(output.get("Description", "")) for output in outputs)

            # Print header
            key_header = "Output Key"
            value_header = "Output Value"
            desc_header = "Description"

            print_colored(
                f"{key_header:<{max_key_len}}  {value_header:<{max_value_len}}  {desc_header}",
                Colors.BOLD + Colors.CYAN,
            )
            print_colored(
                f"{'-' * max_key_len}  {'-' * max_value_len}  {'-' * max_desc_len}",
                Colors.CYAN,
            )

            # Print outputs
            for output in outputs:
                key = output.get("OutputKey", "")
                value = output.get("OutputValue", "")
                desc = output.get("Description", "")

                print(f"{key:<{max_key_len}}  {value:<{max_value_len}}  {desc}")

            print()

        except ClientError as e:
            logger.error(f"Failed to get stack outputs: {e}")
            print_error(f"Failed to retrieve stack outputs: {e}")

    def _get_deployment_parameters(
        self, config_type: str, alert_email: str, environment: str
    ) -> Dict[str, str]:
        """
        Get CloudFormation deployment parameters based on configuration type.

        Args:
            config_type: Type of deployment configuration
            alert_email: Email address for alerts
            environment: Environment name (dev/staging/prod)

        Returns:
            Dictionary of parameter names to values
        """
        parameters = {
            "Environment": environment,
            "AlertEmail": alert_email,
            "EnableAIAnalysis": "false",
            "EnableRemediation": "DRY_RUN",
            "RetentionDays": "180",
        }

        if config_type in ["ai_only", "full_platform"]:
            parameters["EnableAIAnalysis"] = "true"

        if config_type in ["remediation_only", "full_platform"]:
            parameters["EnableRemediation"] = "AUTO"

        return parameters

    def _print_cost_estimate(self, config_type: str) -> None:
        """
        Print the cost estimate for a configuration type.

        Args:
            config_type: Type of deployment configuration
        """
        estimate = COST_ESTIMATES.get(
            config_type, COST_ESTIMATES["no_ai_no_remediation"]
        )

        print_header(f"Cost Estimate - {estimate['name']}")
        print_colored(
            f"Estimated Monthly Cost: {estimate['cost']:.2f}",
            Colors.BOLD + Colors.GREEN,
        )
        print()
        print_colored("Cost Breakdown:", Colors.BOLD)

        for item, cost in estimate["breakdown"].items():
            print(f"  • {item}: {cost}")

        print()
        print_warning(
            "Note: These are estimates based on typical usage. Actual costs may vary."
        )
        print()

    def deploy_stack(
        self, config_type: str, alert_email: str, environment: str
    ) -> bool:
        """
        Deploy a new CloudFormation stack.

        Args:
            config_type: Type of deployment configuration
            alert_email: Email address for alerts
            environment: Environment name (dev/staging/prod)

        Returns:
            True if deployment succeeded, False otherwise
        """
        try:
            # Print cost estimate
            self._print_cost_estimate(config_type)

            # Confirm deployment
            print_colored("Ready to deploy stack?", Colors.BOLD + Colors.YELLOW)
            response = input("Continue? (yes/no): ").strip().lower()

            if response not in ["yes", "y"]:
                print_info("Deployment cancelled.")
                return False

            # Load template
            print_info("Loading CloudFormation template...")
            template_url = self._load_template()

            # Get parameters
            parameters = self._get_deployment_parameters(
                config_type, alert_email, environment
            )

            # Convert to CloudFormation format
            cf_parameters = [
                {"ParameterKey": key, "ParameterValue": value}
                for key, value in parameters.items()
            ]

            # Create stack
            print_info(f"Creating stack: {self.STACK_NAME}")
            print()

            self.cf_client.create_stack(
                StackName=self.STACK_NAME,
                TemplateURL=template_url,
                Parameters=cf_parameters,
                Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
                Tags=[
                    {"Key": "Platform", "Value": "GRC-Evidence-Platform"},
                    {"Key": "Environment", "Value": environment},
                    {"Key": "ConfigType", "Value": config_type},
                    {"Key": "ManagedBy", "Value": "deploy_cloudformation.py"},
                    {"Key": "DeployedAt", "Value": datetime.now().isoformat()},
                ],
                OnFailure="ROLLBACK",
            )

            # Stream events
            self._stream_stack_events(self.STACK_NAME)

            # Check final status
            stack = self.cf_client.describe_stacks(StackName=self.STACK_NAME)["Stacks"][
                0
            ]
            status = stack["StackStatus"]

            if status == "CREATE_COMPLETE":
                print_success(f"Stack {self.STACK_NAME} created successfully!")
                print()
                self._print_stack_outputs(self.STACK_NAME)
                # Cleanup template bucket after successful deployment
                self._cleanup_template_bucket()
                return True
            else:
                print_error(f"Stack creation failed with status: {status}")
                # Cleanup template bucket even on failure
                self._cleanup_template_bucket()
                return False

        except ClientError as e:
            logger.error(f"CloudFormation error: {e}")
            print_error(f"Deployment failed: {e}")
            # Cleanup template bucket on error
            self._cleanup_template_bucket()
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print_error(f"Unexpected error: {e}")
            # Cleanup template bucket on error
            self._cleanup_template_bucket()
            return False

    def update_stack(
        self, alert_email: Optional[str] = None, environment: Optional[str] = None
    ) -> bool:
        """
        Update an existing CloudFormation stack.

        Args:
            alert_email: New email address for alerts (optional)
            environment: New environment name (optional)

        Returns:
            True if update succeeded, False otherwise
        """
        try:
            # Check if stack exists
            try:
                stack = self.cf_client.describe_stacks(StackName=self.STACK_NAME)[
                    "Stacks"
                ][0]
            except self.cf_client.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "ValidationError":
                    print_error(f"Stack {self.STACK_NAME} does not exist.")
                    return False
                raise

            print_info(f"Updating stack: {self.STACK_NAME}")

            # Load template
            template_url = self._load_template()

            # Get current parameters
            current_params = {
                param["ParameterKey"]: param.get("ParameterValue", "")
                for param in stack.get("Parameters", [])
            }

            # Update parameters if provided
            if alert_email:
                current_params["AlertEmail"] = alert_email
            if environment:
                current_params["Environment"] = environment

            # Convert to CloudFormation format
            cf_parameters = [
                {"ParameterKey": key, "ParameterValue": value}
                for key, value in current_params.items()
            ]

            # Update stack
            self.cf_client.update_stack(
                StackName=self.STACK_NAME,
                TemplateURL=template_url,
                Parameters=cf_parameters,
                Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            )

            # Stream events
            self._stream_stack_events(self.STACK_NAME)

            # Check final status
            stack = self.cf_client.describe_stacks(StackName=self.STACK_NAME)["Stacks"][
                0
            ]
            status = stack["StackStatus"]

            if status == "UPDATE_COMPLETE":
                print_success(f"Stack {self.STACK_NAME} updated successfully!")
                print()
                self._print_stack_outputs(self.STACK_NAME)
                # Cleanup template bucket after successful update
                self._cleanup_template_bucket()
                return True
            else:
                print_error(f"Stack update failed with status: {status}")
                # Cleanup template bucket even on failure
                self._cleanup_template_bucket()
                return False

        except ClientError as e:
            logger.error(f"CloudFormation error: {e}")
            print_error(f"Update failed: {e}")
            # Cleanup template bucket on error
            self._cleanup_template_bucket()
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print_error(f"Unexpected error: {e}")
            # Cleanup template bucket on error
            self._cleanup_template_bucket()
            return False

    def delete_stack(self) -> bool:
        """
        Delete an existing CloudFormation stack.

        Returns:
            True if deletion succeeded, False otherwise
        """
        try:
            # Check if stack exists
            try:
                stack = self.cf_client.describe_stacks(StackName=self.STACK_NAME)[
                    "Stacks"
                ][0]
            except self.cf_client.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "ValidationError":
                    print_error(f"Stack {self.STACK_NAME} does not exist.")
                    return False
                raise

            # Confirm deletion
            print_warning(f"You are about to delete stack: {self.STACK_NAME}")
            print_warning("This action cannot be undone!")
            response = input("Are you sure? (yes/no): ").strip().lower()

            if response not in ["yes", "y"]:
                print_info("Deletion cancelled.")
                return False

            print_info(f"Deleting stack: {self.STACK_NAME}")

            # Delete stack
            self.cf_client.delete_stack(StackName=self.STACK_NAME)

            # Stream events
            self._stream_stack_events(self.STACK_NAME)

            # Check if deleted
            try:
                self.cf_client.describe_stacks(StackName=self.STACK_NAME)
                print_error("Stack deletion may still be in progress.")
                return False
            except self.cf_client.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "ValidationError":
                    print_success(f"Stack {self.STACK_NAME} deleted successfully!")
                    return True
                raise

        except ClientError as e:
            logger.error(f"CloudFormation error: {e}")
            print_error(f"Deletion failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print_error(f"Unexpected error: {e}")
            return False

    def view_outputs(self) -> bool:
        """
        View and display all stack outputs.

        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if stack exists
            try:
                self.cf_client.describe_stacks(StackName=self.STACK_NAME)
            except self.cf_client.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "ValidationError":
                    print_error(f"Stack {self.STACK_NAME} does not exist.")
                    return False
                raise

            self._print_stack_outputs(self.STACK_NAME)
            return True

        except ClientError as e:
            logger.error(f"CloudFormation error: {e}")
            print_error(f"Failed to view outputs: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print_error(f"Unexpected error: {e}")
            return False

    def view_cost_estimate(self) -> bool:
        """
        Display cost breakdown for all configurations.

        Returns:
            True if successful, False otherwise
        """
        try:
            print_header("Deployment Cost Estimates")

            for config_type, estimate in COST_ESTIMATES.items():
                print_colored(f"\n{estimate['name']}", Colors.BOLD + Colors.GREEN)
                print_colored(
                    f"Estimated Monthly Cost: ${estimate['cost']:.2f}", Colors.CYAN
                )
                print()
                print("Cost Breakdown:")
                for item, cost in estimate["breakdown"].items():
                    print(f"  • {item}: {cost}")

            print()
            print_warning("Note: These are estimates based on typical usage patterns:")
            print("  - Lambda: 100,000 invocations/month")
            print("  - EventBridge: 4 rules")
            print("  - S3: 10 GB storage")
            print("  - DynamoDB: 10 GB data, 5 million reads/writes")
            print("  - CloudWatch: 5 GB logs")
            print()
            print_colored("Actual costs may vary based on your usage.", Colors.YELLOW)
            print()

            return True

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print_error(f"Unexpected error: {e}")
            return False

    def show_menu(self) -> None:
        """
        Display the interactive menu and handle user input.
        """
        while True:
            print_header("GRC Evidence Platform - CloudFormation Deployment Menu")

            print_colored(
                "1. Deploy: No AI, No Auto-Remediation ($0.00/month)", Colors.WHITE
            )
            print_colored(
                "2. Deploy: With AI Analysis only (~$0.78/month)", Colors.WHITE
            )
            print_colored(
                "3. Deploy: With Auto-Remediation only ($0.00/month)", Colors.WHITE
            )
            print_colored(
                "4. Deploy: Full Platform — AI + Auto-Remediation (~$0.78/month) ⭐ RECOMMENDED",
                Colors.GREEN + Colors.BOLD,
            )
            print_colored("5. Update existing stack", Colors.YELLOW)
            print_colored("6. Delete stack", Colors.RED)
            print_colored("7. View stack outputs", Colors.CYAN)
            print_colored("8. View deployment cost estimate", Colors.MAGENTA)
            print_colored("0. Exit", Colors.WHITE)
            print()

            choice = input("Select an option (0-8): ").strip()

            if choice == "0":
                print_info("Exiting...")
                break

            elif choice == "1":
                alert_email = input(
                    "Enter alert email (optional, press Enter to skip): "
                ).strip()
                environment = (
                    input("Enter environment (dev/staging/prod) [dev]: ").strip()
                    or "dev"
                )
                self.deploy_stack("no_ai_no_remediation", alert_email, environment)

            elif choice == "2":
                alert_email = input(
                    "Enter alert email (optional, press Enter to skip): "
                ).strip()
                environment = (
                    input("Enter environment (dev/staging/prod) [dev]: ").strip()
                    or "dev"
                )
                self.deploy_stack("ai_only", alert_email, environment)

            elif choice == "3":
                alert_email = input(
                    "Enter alert email (optional, press Enter to skip): "
                ).strip()
                environment = (
                    input("Enter environment (dev/staging/prod) [dev]: ").strip()
                    or "dev"
                )
                self.deploy_stack("remediation_only", alert_email, environment)

            elif choice == "4":
                alert_email = input(
                    "Enter alert email (optional, press Enter to skip): "
                ).strip()
                environment = (
                    input("Enter environment (dev/staging/prod) [dev]: ").strip()
                    or "dev"
                )
                self.deploy_stack("full_platform", alert_email, environment)

            elif choice == "5":
                alert_email = (
                    input(
                        "Enter new alert email (press Enter to keep current): "
                    ).strip()
                    or None
                )
                environment = (
                    input(
                        "Enter new environment (press Enter to keep current): "
                    ).strip()
                    or None
                )
                if alert_email is None and environment is None:
                    print_warning("No changes specified.")
                else:
                    self.update_stack(alert_email, environment)

            elif choice == "6":
                self.delete_stack()

            elif choice == "7":
                self.view_outputs()

            elif choice == "8":
                self.view_cost_estimate()

            else:
                print_error("Invalid option. Please select 0-8.")

            # Pause before showing menu again
            if choice != "0":
                input("\nPress Enter to continue...")


def main() -> None:
    """
    Main entry point for the CloudFormation deployment script.
    """
    parser = argparse.ArgumentParser(
        description="Deploy the GRC Evidence Platform v2.0 using CloudFormation"
    )
    parser.add_argument(
        "--region",
        help="AWS region to deploy to (default: from AWS_DEFAULT_REGION or us-east-1)",
        default=None,
    )
    parser.add_argument(
        "--profile", help="AWS profile name to use (default: default)", default=None
    )
    parser.add_argument(
        "--deploy",
        help="Deploy stack with specified config type (no_ai_no_remediation, ai_only, remediation_only, full_platform)",
        choices=[
            "no_ai_no_remediation",
            "ai_only",
            "remediation_only",
            "full_platform",
        ],
        default=None,
    )
    parser.add_argument("--alert-email", help="Email address for alerts", default=None)
    parser.add_argument(
        "--environment", help="Environment name (dev/staging/prod)", default="dev"
    )
    parser.add_argument("--update", help="Update existing stack", action="store_true")
    parser.add_argument("--delete", help="Delete existing stack", action="store_true")
    parser.add_argument("--outputs", help="View stack outputs", action="store_true")
    parser.add_argument(
        "--cost-estimate", help="View cost estimates", action="store_true"
    )

    args = parser.parse_args()

    try:
        deployer = CloudFormationDeployer(region=args.region, profile=args.profile)

        # Handle command-line mode
        if args.deploy:
            alert_email = args.alert_email or ""
            environment = args.environment
            success = deployer.deploy_stack(args.deploy, alert_email, environment)
            sys.exit(0 if success else 1)
        elif args.update:
            success = deployer.update_stack(args.alert_email, args.environment)
            sys.exit(0 if success else 1)
        elif args.delete:
            success = deployer.delete_stack()
            sys.exit(0 if success else 1)
        elif args.outputs:
            success = deployer.view_outputs()
            sys.exit(0 if success else 1)
        elif args.cost_estimate:
            success = deployer.view_cost_estimate()
            sys.exit(0 if success else 1)
        else:
            # Interactive mode
            deployer.show_menu()

    except NoCredentialsError:
        print_error("AWS credentials not found. Please configure your credentials.")
        print_colored(
            "Run 'aws configure' or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.",
            Colors.CYAN,
        )
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
