#!/usr/bin/env python3
"""
GRC Evidence Platform v2.0 - Teardown Script

This script provides complete resource removal for the GRC Evidence Platform.
It deletes resources in the correct reverse dependency order and is idempotent,
handling resources that don't exist gracefully.

Usage:
    python scripts/teardown.py

Author: GRC Platform Team
Version: 2.0
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("grc_teardown.log"),
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


class GRCTeardown:
    """
    Main class for tearing down the GRC Evidence Platform.

    This class provides methods to delete all platform resources in the correct
    reverse dependency order, with idempotent operations and graceful error handling.
    """

    CONFIG_FILE = "grc_config.json"
    PREFIX = "grc-evidence-platform"

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize the GRC Platform Teardown.

        Args:
            region: AWS region to teardown from (default: from environment or us-east-1)
            profile: AWS profile name to use (default: default)
        """
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.session = boto3.Session(region_name=self.region, profile_name=profile)

        # Initialize AWS clients
        self.events_client = self.session.client("events")
        self.lambda_client = self.session.client("lambda")
        self.cloudtrail_client = self.session.client("cloudtrail")
        self.config_client = self.session.client("config")
        self.securityhub_client = self.session.client("securityhub")
        self.guardduty_client = self.session.client("guardduty")
        self.macie_client = self.session.client("macie2")
        self.sns_client = self.session.client("sns")
        self.iam_client = self.session.client("iam")
        self.dynamodb_client = self.session.client("dynamodb")
        self.s3_client = self.session.client("s3")
        self.kms_client = self.session.client("kms")
        self.sts_client = self.session.client("sts")
        self.cloudwatch_client = self.session.client("cloudwatch")
        self.cloudformation_client = self.session.client("cloudformation")

        # Get account ID
        self.account_id = self._get_account_id()

        # Load configuration
        self.config = self._load_config()

        # Track deleted resources
        self.deleted_resources: List[Dict[str, str]] = []

        # Track failed deletions
        self.failed_deletions: List[Dict[str, str]] = []

        print_header(f"GRC Evidence Platform v2.0 - Teardown")
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

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from grc_config.json if it exists.

        Returns:
            Configuration dictionary
        """
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, "r") as f:
                    config = json.load(f)
                print_info(f"Loaded configuration from {self.CONFIG_FILE}")
                return config
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")

        # Return default config structure
        return {"account_id": self.account_id, "region": self.region, "resources": {}}

    def _track_deletion(
        self, resource_type: str, resource_name: str, success: bool
    ) -> None:
        """
        Track a resource deletion.

        Args:
            resource_type: Type of resource deleted
            resource_name: Name/ARN of the resource
            success: Whether the deletion was successful
        """
        record = {
            "type": resource_type,
            "name": resource_name,
            "timestamp": time.time(),
        }

        if success:
            self.deleted_resources.append(record)
        else:
            self.failed_deletions.append(record)

    def _get_resource_names(self) -> Dict[str, str]:
        """
        Get resource names from config or generate them.

        Returns:
            Dictionary of resource types to names
        """
        resources = self.config.get("resources", {})

        # Generate names if not in config
        names = {
            "eventbridge_rules": [
                f"{self.PREFIX}-cloudtrail-rule",
                f"{self.PREFIX}-daily-scorecard-rule",
                f"{self.PREFIX}-hourly-aging-rule",
                f"{self.PREFIX}-weekly-report-rule",
            ],
            "lambda_functions": [
                f"{self.PREFIX}-evidence-processor",
                f"{self.PREFIX}-remediation-engine",
                f"{self.PREFIX}-scorecard-generator",
                f"{self.PREFIX}-aging-monitor",
                f"{self.PREFIX}-report-exporter",
                f"{self.PREFIX}-start-config-recorder",
            ],
            "cloudtrail": f"{self.PREFIX}-compliance-trail",
            "config_recorder": "default",
            "config_channel": "default",
            "config_role": f"{self.PREFIX}-config-role",
            "securityhub": "hub",
            "guardduty": "detector",
            "macie": "session",
            "sns_topic": f"{self.PREFIX}-alerts",
            "iam_roles": [
                f"{self.PREFIX}-evidence-processor",
                f"{self.PREFIX}-remediation-engine",
                f"{self.PREFIX}-scorecard-generator",
                f"{self.PREFIX}-aging-monitor",
                f"{self.PREFIX}-report-exporter",
                f"{self.PREFIX}-config-role",
                f"{self.PREFIX}-start-config-recorder",
            ],
            "dynamodb_tables": [
                f"{self.PREFIX}-metadata-dev",
                f"{self.PREFIX}-remediation-logs-dev",
                f"{self.PREFIX}-scorecards-dev",
                f"{self.PREFIX}-pending-events-dev",
            ],
            "s3_buckets": [
                f"{self.PREFIX}-evidence-{self.account_id}-{self.region}",
                f"{self.PREFIX}-cloudtrail-{self.account_id}-{self.region}",
                f"{self.PREFIX}-reports-{self.account_id}-{self.region}",
                f"{self.PREFIX}-config-{self.account_id}-{self.region}",
            ],
            "kms_key": f"alias/{self.PREFIX}-grc-key",
            "cloudwatch_alarms": [
                f"{self.PREFIX}-lambda-error-rate-alarm",
                f"{self.PREFIX}-lambda-duration-alarm",
                f"{self.PREFIX}-lambda-throttle-alarm",
                f"{self.PREFIX}-dynamodb-read-throttle-alarm",
                f"{self.PREFIX}-dynamodb-write-throttle-alarm",
                f"{self.PREFIX}-sns-publish-failed-alarm",
            ],
            "config_conformance_packs": [
                f"{self.PREFIX}-cis-aws-foundations",
                f"{self.PREFIX}-nist-csf",
                f"{self.PREFIX}-pci-dss",
                f"{self.PREFIX}-nist-800-53",
                f"{self.PREFIX}-aws-security-pillar",
                f"{self.PREFIX}-hipaa-security",
                f"{self.PREFIX}-cmmc-level2",
                f"{self.PREFIX}-fedramp-moderate",
                f"{self.PREFIX}-soc2",
                f"{self.PREFIX}-nist-800-171",
            ],
        }

        # Override with config values if present
        for key, value in resources.items():
            if key in names:
                names[key] = value

        return names

    def delete_eventbridge_rules(self) -> bool:
        """
        Delete EventBridge rules.

        Returns:
            True if all deletions succeeded or rules didn't exist
        """
        print_info("Deleting EventBridge rules...")
        names = self._get_resource_names()
        rules = names.get("eventbridge_rules", [])

        all_success = True
        for rule_name in rules:
            try:
                # Remove targets first
                try:
                    targets = self.events_client.list_targets_by_rule(Rule=rule_name)
                    if targets.get("Targets"):
                        self.events_client.remove_targets(
                            Rule=rule_name, Ids=[t["Id"] for t in targets["Targets"]]
                        )
                except self.events_client.exceptions.ResourceNotFoundException:
                    pass
                except Exception as e:
                    logger.debug(f"Error removing targets for {rule_name}: {e}")

                # Delete rule
                self.events_client.delete_rule(Name=rule_name)
                print_success(f"Deleted EventBridge rule: {rule_name}")
                self._track_deletion("eventbridge_rule", rule_name, True)

            except self.events_client.exceptions.ResourceNotFoundException:
                print_info(f"EventBridge rule not found: {rule_name}")
                self._track_deletion("eventbridge_rule", rule_name, True)
            except Exception as e:
                logger.error(f"Failed to delete EventBridge rule {rule_name}: {e}")
                print_error(f"Failed to delete EventBridge rule {rule_name}: {e}")
                self._track_deletion("eventbridge_rule", rule_name, False)
                all_success = False

        return all_success

    def delete_lambda_functions(self) -> bool:
        """
        Delete Lambda functions.

        Returns:
            True if all deletions succeeded or functions didn't exist
        """
        print_info("Deleting Lambda functions...")
        names = self._get_resource_names()
        functions = names.get("lambda_functions", [])

        all_success = True
        for function_name in functions:
            try:
                # Delete event source mappings
                try:
                    mappings = self.lambda_client.list_event_source_mappings(
                        FunctionName=function_name
                    )
                    for mapping in mappings.get("EventSourceMappings", []):
                        self.lambda_client.delete_event_source_mapping(
                            UUID=mapping["UUID"]
                        )
                except Exception as e:
                    logger.debug(
                        f"Error deleting event source mappings for {function_name}: {e}"
                    )

                # Delete function
                self.lambda_client.delete_function(FunctionName=function_name)
                print_success(f"Deleted Lambda function: {function_name}")
                self._track_deletion("lambda_function", function_name, True)

            except self.lambda_client.exceptions.ResourceNotFoundException:
                print_info(f"Lambda function not found: {function_name}")
                self._track_deletion("lambda_function", function_name, True)
            except Exception as e:
                logger.error(f"Failed to delete Lambda function {function_name}: {e}")
                print_error(f"Failed to delete Lambda function {function_name}: {e}")
                self._track_deletion("lambda_function", function_name, False)
                all_success = False

        return all_success

    def delete_cloudtrail(self) -> bool:
        """
        Delete CloudTrail.

        Returns:
            True if deletion succeeded or CloudTrail didn't exist
        """
        print_info("Deleting CloudTrail...")
        names = self._get_resource_names()
        trail_name = names.get("cloudtrail", f"{self.PREFIX}-trail")

        try:
            # Stop logging
            try:
                self.cloudtrail_client.stop_logging(Name=trail_name)
            except self.cloudtrail_client.exceptions.TrailNotFoundException:
                pass
            except Exception as e:
                logger.debug(f"Error stopping CloudTrail logging: {e}")

            # Delete trail
            self.cloudtrail_client.delete_trail(Name=trail_name)
            print_success(f"Deleted CloudTrail: {trail_name}")
            self._track_deletion("cloudtrail", trail_name, True)
            return True

        except self.cloudtrail_client.exceptions.TrailNotFoundException:
            print_info(f"CloudTrail not found: {trail_name}")
            self._track_deletion("cloudtrail", trail_name, True)
            return True
        except Exception as e:
            logger.error(f"Failed to delete CloudTrail {trail_name}: {e}")
            print_error(f"Failed to delete CloudTrail {trail_name}: {e}")
            self._track_deletion("cloudtrail", trail_name, False)
            return False

    def delete_config(self) -> bool:
        """
        Delete AWS Config recorder and delivery channel.

        Returns:
            True if all deletions succeeded or Config didn't exist
        """
        print_info("Deleting AWS Config...")
        names = self._get_resource_names()
        recorder_name = names.get("config_recorder", f"{self.PREFIX}-recorder")
        channel_name = names.get("config_channel", f"{self.PREFIX}-channel")

        all_success = True

        # Stop and delete recorder
        try:
            self.config_client.stop_configuration_recorder(
                ConfigurationRecorderName=recorder_name
            )
        except self.config_client.exceptions.NoSuchConfigurationRecorderException:
            print_info(f"Config recorder not found: {recorder_name}")
        except Exception as e:
            logger.debug(f"Error stopping Config recorder: {e}")

        try:
            self.config_client.delete_configuration_recorder(
                ConfigurationRecorderName=recorder_name
            )
            print_success(f"Deleted Config recorder: {recorder_name}")
            self._track_deletion("config_recorder", recorder_name, True)
        except self.config_client.exceptions.NoSuchConfigurationRecorderException:
            print_info(f"Config recorder not found: {recorder_name}")
            self._track_deletion("config_recorder", recorder_name, True)
        except Exception as e:
            logger.error(f"Failed to delete Config recorder: {e}")
            print_error(f"Failed to delete Config recorder: {e}")
            self._track_deletion("config_recorder", recorder_name, False)
            all_success = False

        # Delete delivery channel
        try:
            self.config_client.delete_delivery_channel(DeliveryChannelName=channel_name)
            print_success(f"Deleted Config delivery channel: {channel_name}")
            self._track_deletion("config_channel", channel_name, True)
        except self.config_client.exceptions.NoSuchDeliveryChannelException:
            print_info(f"Config delivery channel not found: {channel_name}")
            self._track_deletion("config_channel", channel_name, True)
        except Exception as e:
            logger.error(f"Failed to delete Config delivery channel: {e}")
            print_error(f"Failed to delete Config delivery channel: {e}")
            self._track_deletion("config_channel", channel_name, False)
            all_success = False

        return all_success

    def disable_securityhub(self) -> bool:
        """
        Disable Security Hub standards and hub.

        Returns:
            True if disablement succeeded or Security Hub wasn't enabled
        """
        print_info("Disabling Security Hub...")

        try:
            # List and disable standards
            try:
                standards = self.securityhub_client.list_standards()
                for standard in standards.get("StandardsSubscriptions", []):
                    try:
                        self.securityhub_client.batch_disable_standards(
                            StandardsSubscriptionArns=[
                                standard["StandardsSubscriptionArn"]
                            ]
                        )
                        print_success(
                            f"Disabled Security Hub standard: {standard['StandardsArn']}"
                        )
                    except Exception as e:
                        logger.debug(f"Error disabling standard: {e}")
            except self.securityhub_client.exceptions.InvalidAccessException:
                print_info("Security Hub not enabled")
                self._track_deletion("securityhub", "standards", True)
                return True
            except Exception as e:
                logger.debug(f"Error listing Security Hub standards: {e}")

            # Disable Security Hub
            self.securityhub_client.disable_security_hub()
            print_success("Disabled Security Hub")
            self._track_deletion("securityhub", "hub", True)
            return True

        except self.securityhub_client.exceptions.InvalidAccessException:
            print_info("Security Hub not enabled")
            self._track_deletion("securityhub", "hub", True)
            return True
        except Exception as e:
            logger.error(f"Failed to disable Security Hub: {e}")
            print_error(f"Failed to disable Security Hub: {e}")
            self._track_deletion("securityhub", "hub", False)
            return False

    def disable_guardduty(self) -> bool:
        """
        Disable GuardDuty detector.

        Returns:
            True if disablement succeeded or GuardDuty wasn't enabled
        """
        print_info("Disabling GuardDuty...")

        try:
            # List detectors
            response = self.guardduty_client.list_detectors()
            detector_ids = response.get("DetectorIds", [])

            if not detector_ids:
                print_info("GuardDuty not enabled")
                self._track_deletion("guardduty", "detector", True)
                return True

            # Delete all detectors
            for detector_id in detector_ids:
                self.guardduty_client.delete_detector(DetectorId=detector_id)
                print_success(f"Disabled GuardDuty detector: {detector_id}")
                self._track_deletion("guardduty", detector_id, True)

            return True

        except Exception as e:
            logger.error(f"Failed to disable GuardDuty: {e}")
            print_error(f"Failed to disable GuardDuty: {e}")
            self._track_deletion("guardduty", "detector", False)
            return False

    def disable_macie(self) -> bool:
        """
        Disable Macie.

        Returns:
            True if disablement succeeded or Macie wasn't enabled
        """
        print_info("Disabling Macie...")

        try:
            # Disable Macie
            self.macie_client.disable_macie()
            print_success("Disabled Macie")
            self._track_deletion("macie", "session", True)
            return True

        except self.macie_client.exceptions.ResourceNotFoundException:
            print_info("Macie not enabled")
            self._track_deletion("macie", "session", True)
            return True
        except Exception as e:
            logger.error(f"Failed to disable Macie: {e}")
            print_error(f"Failed to disable Macie: {e}")
            self._track_deletion("macie", "session", False)
            return False

    def delete_sns_topic(self) -> bool:
        """
        Delete SNS topic.

        Returns:
            True if deletion succeeded or topic didn't exist
        """
        print_info("Deleting SNS topic...")
        names = self._get_resource_names()
        topic_name = names.get("sns_topic", f"{self.PREFIX}-alerts")

        try:
            # Find topic ARN
            response = self.sns_client.list_topics()
            topic_arn = None
            for topic in response.get("Topics", []):
                if topic_name in topic["TopicArn"]:
                    topic_arn = topic["TopicArn"]
                    break

            if not topic_arn:
                print_info(f"SNS topic not found: {topic_name}")
                self._track_deletion("sns_topic", topic_name, True)
                return True

            # Delete topic
            self.sns_client.delete_topic(TopicArn=topic_arn)
            print_success(f"Deleted SNS topic: {topic_name}")
            self._track_deletion("sns_topic", topic_name, True)
            return True

        except self.sns_client.exceptions.NotFoundException:
            print_info(f"SNS topic not found: {topic_name}")
            self._track_deletion("sns_topic", topic_name, True)
            return True
        except Exception as e:
            logger.error(f"Failed to delete SNS topic {topic_name}: {e}")
            print_error(f"Failed to delete SNS topic {topic_name}: {e}")
            self._track_deletion("sns_topic", topic_name, False)
            return False

    def delete_iam_roles(self) -> bool:
        """
        Delete IAM roles.

        Returns:
            True if all deletions succeeded or roles didn't exist
        """
        print_info("Deleting IAM roles...")
        names = self._get_resource_names()
        roles = names.get("iam_roles", [])

        all_success = True
        for role_name in roles:
            try:
                # Detach managed policies
                try:
                    attached = self.iam_client.list_attached_role_policies(
                        RoleName=role_name
                    )
                    for policy in attached.get("AttachedPolicies", []):
                        self.iam_client.detach_role_policy(
                            RoleName=role_name, PolicyArn=policy["PolicyArn"]
                        )
                except self.iam_client.exceptions.NoSuchEntityException:
                    pass
                except Exception as e:
                    logger.debug(f"Error detaching policies from {role_name}: {e}")

                # Delete inline policies
                try:
                    inline = self.iam_client.list_role_policies(RoleName=role_name)
                    for policy_name in inline.get("PolicyNames", []):
                        self.iam_client.delete_role_policy(
                            RoleName=role_name, PolicyName=policy_name
                        )
                except self.iam_client.exceptions.NoSuchEntityException:
                    pass
                except Exception as e:
                    logger.debug(
                        f"Error deleting inline policies from {role_name}: {e}"
                    )

                # Delete role
                self.iam_client.delete_role(RoleName=role_name)
                print_success(f"Deleted IAM role: {role_name}")
                self._track_deletion("iam_role", role_name, True)

            except self.iam_client.exceptions.NoSuchEntityException:
                print_info(f"IAM role not found: {role_name}")
                self._track_deletion("iam_role", role_name, True)
            except Exception as e:
                logger.error(f"Failed to delete IAM role {role_name}: {e}")
                print_error(f"Failed to delete IAM role {role_name}: {e}")
                self._track_deletion("iam_role", role_name, False)
                all_success = False

        return all_success

    def delete_dynamodb_tables(self) -> bool:
        """
        Delete DynamoDB tables.

        Returns:
            True if all deletions succeeded or tables didn't exist
        """
        print_info("Deleting DynamoDB tables...")
        names = self._get_resource_names()
        tables = names.get("dynamodb_tables", [])

        # DIAGNOSTIC: List actual DynamoDB tables in the account
        logger.info("=== DIAGNOSTIC: Listing actual DynamoDB tables ===")
        try:
            actual_tables = self.dynamodb_client.list_tables()
            logger.info(
                f"Actual tables in account: {actual_tables.get('TableNames', [])}"
            )
        except Exception as e:
            logger.error(f"Failed to list DynamoDB tables: {e}")
        logger.info("=== END DIAGNOSTIC ===")

        all_success = True
        for table_name in tables:
            logger.info(f"Attempting to delete DynamoDB table: {table_name}")
            try:
                logger.info(f"Calling delete_table for: {table_name}")
                self.dynamodb_client.delete_table(TableName=table_name)
                logger.info(f"delete_table API call succeeded for: {table_name}")

                # Wait for table to be deleted
                try:
                    logger.info(f"Waiting for table deletion: {table_name}")
                    waiter = self.dynamodb_client.get_waiter("table_not_exists")
                    waiter.wait(TableName=table_name)
                    logger.info(f"Waiter completed successfully for: {table_name}")
                except Exception as e:
                    logger.warning(f"Waiter failed for {table_name}: {e}")

                print_success(f"Deleted DynamoDB table: {table_name}")
                self._track_deletion("dynamodb_table", table_name, True)

            except self.dynamodb_client.exceptions.ResourceNotFoundException:
                logger.warning(f"DynamoDB table not found: {table_name}")
                print_info(f"DynamoDB table not found: {table_name}")
                self._track_deletion("dynamodb_table", table_name, True)
            except Exception as e:
                logger.error(f"Failed to delete DynamoDB table {table_name}: {e}")
                print_error(f"Failed to delete DynamoDB table {table_name}: {e}")
                self._track_deletion("dynamodb_table", table_name, False)
                all_success = False

        return all_success

    def delete_s3_buckets(self) -> bool:
        """
        Delete S3 buckets after emptying them.

        Returns:
            True if all deletions succeeded or buckets didn't exist
        """
        print_info("Deleting S3 buckets...")
        names = self._get_resource_names()
        buckets = names.get("s3_buckets", [])

        # DIAGNOSTIC: List actual S3 buckets in the account
        logger.info("=== DIAGNOSTIC: Listing actual S3 buckets ===")
        try:
            actual_buckets = self.s3_client.list_buckets()
            bucket_names = [b["Name"] for b in actual_buckets.get("Buckets", [])]
            logger.info(f"Actual buckets in account: {bucket_names}")
        except Exception as e:
            logger.error(f"Failed to list S3 buckets: {e}")
        logger.info("=== END DIAGNOSTIC ===")

        all_success = True
        for bucket_name in buckets:
            logger.info(f"Attempting to delete S3 bucket: {bucket_name}")
            try:
                # Empty bucket
                print_info(f"Emptying bucket: {bucket_name}")
                logger.info(f"Starting to empty bucket: {bucket_name}")
                try:
                    # List and delete all objects
                    continuation_token = None
                    object_count = 0
                    while True:
                        list_kwargs = {"Bucket": bucket_name}
                        if continuation_token:
                            list_kwargs["ContinuationToken"] = continuation_token

                        response = self.s3_client.list_objects_v2(**list_kwargs)

                        if "Contents" in response:
                            delete_keys = [
                                {"Key": obj["Key"]} for obj in response["Contents"]
                            ]
                            if delete_keys:
                                logger.info(
                                    f"Deleting {len(delete_keys)} objects from {bucket_name}"
                                )
                                self.s3_client.delete_objects(
                                    Bucket=bucket_name, Delete={"Objects": delete_keys}
                                )
                                object_count += len(delete_keys)

                        if not response.get("IsTruncated"):
                            break
                        continuation_token = response.get("NextContinuationToken")

                    logger.info(
                        f"Total objects deleted from {bucket_name}: {object_count}"
                    )

                    # Delete all versions if versioning is enabled
                    try:
                        continuation_token = None
                        version_count = 0
                        while True:
                            list_kwargs = {"Bucket": bucket_name}
                            if continuation_token:
                                list_kwargs["VersionIdMarker"] = continuation_token

                            response = self.s3_client.list_object_versions(
                                **list_kwargs
                            )

                            delete_objects = []
                            for version in response.get("Versions", []):
                                delete_objects.append(
                                    {
                                        "Key": version["Key"],
                                        "VersionId": version["VersionId"],
                                    }
                                )
                            for marker in response.get("DeleteMarkers", []):
                                delete_objects.append(
                                    {
                                        "Key": marker["Key"],
                                        "VersionId": marker["VersionId"],
                                    }
                                )

                            if delete_objects:
                                logger.info(
                                    f"Deleting {len(delete_objects)} versions from {bucket_name}"
                                )
                                self.s3_client.delete_objects(
                                    Bucket=bucket_name,
                                    Delete={"Objects": delete_objects},
                                )
                                version_count += len(delete_objects)

                            if not response.get("IsTruncated"):
                                break
                            continuation_token = response.get("NextVersionIdMarker")
                        logger.info(
                            f"Total versions deleted from {bucket_name}: {version_count}"
                        )
                    except Exception as e:
                        logger.warning(f"Error deleting versions: {e}")

                except self.s3_client.exceptions.NoSuchBucket:
                    logger.warning(f"Bucket not found during emptying: {bucket_name}")
                    pass
                except Exception as e:
                    logger.error(f"Error emptying bucket: {e}")

                # Delete bucket
                logger.info(f"Calling delete_bucket for: {bucket_name}")
                self.s3_client.delete_bucket(Bucket=bucket_name)
                logger.info(f"delete_bucket API call succeeded for: {bucket_name}")
                print_success(f"Deleted S3 bucket: {bucket_name}")
                self._track_deletion("s3_bucket", bucket_name, True)

            except self.s3_client.exceptions.NoSuchBucket:
                logger.warning(f"S3 bucket not found: {bucket_name}")
                print_info(f"S3 bucket not found: {bucket_name}")
                self._track_deletion("s3_bucket", bucket_name, True)
            except Exception as e:
                logger.error(f"Failed to delete S3 bucket {bucket_name}: {e}")
                print_error(f"Failed to delete S3 bucket {bucket_name}: {e}")
                self._track_deletion("s3_bucket", bucket_name, False)
                all_success = False

        return all_success

    def delete_kms_key(self) -> bool:
        """
        Schedule KMS key for deletion.

        Returns:
            True if deletion was scheduled or key didn't exist
        """
        print_info("Scheduling KMS key for deletion...")
        names = self._get_resource_names()
        key_alias = names.get("kms_key", f"alias/{self.PREFIX}-key")

        try:
            # Get key ID from alias
            response = self.kms_client.describe_key(KeyId=key_alias)
            key_id = response["KeyMetadata"]["KeyId"]

            # Schedule for deletion (7-day waiting period)
            self.kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)

            print_success(
                f"Scheduled KMS key for deletion: {key_id} (will be deleted in 7 days)"
            )
            self._track_deletion("kms_key", key_id, True)
            return True

        except self.kms_client.exceptions.NotFoundException:
            print_info(f"KMS key not found: {key_alias}")
            self._track_deletion("kms_key", key_alias, True)
            return True
        except Exception as e:
            logger.error(f"Failed to schedule KMS key deletion: {e}")
            print_error(f"Failed to schedule KMS key deletion: {e}")
            self._track_deletion("kms_key", key_alias, False)
            return False

    def delete_config_rules(self) -> bool:
        """
        Delete all AWS Config rules.

        Returns:
            True if all deletions succeeded or rules didn't exist
        """
        print_info("Deleting AWS Config rules...")
        names = self._get_resource_names()
        all_success = True

        # List all config rules
        try:
            response = self.config_client.describe_config_rules()
            rules = response.get("ConfigRules", [])

            # Filter for GRC platform rules
            grc_rules = [
                rule
                for rule in rules
                if rule.get("ConfigRuleName", "").startswith(self.PREFIX)
            ]

            if not grc_rules:
                print_info("No GRC Config rules found")
                return True

            for rule in grc_rules:
                rule_name = rule.get("ConfigRuleName")
                try:
                    self.config_client.delete_config_rule(ConfigRuleName=rule_name)
                    print_success(f"Deleted Config rule: {rule_name}")
                    self._track_deletion("config_rule", rule_name, True)
                except self.config_client.exceptions.NoSuchConfigRuleException:
                    print_info(f"Config rule not found: {rule_name}")
                    self._track_deletion("config_rule", rule_name, True)
                except Exception as e:
                    logger.error(f"Failed to delete Config rule {rule_name}: {e}")
                    print_error(f"Failed to delete Config rule {rule_name}: {e}")
                    self._track_deletion("config_rule", rule_name, False)
                    all_success = False

        except Exception as e:
            logger.error(f"Failed to list Config rules: {e}")
            print_error(f"Failed to list Config rules: {e}")
            all_success = False

        return all_success

    def delete_config_conformance_packs(self) -> bool:
        """
        Delete all AWS Config conformance packs.

        Returns:
            True if all deletions succeeded or packs didn't exist
        """
        print_info("Deleting AWS Config conformance packs...")
        names = self._get_resource_names()
        packs = names.get("config_conformance_packs", [])

        all_success = True
        for pack_name in packs:
            try:
                self.config_client.delete_conformance_pack(
                    ConformancePackName=pack_name
                )
                print_success(f"Deleted Config conformance pack: {pack_name}")
                self._track_deletion("config_conformance_pack", pack_name, True)
            except self.config_client.exceptions.ResourceNotFoundException:
                print_info(f"Config conformance pack not found: {pack_name}")
                self._track_deletion("config_conformance_pack", pack_name, True)
            except Exception as e:
                logger.error(
                    f"Failed to delete Config conformance pack {pack_name}: {e}"
                )
                print_error(
                    f"Failed to delete Config conformance pack {pack_name}: {e}"
                )
                self._track_deletion("config_conformance_pack", pack_name, False)
                all_success = False

        return all_success

    def delete_cloudwatch_alarms(self) -> bool:
        """
        Delete CloudWatch alarms.

        Returns:
            True if all deletions succeeded or alarms didn't exist
        """
        print_info("Deleting CloudWatch alarms...")
        names = self._get_resource_names()
        alarms = names.get("cloudwatch_alarms", [])

        all_success = True
        for alarm_name in alarms:
            try:
                self.cloudwatch_client.delete_alarms(AlarmNames=[alarm_name])
                print_success(f"Deleted CloudWatch alarm: {alarm_name}")
                self._track_deletion("cloudwatch_alarm", alarm_name, True)
            except self.cloudwatch_client.exceptions.ResourceNotFoundException:
                print_info(f"CloudWatch alarm not found: {alarm_name}")
                self._track_deletion("cloudwatch_alarm", alarm_name, True)
            except Exception as e:
                logger.error(f"Failed to delete CloudWatch alarm {alarm_name}: {e}")
                print_error(f"Failed to delete CloudWatch alarm {alarm_name}: {e}")
                self._track_deletion("cloudwatch_alarm", alarm_name, False)
                all_success = False

        return all_success

    def delete_config_file(self) -> bool:
        """
        Delete the grc_config.json file.

        Returns:
            True if deletion succeeded or file didn't exist
        """
        try:
            if os.path.exists(self.CONFIG_FILE):
                os.remove(self.CONFIG_FILE)
                print_success(f"Deleted configuration file: {self.CONFIG_FILE}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete config file: {e}")
            print_error(f"Failed to delete config file: {e}")
            return False

    def delete_cloudformation_stack(self) -> bool:
        """
        Delete the CloudFormation stack.

        Returns:
            True if deletion succeeded or stack didn't exist
        """
        stack_name = "grc-evidence-platform"
        print_info(f"Deleting CloudFormation stack: {stack_name}")

        try:
            # Check if stack exists
            try:
                response = self.cloudformation_client.describe_stacks(
                    StackName=stack_name
                )
                stack = response["Stacks"][0]
                logger.info(f"=== DIAGNOSTIC: Stack found ===")
                logger.info(f"Stack name: {stack.get('StackName')}")
                logger.info(f"Stack status: {stack.get('StackStatus')}")
                logger.info(f"Stack creation time: {stack.get('CreationTime')}")
                if "StackStatusReason" in stack:
                    logger.info(
                        f"Stack status reason: {stack.get('StackStatusReason')}"
                    )
                logger.info(f"=== END DIAGNOSTIC ===")
            except self.cloudformation_client.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "ValidationError":
                    print_info(f"CloudFormation stack not found: {stack_name}")
                    self._track_deletion("cloudformation_stack", stack_name, True)
                    return True
                raise

            # Delete the stack
            self.cloudformation_client.delete_stack(StackName=stack_name)
            print_success(f"Initiated CloudFormation stack deletion: {stack_name}")
            self._track_deletion("cloudformation_stack", stack_name, True)

            # Wait for stack deletion to complete with progress polling
            print_info("Waiting for CloudFormation stack deletion to complete...")
            logger.info("=== DIAGNOSTIC: Starting stack deletion polling ===")

            # Custom polling loop with progress updates
            max_attempts = 180  # 30 minutes total (180 * 10 seconds)
            poll_interval = 10  # Poll every 10 seconds
            attempt = 0

            while attempt < max_attempts:
                attempt += 1
                elapsed_time = attempt * poll_interval

                try:
                    # Try to describe the stack
                    response = self.cloudformation_client.describe_stacks(
                        StackName=stack_name
                    )
                    stack = response["Stacks"][0]
                    status = stack.get("StackStatus")

                    # Check if stack is deleted
                    if status == "DELETE_COMPLETE":
                        print_success(
                            f"CloudFormation stack deleted successfully: {stack_name} "
                            f"(elapsed: {elapsed_time}s)"
                        )
                        logger.info("=== Stack deletion completed successfully ===")
                        return True

                    # Check if deletion failed
                    if status == "DELETE_FAILED":
                        error_msg = stack.get("StackStatusReason", "Unknown reason")
                        logger.error(f"Stack deletion failed: {error_msg}")

                        # Get recent events to identify the failing resource
                        print_error(f"Stack deletion failed: {error_msg}")
                        print_info(
                            "Checking recent stack events to identify the issue..."
                        )

                        events = self.cloudformation_client.describe_stack_events(
                            StackName=stack_name
                        )
                        print_info("Recent stack events (last 5):")
                        for event in events.get("StackEvents", [])[:5]:
                            timestamp = event.get("Timestamp").strftime("%H:%M:%S")
                            resource_id = event.get("LogicalResourceId")
                            resource_type = event.get("ResourceType")
                            resource_status = event.get("ResourceStatus")
                            reason = event.get("ResourceStatusReason", "")

                            print_colored(
                                f"  [{timestamp}] {resource_id} ({resource_type}): {resource_status}",
                                (
                                    Colors.YELLOW
                                    if "FAILED" in resource_status
                                    else Colors.CYAN
                                ),
                            )
                            if reason:
                                print_colored(f"    Reason: {reason}", Colors.RED)

                        logger.info("=== Stack deletion FAILED ===")
                        self._track_deletion("cloudformation_stack", stack_name, False)
                        return False

                    # Stack is still in progress
                    if attempt % 6 == 0:  # Print status every minute (6 * 10s)
                        print_info(
                            f"Stack deletion in progress... Status: {status} "
                            f"(elapsed: {elapsed_time}s)"
                        )
                        logger.info(
                            f"Stack status: {status} (elapsed: {elapsed_time}s)"
                        )

                    # Wait before next poll
                    time.sleep(poll_interval)

                except self.cloudformation_client.exceptions.ClientError as e:
                    error_code = e.response["Error"]["Code"]
                    # Stack not found means deletion is complete
                    if error_code == "ValidationError":
                        print_success(
                            f"CloudFormation stack deleted successfully: {stack_name} "
                            f"(elapsed: {elapsed_time}s)"
                        )
                        logger.info(
                            "=== Stack deletion completed successfully (stack not found) ==="
                        )
                        return True
                    # Some other error
                    logger.error(f"Error describing stack: {e}")
                    raise

            # Timeout reached
            logger.error(f"Stack deletion timed out after {elapsed_time}s")

            # Check final status
            try:
                response = self.cloudformation_client.describe_stacks(
                    StackName=stack_name
                )
                stack = response["Stacks"][0]
                status = stack.get("StackStatus")
                reason = stack.get("StackStatusReason", "Unknown")

                print_error(
                    f"Stack deletion timed out after {elapsed_time}s. "
                    f"Final status: {status}"
                )
                print_warning(f"Reason: {reason}")

                # Get recent events
                print_info("Recent stack events (last 10):")
                events = self.cloudformation_client.describe_stack_events(
                    StackName=stack_name
                )
                for event in events.get("StackEvents", [])[:10]:
                    timestamp = event.get("Timestamp").strftime("%H:%M:%S")
                    resource_id = event.get("LogicalResourceId")
                    resource_type = event.get("ResourceType")
                    resource_status = event.get("ResourceStatus")
                    reason = event.get("ResourceStatusReason", "")

                    print_colored(
                        f"  [{timestamp}] {resource_id} ({resource_type}): {resource_status}",
                        Colors.YELLOW if "FAILED" in resource_status else Colors.CYAN,
                    )
                    if reason:
                        print_colored(f"    Reason: {reason}", Colors.RED)

                logger.info("=== Stack deletion TIMED OUT ===")

            except Exception as e:
                logger.error(f"Could not check final stack status: {e}")

            self._track_deletion("cloudformation_stack", stack_name, False)
            return False

            return True

        except Exception as e:
            logger.error(f"Failed to delete CloudFormation stack {stack_name}: {e}")
            print_error(f"Failed to delete CloudFormation stack {stack_name}: {e}")
            self._track_deletion("cloudformation_stack", stack_name, False)
            return False

    def print_summary(self) -> None:
        """
        Print a summary of the teardown operation.
        """
        print_header("Teardown Summary")

        print_colored(f"Account ID: {self.account_id}", Colors.CYAN)
        print_colored(f"Region: {self.region}", Colors.CYAN)
        print()

        if self.deleted_resources:
            print_colored("Resources Deleted:", Colors.BOLD + Colors.GREEN)
            for resource in self.deleted_resources:
                print(f"  • {resource['type']}: {resource['name']}")
            print()

        if self.failed_deletions:
            print_colored("Failed Deletions:", Colors.BOLD + Colors.RED)
            for resource in self.failed_deletions:
                print(f"  • {resource['type']}: {resource['name']}")
            print()

        print_colored(f"Total deleted: {len(self.deleted_resources)}", Colors.GREEN)
        if self.failed_deletions:
            print_colored(f"Total failed: {len(self.failed_deletions)}", Colors.RED)
        print()

    def teardown(self, confirm: bool = True) -> bool:
        """
        Execute the complete teardown process.

        Args:
            confirm: Whether to prompt for confirmation before deletion

        Returns:
            True if teardown completed successfully (with possible failures)
        """
        try:
            # Confirm before proceeding
            if confirm:
                print_header("⚠️  WARNING: Complete Platform Teardown  ⚠️")
                print_warning("This will delete ALL GRC Evidence Platform resources!")
                print_warning("This action cannot be undone!")
                print()
                print_colored("Resources to be deleted:", Colors.BOLD)
                names = self._get_resource_names()
                print(
                    f"  • CloudWatch alarms: {len(names.get('cloudwatch_alarms', []))}"
                )
                print(
                    f"  • EventBridge rules: {len(names.get('eventbridge_rules', []))}"
                )
                print(f"  • Lambda functions: {len(names.get('lambda_functions', []))}")
                print(f"  • CloudTrail trails: 1")
                print(
                    f"  • AWS Config conformance packs: {len(names.get('config_conformance_packs', []))}"
                )
                print(f"  • AWS Config rules: (all GRC rules)")
                print(f"  • AWS Config resources: 2 (recorder + delivery channel)")
                print(f"  • Security Hub: 1")
                print(f"  • GuardDuty detectors: 1")
                print(f"  • Macie: 1")
                print(f"  • SNS topics: 1")
                print(f"  • IAM roles: {len(names.get('iam_roles', []))}")
                print(f"  • DynamoDB tables: {len(names.get('dynamodb_tables', []))}")
                print(f"  • S3 buckets: {len(names.get('s3_buckets', []))}")
                print(f"  • KMS keys: 1 (scheduled for deletion)")
                print()

                # DIAGNOSTIC: Log the actual resource names being used
                logger.info("=== DIAGNOSTIC: Resource Names ===")
                logger.info(f"DynamoDB tables: {names.get('dynamodb_tables', [])}")
                logger.info(f"S3 buckets: {names.get('s3_buckets', [])}")
                logger.info(f"IAM roles: {names.get('iam_roles', [])}")
                logger.info(f"Lambda functions: {names.get('lambda_functions', [])}")
                logger.info(f"Config from file: {self.config.get('resources', {})}")
                logger.info("=== END DIAGNOSTIC ===")

                response = (
                    input("Are you sure you want to proceed? (type 'yes' to confirm): ")
                    .strip()
                    .lower()
                )
                if response != "yes":
                    print_info("Teardown cancelled.")
                    return False

            print_header("Starting Platform Teardown")

            # Delete resources in reverse dependency order
            # DIAGNOSTIC: Log each deletion step
            logger.info("=== Starting deletion sequence ===")

            # Step 1: Delete CloudFormation stack (this will delete most resources)
            logger.info("Step 1: Deleting CloudFormation stack")
            result1 = self.delete_cloudformation_stack()
            logger.info(f"CloudFormation stack deletion result: {result1}")

            # Step 2: Delete remaining resources that might not be in the stack
            logger.info("Step 2: Deleting CloudWatch alarms")
            result2 = self.delete_cloudwatch_alarms()
            logger.info(f"CloudWatch alarms deletion result: {result2}")

            logger.info("Step 3: Deleting EventBridge rules")
            result3 = self.delete_eventbridge_rules()
            logger.info(f"EventBridge rules deletion result: {result3}")

            logger.info("Step 4: Deleting Lambda functions")
            result4 = self.delete_lambda_functions()
            logger.info(f"Lambda functions deletion result: {result4}")

            logger.info("Step 5: Deleting CloudTrail")
            result5 = self.delete_cloudtrail()
            logger.info(f"CloudTrail deletion result: {result5}")

            logger.info("Step 6: Deleting Config conformance packs")
            result6 = self.delete_config_conformance_packs()
            logger.info(f"Config conformance packs deletion result: {result6}")

            logger.info("Step 7: Deleting Config rules")
            result7 = self.delete_config_rules()
            logger.info(f"Config rules deletion result: {result7}")

            logger.info("Step 8: Deleting Config")
            result8 = self.delete_config()
            logger.info(f"Config deletion result: {result8}")

            logger.info("Step 9: Disabling Security Hub")
            result9 = self.disable_securityhub()
            logger.info(f"Security Hub disablement result: {result9}")

            logger.info("Step 10: Disabling GuardDuty")
            result10 = self.disable_guardduty()
            logger.info(f"GuardDuty disablement result: {result10}")

            logger.info("Step 11: Disabling Macie")
            result11 = self.disable_macie()
            logger.info(f"Macie disablement result: {result11}")

            logger.info("Step 12: Deleting SNS topic")
            result12 = self.delete_sns_topic()
            logger.info(f"SNS topic deletion result: {result12}")

            logger.info("Step 13: Deleting IAM roles")
            result13 = self.delete_iam_roles()
            logger.info(f"IAM roles deletion result: {result13}")

            logger.info("Step 14: Deleting DynamoDB tables")
            result14 = self.delete_dynamodb_tables()
            logger.info(f"DynamoDB tables deletion result: {result14}")

            logger.info("Step 15: Deleting S3 buckets")
            result15 = self.delete_s3_buckets()
            logger.info(f"S3 buckets deletion result: {result15}")

            logger.info("Step 16: Scheduling KMS key deletion")
            result16 = self.delete_kms_key()
            logger.info(f"KMS key deletion result: {result16}")
            logger.info("=== Deletion sequence complete ===")

            # Delete config file
            self.delete_config_file()

            # Print summary
            self.print_summary()

            # Final status
            if self.failed_deletions:
                print_warning(
                    "Teardown completed with some failures. Check the log for details."
                )
                return False
            else:
                print_success("Teardown completed successfully!")
                print_colored(
                    "All GRC Evidence Platform resources have been removed.",
                    Colors.GREEN,
                )
                return True

        except Exception as e:
            logger.error(f"Teardown error: {e}", exc_info=True)
            print_error(f"Teardown failed: {e}")
            return False


def main() -> None:
    """
    Main entry point for the teardown script.
    """
    parser = argparse.ArgumentParser(
        description="Tear down the GRC Evidence Platform v2.0"
    )
    parser.add_argument(
        "--region",
        help="AWS region to teardown from (default: from AWS_DEFAULT_REGION or us-east-1)",
        default=None,
    )
    parser.add_argument(
        "--profile", help="AWS profile name to use (default: default)", default=None
    )
    parser.add_argument("--yes", help="Skip confirmation prompt", action="store_true")

    args = parser.parse_args()

    try:
        teardown = GRCTeardown(region=args.region, profile=args.profile)
        success = teardown.teardown(confirm=not args.yes)
        sys.exit(0 if success else 1)

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
