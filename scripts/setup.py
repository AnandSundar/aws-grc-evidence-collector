#!/usr/bin/env python3
"""
GRC Evidence Platform v2.0 - One-Click Deployment Script

This script provides a complete, idempotent deployment of the GRC Evidence Platform
using boto3. It creates all necessary AWS resources including KMS keys, S3 buckets,
DynamoDB tables, Lambda functions, and enables security services.

Usage:
    python scripts/setup.py

Author: GRC Platform Team
Version: 2.0
"""

import argparse
import json
import logging
import os
import shutil
import sys
import time
import zipfile
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("grc_setup.log")],
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


class GRCPlatformSetup:
    """
    Main class for setting up the GRC Evidence Platform.

    This class provides methods to create all necessary AWS resources for the platform,
    with idempotent operations and rollback capabilities on failure.
    """

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize the GRC Platform Setup.

        Args:
            region: AWS region to deploy to (default: from environment or us-east-1)
            profile: AWS profile name to use (default: default)
        """
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.session = boto3.Session(region_name=self.region, profile_name=profile)

        # Initialize AWS clients
        self.kms_client = self.session.client("kms")
        self.s3_client = self.session.client("s3")
        self.dynamodb_client = self.session.client("dynamodb")
        self.sns_client = self.session.client("sns")
        self.iam_client = self.session.client("iam")
        self.lambda_client = self.session.client("lambda")
        self.events_client = self.session.client("events")
        self.cloudtrail_client = self.session.client("cloudtrail")
        self.config_client = self.session.client("config")
        self.guardduty_client = self.session.client("guardduty")
        self.securityhub_client = self.session.client("securityhub")
        self.macie_client = self.session.client("macie2")
        self.sts_client = self.session.client("sts")

        # Get account ID
        self.account_id = self._get_account_id()

        # Track created resources for rollback
        self.created_resources: List[Dict[str, str]] = []

        # Configuration storage
        self.config: Dict[str, Any] = {
            "account_id": self.account_id,
            "region": self.region,
            "created_at": datetime.now().isoformat(),
            "resources": {},
        }

        # Resource naming prefix
        self.prefix = "grc-evidence-platform"

        print_header(f"GRC Evidence Platform v2.0 - Setup")
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

    def _track_resource(
        self, resource_type: str, resource_id: str, resource_name: str
    ) -> None:
        """
        Track a created resource for potential rollback.

        Args:
            resource_type: Type of resource (e.g., 'kms_key', 's3_bucket')
            resource_id: Unique identifier for the resource
            resource_name: Name/ARN of the resource
        """
        self.created_resources.append(
            {
                "type": resource_type,
                "id": resource_id,
                "name": resource_name,
                "created_at": datetime.now().isoformat(),
            }
        )
        self.config["resources"][resource_type] = {
            "id": resource_id,
            "name": resource_name,
        }
        logger.info(f"Tracked resource: {resource_type} - {resource_name}")

    def _wait_for_resource(
        self, resource_type: str, check_func, timeout: int = 300
    ) -> bool:
        """
        Wait for a resource to become available.

        Args:
            resource_type: Type of resource being waited on
            check_func: Function that returns True when resource is ready
            timeout: Maximum time to wait in seconds

        Returns:
            True if resource became available, False otherwise
        """
        print_info(f"Waiting for {resource_type} to be ready...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                if check_func():
                    print_success(f"{resource_type} is ready")
                    return True
            except Exception as e:
                logger.debug(f"Waiting for {resource_type}: {e}")

            time.sleep(5)

        print_error(f"Timeout waiting for {resource_type}")
        return False

    def create_kms_key(self) -> str:
        """
        Create a KMS customer master key with automatic key rotation.

        Returns:
            KMS key ARN

        Raises:
            Exception: If key creation fails
        """
        key_alias = f"alias/{self.prefix}-key"

        try:
            # Check if key already exists
            try:
                response = self.kms_client.describe_key(KeyId=key_alias)
                key_arn = response["KeyMetadata"]["Arn"]
                print_success(f"KMS key already exists: {key_arn}")
                self._track_resource("kms_key", key_arn, key_arn)
                return key_arn
            except self.kms_client.exceptions.NotFoundException:
                pass

            # Create new key
            print_info("Creating KMS key with rotation...")
            response = self.kms_client.create_key(
                Description="GRC Evidence Platform encryption key",
                KeyUsage="ENCRYPT_DECRYPT",
                Origin="AWS_KMS",
                BypassPolicyLockoutSafetyCheck=False,
                Tags=[
                    {"TagKey": "Name", "TagValue": f"{self.prefix}-key"},
                    {"TagKey": "Platform", "TagValue": "GRC-Evidence-Platform"},
                    {"TagKey": "ManagedBy", "TagValue": "setup.py"},
                ],
            )

            key_id = response["KeyMetadata"]["KeyId"]
            key_arn = response["KeyMetadata"]["Arn"]

            # Enable key rotation
            self.kms_client.enable_key_rotation(KeyId=key_id)

            # Create alias
            self.kms_client.create_alias(AliasName=key_alias, TargetKeyId=key_id)

            # Get current account ID for key policy
            account_id = self.account_id

            # Set key policy
            key_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Enable IAM User Permissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "Allow S3 and DynamoDB Access",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": [
                                "s3.amazonaws.com",
                                "dynamodb.amazonaws.com",
                                "lambda.amazonaws.com",
                            ]
                        },
                        "Action": [
                            "kms:Encrypt",
                            "kms:Decrypt",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:DescribeKey",
                        ],
                        "Resource": "*",
                    },
                ],
            }

            self.kms_client.put_key_policy(
                KeyId=key_id, PolicyName="default", Policy=json.dumps(key_policy)
            )

            print_success(f"KMS key created: {key_arn}")
            self._track_resource("kms_key", key_arn, key_arn)
            return key_arn

        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to create KMS key: {e}")
            raise

    def create_s3_buckets(self) -> Dict[str, str]:
        """
        Create three S3 buckets: evidence, cloudtrail, and reports.

        Each bucket has:
        - Server-side encryption with KMS
        - Versioning enabled
        - Lifecycle policies
        - Public access blocked

        Returns:
            Dictionary mapping bucket names to their ARNs

        Raises:
            Exception: If bucket creation fails
        """
        buckets = {
            "evidence": f"{self.prefix}-evidence-{self.account_id}",
            "cloudtrail": f"{self.prefix}-cloudtrail-{self.account_id}",
            "reports": f"{self.prefix}-reports-{self.account_id}",
        }

        bucket_arns = {}
        kms_key_arn = self.config["resources"].get("kms_key", {}).get("name", "")

        for bucket_type, bucket_name in buckets.items():
            try:
                # Check if bucket already exists
                try:
                    self.s3_client.head_bucket(Bucket=bucket_name)
                    location = self.s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location.get("LocationConstraint") or "us-east-1"
                    bucket_arn = f"arn:aws:s3:::{bucket_name}"
                    print_success(f"S3 bucket already exists: {bucket_name}")
                    self._track_resource(
                        f"s3_bucket_{bucket_type}", bucket_name, bucket_arn
                    )
                    bucket_arns[bucket_type] = bucket_arn
                    continue
                except self.s3_client.exceptions.ClientError as e:
                    if e.response["Error"]["Code"] != "404":
                        raise

                # Create bucket
                print_info(f"Creating S3 bucket: {bucket_name}")

                if self.region == "us-east-1":
                    self.s3_client.create_bucket(Bucket=bucket_name)
                else:
                    self.s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={"LocationConstraint": self.region},
                    )

                # Wait for bucket to exist
                self.s3_client.get_waiter("bucket_exists").wait(Bucket=bucket_name)

                # Enable versioning
                self.s3_client.put_bucket_versioning(
                    Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
                )

                # Set encryption
                if kms_key_arn:
                    self.s3_client.put_bucket_encryption(
                        Bucket=bucket_name,
                        ServerSideEncryptionConfiguration={
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "aws:kms",
                                        "KMSMasterKeyID": kms_key_arn,
                                    }
                                }
                            ]
                        },
                    )
                else:
                    self.s3_client.put_bucket_encryption(
                        Bucket=bucket_name,
                        ServerSideEncryptionConfiguration={
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "AES256"
                                    }
                                }
                            ]
                        },
                    )

                # Block public access
                self.s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                )

                # Set lifecycle policy
                lifecycle_rules = []

                if bucket_type == "evidence":
                    lifecycle_rules.append(
                        {
                            "ID": "DeleteOldVersions",
                            "Status": "Enabled",
                            "NoncurrentVersionExpiration": {"NoncurrentDays": 90},
                        }
                    )
                    lifecycle_rules.append(
                        {
                            "ID": "TransitionToGlacier",
                            "Status": "Enabled",
                            "Transitions": [
                                {"Days": 30, "StorageClass": "STANDARD_IA"},
                                {"Days": 90, "StorageClass": "GLACIER"},
                            ],
                        }
                    )
                elif bucket_type == "cloudtrail":
                    lifecycle_rules.append(
                        {
                            "ID": "DeleteOldLogs",
                            "Status": "Enabled",
                            "Expiration": {"Days": 365},
                        }
                    )
                elif bucket_type == "reports":
                    lifecycle_rules.append(
                        {
                            "ID": "DeleteOldReports",
                            "Status": "Enabled",
                            "Expiration": {"Days": 180},
                        }
                    )

                if lifecycle_rules:
                    self.s3_client.put_bucket_lifecycle_configuration(
                        Bucket=bucket_name,
                        LifecycleConfiguration={"Rules": lifecycle_rules},
                    )

                # Add bucket tags
                self.s3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={
                        "TagSet": [
                            {"Key": "Name", "Value": bucket_name},
                            {"Key": "Platform", "Value": "GRC-Evidence-Platform"},
                            {"Key": "Type", "Value": bucket_type},
                            {"Key": "ManagedBy", "Value": "setup.py"},
                        ]
                    },
                )

                bucket_arn = f"arn:aws:s3:::{bucket_name}"
                print_success(f"S3 bucket created: {bucket_name}")
                self._track_resource(
                    f"s3_bucket_{bucket_type}", bucket_name, bucket_arn
                )
                bucket_arns[bucket_type] = bucket_arn

            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to create S3 bucket {bucket_name}: {e}")
                raise

        return bucket_arns

    def create_dynamodb_tables(self) -> Dict[str, str]:
        """
        Create three DynamoDB tables: metadata, remediation-log, and scorecards.

        Each table has:
        - Appropriate partition and sort keys
        - Global Secondary Indexes (GSIs)
        - Time-to-Live (TTL) configuration
        - On-demand capacity mode

        Returns:
            Dictionary mapping table names to their ARNs

        Raises:
            Exception: If table creation fails
        """
        tables = {
            "metadata": {
                "name": f"{self.prefix}-metadata",
                "key_schema": [
                    {"AttributeName": "resource_id", "KeyType": "HASH"},
                    {"AttributeName": "timestamp", "KeyType": "RANGE"},
                ],
                "attribute_definitions": [
                    {"AttributeName": "resource_id", "AttributeType": "S"},
                    {"AttributeName": "timestamp", "AttributeType": "S"},
                    {"AttributeName": "resource_type", "AttributeType": "S"},
                    {"AttributeName": "severity", "AttributeType": "S"},
                ],
                "gsis": [
                    {
                        "IndexName": "resource-type-index",
                        "KeySchema": [
                            {"AttributeName": "resource_type", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    },
                    {
                        "IndexName": "severity-index",
                        "KeySchema": [
                            {"AttributeName": "severity", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    },
                ],
                "ttl_attribute": "expire_at",
            },
            "remediation-log": {
                "name": f"{self.prefix}-remediation-log",
                "key_schema": [
                    {"AttributeName": "finding_id", "KeyType": "HASH"},
                    {"AttributeName": "timestamp", "KeyType": "RANGE"},
                ],
                "attribute_definitions": [
                    {"AttributeName": "finding_id", "AttributeType": "S"},
                    {"AttributeName": "timestamp", "AttributeType": "S"},
                    {"AttributeName": "status", "AttributeType": "S"},
                    {"AttributeName": "remediated_by", "AttributeType": "S"},
                ],
                "gsis": [
                    {
                        "IndexName": "status-index",
                        "KeySchema": [
                            {"AttributeName": "status", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    },
                    {
                        "IndexName": "remediated-by-index",
                        "KeySchema": [
                            {"AttributeName": "remediated_by", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    },
                ],
                "ttl_attribute": "expire_at",
            },
            "scorecards": {
                "name": f"{self.prefix}-scorecards",
                "key_schema": [
                    {"AttributeName": "compliance_standard", "KeyType": "HASH"},
                    {"AttributeName": "timestamp", "KeyType": "RANGE"},
                ],
                "attribute_definitions": [
                    {"AttributeName": "compliance_standard", "AttributeType": "S"},
                    {"AttributeName": "timestamp", "AttributeType": "S"},
                    {"AttributeName": "score", "AttributeType": "N"},
                ],
                "gsis": [
                    {
                        "IndexName": "score-index",
                        "KeySchema": [
                            {"AttributeName": "score", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    }
                ],
                "ttl_attribute": "expire_at",
            },
        }

        table_arns = {}

        for table_type, table_config in tables.items():
            try:
                # Check if table already exists
                try:
                    response = self.dynamodb_client.describe_table(
                        TableName=table_config["name"]
                    )
                    table_arn = response["Table"]["TableArn"]
                    print_success(
                        f"DynamoDB table already exists: {table_config['name']}"
                    )
                    self._track_resource(
                        f"dynamodb_table_{table_type}", table_config["name"], table_arn
                    )
                    table_arns[table_type] = table_arn
                    continue
                except self.dynamodb_client.exceptions.ResourceNotFoundException:
                    pass

                # Create table
                print_info(f"Creating DynamoDB table: {table_config['name']}")

                create_params = {
                    "TableName": table_config["name"],
                    "KeySchema": table_config["key_schema"],
                    "AttributeDefinitions": table_config["attribute_definitions"],
                    "BillingMode": "PAY_PER_REQUEST",
                    "Tags": [
                        {"Key": "Name", "Value": table_config["name"]},
                        {"Key": "Platform", "Value": "GRC-Evidence-Platform"},
                        {"Key": "Type", "Value": table_type},
                        {"Key": "ManagedBy", "Value": "setup.py"},
                    ],
                }

                # Add GSIs if defined
                if table_config["gsis"]:
                    create_params["GlobalSecondaryIndexes"] = table_config["gsis"]

                response = self.dynamodb_client.create_table(**create_params)
                table_arn = response["TableDescription"]["TableArn"]

                # Wait for table to be created
                waiter = self.dynamodb_client.get_waiter("table_exists")
                waiter.wait(TableName=table_config["name"])

                # Enable TTL
                if table_config["ttl_attribute"]:
                    self.dynamodb_client.update_time_to_live(
                        TableName=table_config["name"],
                        TimeToLiveSpecification={
                            "AttributeName": table_config["ttl_attribute"],
                            "Enabled": True,
                        },
                    )

                print_success(f"DynamoDB table created: {table_config['name']}")
                self._track_resource(
                    f"dynamodb_table_{table_type}", table_config["name"], table_arn
                )
                table_arns[table_type] = table_arn

            except (ClientError, BotoCoreError) as e:
                logger.error(
                    f"Failed to create DynamoDB table {table_config['name']}: {e}"
                )
                raise

        return table_arns

    def create_sns_topic(self) -> str:
        """
        Create an SNS topic for platform alerts and notifications.

        Returns:
            SNS topic ARN

        Raises:
            Exception: If topic creation fails
        """
        topic_name = f"{self.prefix}-alerts"

        try:
            # Check if topic already exists
            try:
                response = self.sns_client.create_topic(
                    Name=topic_name,
                    Tags=[
                        {"Key": "Name", "Value": topic_name},
                        {"Key": "Platform", "Value": "GRC-Evidence-Platform"},
                        {"Key": "ManagedBy", "Value": "setup.py"},
                    ],
                )
                topic_arn = response["TopicArn"]
                print_success(f"SNS topic created: {topic_name}")
                self._track_resource("sns_topic", topic_name, topic_arn)
                return topic_arn
            except self.sns_client.exceptions.TopicExistsException:
                # Find existing topic
                response = self.sns_client.list_topics()
                for topic in response["Topics"]:
                    if topic_name in topic["TopicArn"]:
                        topic_arn = topic["TopicArn"]
                        print_success(f"SNS topic already exists: {topic_name}")
                        self._track_resource("sns_topic", topic_name, topic_arn)
                        return topic_arn

        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to create SNS topic: {e}")
            raise

        raise Exception(f"Failed to create or find SNS topic: {topic_name}")

    def create_iam_roles(self) -> Dict[str, str]:
        """
        Create 5 IAM roles with least-privilege policies.

        Roles created:
        1. grc-evidence-collector - For Lambda collectors
        2. grc-evidence-processor - For evidence processing
        3. grc-remediation-engine - For auto-remediation
        4. grc-report-generator - For report generation
        5. grc-scorecard-generator - For scorecard generation

        Returns:
            Dictionary mapping role names to their ARNs

        Raises:
            Exception: If role creation fails
        """
        roles = {
            "grc-evidence-collector": {
                "description": "Role for GRC evidence collector Lambda functions",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "policies": {
                    "BasicExecution": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                    "CollectorPermissions": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "iam:List*",
                                    "iam:Get*",
                                    "iam:Describe*",
                                    "rds:Describe*",
                                    "rds:List*",
                                    "s3:List*",
                                    "s3:Get*",
                                    "config:Get*",
                                    "config:List*",
                                    "securityhub:Get*",
                                    "securityhub:List*",
                                    "guardduty:List*",
                                    "guardduty:Get*",
                                    "vpc:Describe*",
                                    "vpc:List*",
                                    "kms:Describe*",
                                    "kms:List*",
                                    "acm:Describe*",
                                    "acm:List*",
                                    "macie2:List*",
                                    "macie2:Get*",
                                    "inspector2:List*",
                                    "inspector2:Get*",
                                    "cloudtrail:Describe*",
                                    "cloudtrail:LookupEvents",
                                ],
                                "Resource": "*",
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:Query",
                                    "dynamodb:Scan",
                                ],
                                "Resource": [
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-metadata",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-metadata/index/*",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-remediation-log",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-remediation-log/index/*",
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["s3:PutObject", "s3:GetObject"],
                                "Resource": [
                                    f"arn:aws:s3:::{self.prefix}-evidence-{self.account_id}/*",
                                    f"arn:aws:s3:::{self.prefix}-cloudtrail-{self.account_id}/*",
                                ],
                            },
                        ],
                    },
                },
            },
            "grc-evidence-processor": {
                "description": "Role for GRC evidence processing Lambda",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "policies": {
                    "BasicExecution": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                    "ProcessorPermissions": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:Query",
                                    "dynamodb:Scan",
                                    "dynamodb:DeleteItem",
                                ],
                                "Resource": [
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-metadata",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-metadata/index/*",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-remediation-log",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-remediation-log/index/*",
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject",
                                    "s3:PutObject",
                                    "s3:DeleteObject",
                                ],
                                "Resource": [
                                    f"arn:aws:s3:::{self.prefix}-evidence-{self.account_id}/*"
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["kms:Decrypt", "kms:Encrypt"],
                                "Resource": "*",
                            },
                        ],
                    },
                },
            },
            "grc-remediation-engine": {
                "description": "Role for GRC auto-remediation Lambda",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "policies": {
                    "BasicExecution": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                    "RemediationPermissions": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:Query",
                                    "dynamodb:Scan",
                                ],
                                "Resource": [
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-remediation-log",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-remediation-log/index/*",
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:PutBucketEncryption",
                                    "s3:PutBucketPolicy",
                                    "s3:PutPublicAccessBlock",
                                    "iam:AttachRolePolicy",
                                    "iam:DeleteRolePolicy",
                                    "iam:PutRolePolicy",
                                    "ec2:ModifyInstanceAttribute",
                                    "ec2:StopInstances",
                                    "ec2:TerminateInstances",
                                    "rds:ModifyDBInstance",
                                    "securityhub:BatchUpdateFindings",
                                ],
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {"aws:RequestedRegion": self.region}
                                },
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["sns:Publish"],
                                "Resource": f"arn:aws:sns:{self.region}:{self.account_id}:{self.prefix}-alerts",
                            },
                        ],
                    },
                },
            },
            "grc-report-generator": {
                "description": "Role for GRC report generator Lambda",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "policies": {
                    "BasicExecution": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                    "ReportGeneratorPermissions": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["dynamodb:Query", "dynamodb:Scan"],
                                "Resource": [
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-metadata",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-metadata/index/*",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-scorecards",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-scorecards/index/*",
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["s3:PutObject", "s3:GetObject"],
                                "Resource": [
                                    f"arn:aws:s3:::{self.prefix}-reports-{self.account_id}/*",
                                    f"arn:aws:s3:::{self.prefix}-evidence-{self.account_id}/*",
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["kms:Decrypt", "kms:Encrypt"],
                                "Resource": "*",
                            },
                        ],
                    },
                },
            },
            "grc-scorecard-generator": {
                "description": "Role for GRC scorecard generator Lambda",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "policies": {
                    "BasicExecution": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                    "ScorecardGeneratorPermissions": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:Query",
                                    "dynamodb:Scan",
                                ],
                                "Resource": [
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-metadata",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-metadata/index/*",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-scorecards",
                                    f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.prefix}-scorecards/index/*",
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["s3:PutObject"],
                                "Resource": [
                                    f"arn:aws:s3:::{self.prefix}-reports-{self.account_id}/*"
                                ],
                            },
                        ],
                    },
                },
            },
        }

        role_arns = {}

        for role_name, role_config in roles.items():
            try:
                # Check if role already exists
                try:
                    response = self.iam_client.get_role(RoleName=role_name)
                    role_arn = response["Role"]["Arn"]
                    print_success(f"IAM role already exists: {role_name}")
                    self._track_resource(f"iam_role_{role_name}", role_name, role_arn)
                    role_arns[role_name] = role_arn
                    continue
                except self.iam_client.exceptions.NoSuchEntityException:
                    pass

                # Create role
                print_info(f"Creating IAM role: {role_name}")

                response = self.iam_client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(role_config["trust_policy"]),
                    Description=role_config["description"],
                    Tags=[
                        {"Key": "Name", "Value": role_name},
                        {"Key": "Platform", "Value": "GRC-Evidence-Platform"},
                        {"Key": "ManagedBy", "Value": "setup.py"},
                    ],
                )

                role_arn = response["Role"]["Arn"]

                # Attach policies
                for policy_name, policy_document in role_config["policies"].items():
                    self.iam_client.put_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy_document),
                    )

                # Wait for role to be ready
                time.sleep(10)

                print_success(f"IAM role created: {role_name}")
                self._track_resource(f"iam_role_{role_name}", role_name, role_arn)
                role_arns[role_name] = role_arn

            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to create IAM role {role_name}: {e}")
                raise

        return role_arns

    def _create_lambda_zip(self, source_path: str, zip_path: str) -> None:
        """
        Create a zip file for Lambda deployment.

        Args:
            source_path: Path to the source directory or file
            zip_path: Path where the zip file should be created
        """
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            if os.path.isfile(source_path):
                zipf.write(source_path, os.path.basename(source_path))
            else:
                for root, dirs, files in os.walk(source_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, source_path)
                        zipf.write(file_path, arcname)

    def create_lambda_functions(self) -> Dict[str, str]:
        """
        Zip and deploy all 5 Lambda functions.

        Functions deployed:
        1. grc-evidence-collector - Evidence collection orchestrator
        2. grc-evidence-processor - Evidence processing and storage
        3. grc-remediation-engine - Auto-remediation engine
        4. grc-report-generator - Report generation
        5. grc-scorecard-generator - Scorecard generation

        Returns:
            Dictionary mapping function names to their ARNs

        Raises:
            Exception: If function creation fails
        """
        lambda_functions = {
            "grc-evidence-collector": {
                "handler": "lambda.handler",
                "runtime": "python3.11",
                "timeout": 300,
                "memory_size": 512,
                "role": "grc-evidence-collector",
                "description": "GRC Evidence Collection Orchestrator",
            },
            "grc-evidence-processor": {
                "handler": "lambda/evidence_processor/handler.lambda_handler",
                "runtime": "python3.11",
                "timeout": 300,
                "memory_size": 512,
                "role": "grc-evidence-processor",
                "description": "GRC Evidence Processor",
            },
            "grc-remediation-engine": {
                "handler": "lambda/remediation_engine/handler.lambda_handler",
                "runtime": "python3.11",
                "timeout": 300,
                "memory_size": 512,
                "role": "grc-remediation-engine",
                "description": "GRC Auto-Remediation Engine",
            },
            "grc-report-generator": {
                "handler": "lambda/report_generator/handler.lambda_handler",
                "runtime": "python3.11",
                "timeout": 300,
                "memory_size": 512,
                "role": "grc-report-generator",
                "description": "GRC Report Generator",
            },
            "grc-scorecard-generator": {
                "handler": "lambda/scorecard_generator/handler.lambda_handler",
                "runtime": "python3.11",
                "timeout": 300,
                "memory_size": 512,
                "role": "grc-scorecard-generator",
                "description": "GRC Scorecard Generator",
            },
        }

        function_arns = {}

        for func_name, func_config in lambda_functions.items():
            try:
                # Check if function already exists
                try:
                    response = self.lambda_client.get_function(FunctionName=func_name)
                    function_arn = response["Configuration"]["FunctionArn"]
                    print_success(f"Lambda function already exists: {func_name}")
                    self._track_resource(
                        f"lambda_function_{func_name}", func_name, function_arn
                    )
                    function_arns[func_name] = function_arn
                    continue
                except self.lambda_client.exceptions.ResourceNotFoundException:
                    pass

                # Create deployment package
                print_info(f"Creating deployment package for: {func_name}")

                # Determine source path
                if func_name == "grc-evidence-collector":
                    source_path = "lambda/handler.py"
                else:
                    # Extract directory from handler path
                    handler_parts = func_config["handler"].split("/")
                    if len(handler_parts) > 1:
                        source_path = "/".join(handler_parts[:-1])
                    else:
                        source_path = "lambda"

                # Create zip file
                zip_path = f"/tmp/{func_name}.zip"

                # Check if source exists
                if not os.path.exists(source_path):
                    print_warning(
                        f"Source path not found: {source_path}, creating placeholder"
                    )
                    # Create a minimal handler
                    os.makedirs(
                        os.path.dirname(zip_path) if os.path.dirname(zip_path) else ".",
                        exist_ok=True,
                    )
                    with zipfile.ZipFile(zip_path, "w") as zipf:
                        zipf.writestr(
                            "lambda_function.py",
                            'def lambda_handler(event, context):\n    return {"statusCode": 200, "body": "OK"}\n',
                        )
                        func_config["handler"] = "lambda_function.lambda_handler"
                else:
                    self._create_lambda_zip(source_path, zip_path)

                # Read zip file
                with open(zip_path, "rb") as f:
                    zip_bytes = f.read()

                # Get role ARN
                role_arn = (
                    self.config["resources"]
                    .get(f'iam_role_{func_config["role"]}', {})
                    .get("name", "")
                )
                if not role_arn:
                    raise Exception(
                        f"Role not found for {func_name}: {func_config['role']}"
                    )

                # Create function
                print_info(f"Deploying Lambda function: {func_name}")

                response = self.lambda_client.create_function(
                    FunctionName=func_name,
                    Runtime=func_config["runtime"],
                    Role=role_arn,
                    Handler=func_config["handler"],
                    Code={"ZipFile": zip_bytes},
                    Description=func_config["description"],
                    Timeout=func_config["timeout"],
                    MemorySize=func_config["memory_size"],
                    Environment={
                        "Variables": {
                            "EVIDENCE_BUCKET": f"{self.prefix}-evidence-{self.account_id}",
                            "METADATA_TABLE": f"{self.prefix}-metadata",
                            "REMEDIATION_LOG_TABLE": f"{self.prefix}-remediation-log",
                            "SCORECARD_TABLE": f"{self.prefix}-scorecards",
                            "ALERTS_TOPIC": f"arn:aws:sns:{self.region}:{self.account_id}:{self.prefix}-alerts",
                            "REGION": self.region,
                            "ACCOUNT_ID": self.account_id,
                        }
                    },
                    Tags={
                        "Name": func_name,
                        "Platform": "GRC-Evidence-Platform",
                        "ManagedBy": "setup.py",
                    },
                )

                function_arn = response["FunctionArn"]

                # Wait for function to be active
                self.lambda_client.get_waiter("function_active").wait(
                    FunctionName=func_name
                )

                # Clean up zip file
                if os.path.exists(zip_path):
                    os.remove(zip_path)

                print_success(f"Lambda function created: {func_name}")
                self._track_resource(
                    f"lambda_function_{func_name}", func_name, function_arn
                )
                function_arns[func_name] = function_arn

            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to create Lambda function {func_name}: {e}")
                raise
            except Exception as e:
                logger.error(
                    f"Unexpected error creating Lambda function {func_name}: {e}"
                )
                raise

        return function_arns

    def create_eventbridge_rules(self) -> Dict[str, str]:
        """
        Create EventBridge rules for automated triggers.

        Rules created:
        1. CloudTrail trigger - Triggers on CloudTrail events
        2. Daily collection - Runs daily at 2 AM UTC
        3. Hourly collection - Runs every hour
        4. Weekly scorecard - Runs weekly on Sunday at 3 AM UTC

        Returns:
            Dictionary mapping rule names to their ARNs

        Raises:
            Exception: If rule creation fails
        """
        rules = {
            "grc-cloudtrail-trigger": {
                "description": "Trigger on CloudTrail events",
                "event_pattern": {
                    "source": ["aws.cloudtrail"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                },
                "targets": [
                    {
                        "function": "grc-evidence-collector",
                        "input": '{"trigger_source": "cloudtrail"}',
                    }
                ],
            },
            "grc-daily-collection": {
                "description": "Daily evidence collection at 2 AM UTC",
                "schedule_expression": "cron(0 2 * * ? *)",
                "targets": [
                    {
                        "function": "grc-evidence-collector",
                        "input": '{"trigger_source": "scheduled", "schedule": "daily"}',
                    }
                ],
            },
            "grc-hourly-collection": {
                "description": "Hourly evidence collection",
                "schedule_expression": "rate(1 hour)",
                "targets": [
                    {
                        "function": "grc-evidence-collector",
                        "input": '{"trigger_source": "scheduled", "schedule": "hourly"}',
                    }
                ],
            },
            "grc-weekly-scorecard": {
                "description": "Weekly scorecard generation on Sunday at 3 AM UTC",
                "schedule_expression": "cron(0 3 ? * SUN *)",
                "targets": [
                    {
                        "function": "grc-scorecard-generator",
                        "input": '{"trigger_source": "scheduled", "schedule": "weekly"}',
                    }
                ],
            },
        }

        rule_arns = {}

        for rule_name, rule_config in rules.items():
            try:
                # Check if rule already exists
                try:
                    response = self.events_client.describe_rule(Name=rule_name)
                    rule_arn = response["Arn"]
                    print_success(f"EventBridge rule already exists: {rule_name}")
                    self._track_resource(
                        f"eventbridge_rule_{rule_name}", rule_name, rule_arn
                    )
                    rule_arns[rule_name] = rule_arn
                    continue
                except self.events_client.exceptions.ResourceNotFoundException:
                    pass

                # Create rule
                print_info(f"Creating EventBridge rule: {rule_name}")

                params = {"Name": rule_name, "Description": rule_config["description"]}

                if "event_pattern" in rule_config:
                    params["EventPattern"] = json.dumps(rule_config["event_pattern"])
                if "schedule_expression" in rule_config:
                    params["ScheduleExpression"] = rule_config["schedule_expression"]

                response = self.events_client.put_rule(**params)
                rule_arn = response["RuleArn"]

                # Add targets
                for target in rule_config["targets"]:
                    function_arn = (
                        self.config["resources"]
                        .get(f'lambda_function_{target["function"]}', {})
                        .get("name", "")
                    )

                    if not function_arn:
                        print_warning(
                            f"Function not found for target: {target['function']}"
                        )
                        continue

                    self.events_client.put_targets(
                        Rule=rule_name,
                        Targets=[
                            {
                                "Id": f"{rule_name}-target",
                                "Arn": function_arn,
                                "Input": target["input"],
                            }
                        ],
                    )

                # Add permission for EventBridge to invoke Lambda
                for target in rule_config["targets"]:
                    function_name = target["function"]
                    try:
                        self.lambda_client.add_permission(
                            FunctionName=function_name,
                            StatementId=f"{rule_name}-invoke",
                            Action="lambda:InvokeFunction",
                            Principal="events.amazonaws.com",
                            SourceArn=rule_arn,
                        )
                    except self.lambda_client.exceptions.ResourceConflictException:
                        # Permission already exists
                        pass

                print_success(f"EventBridge rule created: {rule_name}")
                self._track_resource(
                    f"eventbridge_rule_{rule_name}", rule_name, rule_arn
                )
                rule_arns[rule_name] = rule_arn

            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to create EventBridge rule {rule_name}: {e}")
                raise

        return rule_arns

    def enable_cloudtrail(self) -> str:
        """
        Enable CloudTrail with S3 logging.

        Returns:
            CloudTrail ARN

        Raises:
            Exception: If CloudTrail enablement fails
        """
        trail_name = f"{self.prefix}-trail"
        bucket_name = f"{self.prefix}-cloudtrail-{self.account_id}"

        try:
            # Check if trail already exists
            try:
                response = self.cloudtrail_client.describe_trails(
                    trailNameList=[trail_name]
                )
                if response["trailList"]:
                    trail_arn = response["trailList"][0]["TrailARN"]
                    print_success(f"CloudTrail already exists: {trail_name}")
                    self._track_resource("cloudtrail", trail_name, trail_arn)
                    return trail_arn
            except (ClientError, BotoCoreError) as e:
                logger.debug(f"CloudTrail check: {e}")

            # Create trail
            print_info(f"Enabling CloudTrail: {trail_name}")

            response = self.cloudtrail_client.create_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
                IncludeGlobalServiceEvents=True,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                TagsList=[
                    {"Key": "Name", "Value": trail_name},
                    {"Key": "Platform", "Value": "GRC-Evidence-Platform"},
                    {"Key": "ManagedBy", "Value": "setup.py"},
                ],
            )

            trail_arn = response["TrailARN"]

            # Start logging
            self.cloudtrail_client.start_logging(Name=trail_name)

            print_success(f"CloudTrail enabled: {trail_name}")
            self._track_resource("cloudtrail", trail_name, trail_arn)
            return trail_arn

        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to enable CloudTrail: {e}")
            raise

    def enable_config(self) -> Tuple[str, str]:
        """
        Enable AWS Config recorder and delivery channel.

        Returns:
            Tuple of (recorder ARN, delivery channel name)

        Raises:
            Exception: If Config enablement fails
        """
        recorder_name = f"{self.prefix}-recorder"
        channel_name = f"{self.prefix}-channel"
        bucket_name = f"{self.prefix}-evidence-{self.account_id}"
        role_name = f"{self.prefix}-config-role"

        try:
            # Create Config role if needed
            try:
                self.iam_client.get_role(RoleName=role_name)
                print_success(f"Config role already exists: {role_name}")
            except self.iam_client.exceptions.NoSuchEntityException:
                print_info(f"Creating Config role: {role_name}")

                trust_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "config.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }

                response = self.iam_client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(trust_policy),
                    Description="Role for AWS Config",
                    Tags=[
                        {"Key": "Name", "Value": role_name},
                        {"Key": "Platform", "Value": "GRC-Evidence-Platform"},
                        {"Key": "ManagedBy", "Value": "setup.py"},
                    ],
                )

                # Attach Config service role policy
                self.iam_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn="arn:aws:iam::aws:policy/service-role/AWSConfigRole",
                )

                # Create custom policy for S3 access
                s3_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:PutObject", "s3:GetBucketAcl"],
                            "Resource": [
                                f"arn:aws:s3:::{bucket_name}",
                                f"arn:aws:s3:::{bucket_name}/AWSLogs/{self.account_id}/*",
                            ],
                        }
                    ],
                }

                self.iam_client.put_role_policy(
                    RoleName=role_name,
                    PolicyName="S3Access",
                    PolicyDocument=json.dumps(s3_policy),
                )

                self._track_resource(
                    "iam_role_config", role_name, response["Role"]["Arn"]
                )
                print_success(f"Config role created: {role_name}")

            role_arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"

            # Check if recorder already exists
            try:
                response = self.config_client.describe_configuration_recorders(
                    ConfigurationRecorderNames=[recorder_name]
                )
                if response["ConfigurationRecorders"]:
                    recorder_arn = response["ConfigurationRecorders"][0]["roleARN"]
                    print_success(f"Config recorder already exists: {recorder_name}")
                    self._track_resource("config_recorder", recorder_name, recorder_arn)
                else:
                    raise self.config_client.exceptions.NoSuchConfigurationRecorderException()
            except self.config_client.exceptions.NoSuchConfigurationRecorderException:
                # Create recorder
                print_info(f"Creating Config recorder: {recorder_name}")

                response = self.config_client.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder_name,
                        "roleARN": role_arn,
                        "recordingGroup": {
                            "allSupported": True,
                            "includeGlobalResourceTypes": True,
                        },
                    }
                )

                recorder_arn = role_arn
                print_success(f"Config recorder created: {recorder_name}")
                self._track_resource("config_recorder", recorder_name, recorder_arn)

            # Check if delivery channel already exists
            try:
                self.config_client.describe_delivery_channels(
                    DeliveryChannelNames=[channel_name]
                )
                print_success(f"Config delivery channel already exists: {channel_name}")
                self._track_resource("config_channel", channel_name, channel_name)
            except self.config_client.exceptions.NoSuchDeliveryChannelException:
                # Create delivery channel
                print_info(f"Creating Config delivery channel: {channel_name}")

                self.config_client.put_delivery_channel(
                    DeliveryChannel={
                        "name": channel_name,
                        "s3BucketName": bucket_name,
                        "s3KeyPrefix": "config/",
                        "configSnapshotDeliveryProperties": {
                            "deliveryFrequency": "TwentyFour_Hours"
                        },
                    }
                )

                print_success(f"Config delivery channel created: {channel_name}")
                self._track_resource("config_channel", channel_name, channel_name)

            # Start recorder
            print_info("Starting Config recorder...")
            self.config_client.start_configuration_recorder(
                ConfigurationRecorderName=recorder_name
            )

            print_success("AWS Config enabled")
            return (recorder_arn, channel_name)

        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to enable AWS Config: {e}")
            raise

    def enable_guardduty(self) -> str:
        """
        Enable GuardDuty detector.

        Returns:
            GuardDuty detector ID

        Raises:
            Exception: If GuardDuty enablement fails
        """
        try:
            # List existing detectors
            response = self.guardduty_client.list_detectors()

            if response["DetectorIds"]:
                detector_id = response["DetectorIds"][0]
                print_success(f"GuardDuty already enabled: {detector_id}")
                self._track_resource("guardduty", detector_id, detector_id)
                return detector_id

            # Create detector
            print_info("Enabling GuardDuty...")

            response = self.guardduty_client.create_detector(
                enable=True,
                dataSources={
                    "cloudTrail": {"enable": True},
                    "dnsLogs": {"enable": True},
                    "flowLogs": {"enable": True},
                    "s3Logs": {"enable": True},
                    "kubernetes": {"auditLogs": {"enable": True}},
                },
                tags=[
                    {"Key": "Platform", "Value": "GRC-Evidence-Platform"},
                    {"Key": "ManagedBy", "Value": "setup.py"},
                ],
            )

            detector_id = response["DetectorId"]
            print_success(f"GuardDuty enabled: {detector_id}")
            self._track_resource("guardduty", detector_id, detector_id)
            return detector_id

        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to enable GuardDuty: {e}")
            raise

    def enable_securityhub(self) -> str:
        """
        Enable Security Hub with standards.

        Returns:
            Security Hub ARN

        Raises:
            Exception: If Security Hub enablement fails
        """
        try:
            # Check if Security Hub is already enabled
            try:
                response = self.securityhub_client.describe_hub()
                hub_arn = response["HubArn"]
                print_success(f"Security Hub already enabled")
                self._track_resource("securityhub", "hub", hub_arn)
            except self.securityhub_client.exceptions.InvalidAccessException:
                # Enable Security Hub
                print_info("Enabling Security Hub...")

                response = self.securityhub_client.enable_security_hub(
                    Tags={"Platform": "GRC-Evidence-Platform", "ManagedBy": "setup.py"}
                )

                hub_arn = response.get(
                    "HubArn",
                    f"arn:aws:securityhub:{self.region}:{self.account_id}:hub/default",
                )
                print_success("Security Hub enabled")
                self._track_resource("securityhub", "hub", hub_arn)

            # Enable standards
            print_info("Enabling Security Hub standards...")

            standards_to_enable = [
                "aws-foundational-security-best-practices/v/1.0.0",
                "cis-aws-foundations-benchmark/v/1.2.0",
                "pci-dss/v/3.2.1",
                "nist-800-53/v/5.0.0",
            ]

            for standard_arn in standards_to_enable:
                try:
                    self.securityhub_client.batch_enable_standards(
                        StandardsSubscriptionRequests=[
                            {
                                "StandardsArn": f"arn:aws:securityhub:{self.region}::standards/{standard_arn}",
                                "StandardsInput": {},
                            }
                        ]
                    )
                    print_success(f"Enabled standard: {standard_arn}")
                except (ClientError, BotoCoreError) as e:
                    logger.warning(f"Failed to enable standard {standard_arn}: {e}")

            return hub_arn

        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to enable Security Hub: {e}")
            raise

    def enable_macie(self) -> str:
        """
        Enable Macie for data discovery and classification.

        Returns:
            Macie account ID

        Raises:
            Exception: If Macie enablement fails
        """
        try:
            # Check if Macie is already enabled
            try:
                response = self.macie_client.get_macie_session()
                print_success(f"Macie already enabled")
                self._track_resource("macie", "session", "enabled")
                return "enabled"
            except self.macie_client.exceptions.ResourceNotFoundException:
                pass

            # Enable Macie
            print_info("Enabling Macie...")

            # Get finding publishing options
            finding_publishing_frequency = "FIFTEEN_MINUTES"
            status = "ENABLED"

            # Create Macie session
            response = self.macie_client.enable_macie(
                findingPublishingFrequency=finding_publishing_frequency,
                status=status,
                clientToken=f"grc-setup-{int(time.time())}",
            )

            print_success("Macie enabled")
            self._track_resource("macie", "session", "enabled")
            return "enabled"

        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to enable Macie: {e}")
            # Macie might not be available in all regions
            print_warning(
                f"Macie enablement failed (may not be available in {self.region}): {e}"
            )
            self._track_resource("macie", "session", "skipped")
            return "skipped"

    def save_config(self) -> None:
        """
        Save all ARNs and names to grc_config.json.
        """
        config_path = "grc_config.json"

        try:
            with open(config_path, "w") as f:
                json.dump(self.config, f, indent=2)

            print_success(f"Configuration saved to {config_path}")

        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise

    def print_summary(self) -> None:
        """
        Print a formatted summary of all created resources.
        """
        print_header("Deployment Summary")

        print_colored(f"Account ID: {self.account_id}", Colors.CYAN)
        print_colored(f"Region: {self.region}", Colors.CYAN)
        print_colored(f"Created at: {self.config['created_at']}", Colors.CYAN)
        print()

        print_colored("Resources Created:", Colors.BOLD + Colors.GREEN)
        print()

        # Group resources by type
        resource_groups = {}
        for resource in self.created_resources:
            resource_type = resource["type"]
            if resource_type not in resource_groups:
                resource_groups[resource_type] = []
            resource_groups[resource_type].append(resource)

        # Print each group
        for resource_type, resources in sorted(resource_groups.items()):
            print_colored(
                f"\n{resource_type.replace('_', ' ').title()}:", Colors.YELLOW
            )
            for resource in resources:
                print(f"  • {resource['name']}")

        print()
        print_colored(
            f"Total resources created: {len(self.created_resources)}",
            Colors.BOLD + Colors.GREEN,
        )
        print()

    def rollback(self) -> None:
        """
        Delete all created resources in reverse order on failure.
        """
        print_header("Rolling Back Deployment")

        # Reverse the list to delete in reverse order
        for resource in reversed(self.created_resources):
            resource_type = resource["type"]
            resource_name = resource["name"]

            try:
                print_info(f"Deleting {resource_type}: {resource_name}")

                if resource_type.startswith("s3_bucket_"):
                    # Empty bucket first
                    try:
                        objects = self.s3_client.list_objects_v2(Bucket=resource_name)
                        if "Contents" in objects:
                            delete_keys = [
                                {"Key": obj["Key"]} for obj in objects["Contents"]
                            ]
                            self.s3_client.delete_objects(
                                Bucket=resource_name, Delete={"Objects": delete_keys}
                            )
                    except Exception as e:
                        logger.debug(f"Error emptying bucket: {e}")

                    # Delete bucket
                    self.s3_client.delete_bucket(Bucket=resource_name)

                elif resource_type.startswith("dynamodb_table_"):
                    self.dynamodb_client.delete_table(TableName=resource_name)

                elif resource_type.startswith("iam_role_"):
                    # Detach policies first
                    try:
                        policies = self.iam_client.list_attached_role_policies(
                            RoleName=resource_name
                        )
                        for policy in policies["AttachedPolicies"]:
                            self.iam_client.detach_role_policy(
                                RoleName=resource_name, PolicyArn=policy["PolicyArn"]
                            )

                        inline_policies = self.iam_client.list_role_policies(
                            RoleName=resource_name
                        )
                        for policy_name in inline_policies["PolicyNames"]:
                            self.iam_client.delete_role_policy(
                                RoleName=resource_name, PolicyName=policy_name
                            )
                    except Exception as e:
                        logger.debug(f"Error detaching policies: {e}")

                    self.iam_client.delete_role(RoleName=resource_name)

                elif resource_type.startswith("lambda_function_"):
                    # Delete event source mappings
                    try:
                        mappings = self.lambda_client.list_event_source_mappings(
                            FunctionName=resource_name
                        )
                        for mapping in mappings["EventSourceMappings"]:
                            self.lambda_client.delete_event_source_mapping(
                                UUID=mapping["UUID"]
                            )
                    except Exception as e:
                        logger.debug(f"Error deleting event source mappings: {e}")

                    self.lambda_client.delete_function(FunctionName=resource_name)

                elif resource_type.startswith("eventbridge_rule_"):
                    # Remove targets first
                    try:
                        targets = self.events_client.list_targets_by_rule(
                            Rule=resource_name
                        )
                        if targets["Targets"]:
                            self.events_client.remove_targets(
                                Rule=resource_name,
                                Ids=[t["Id"] for t in targets["Targets"]],
                            )
                    except Exception as e:
                        logger.debug(f"Error removing targets: {e}")

                    self.events_client.delete_rule(Name=resource_name)

                elif resource_type == "sns_topic":
                    self.sns_client.delete_topic(TopicArn=resource_name)

                elif resource_type == "cloudtrail":
                    self.cloudtrail_client.stop_logging(Name=resource_name)
                    self.cloudtrail_client.delete_trail(Name=resource_name)

                elif resource_type == "config_recorder":
                    self.config_client.stop_configuration_recorder(
                        ConfigurationRecorderName=resource_name
                    )
                    self.config_client.delete_configuration_recorder(
                        ConfigurationRecorderName=resource_name
                    )

                elif resource_type == "config_channel":
                    self.config_client.delete_delivery_channel(
                        DeliveryChannelName=resource_name
                    )

                elif resource_type == "guardduty":
                    self.guardduty_client.delete_detector(DetectorId=resource_name)

                elif resource_type == "securityhub":
                    try:
                        self.securityhub_client.disable_security_hub()
                    except Exception as e:
                        logger.debug(f"Error disabling Security Hub: {e}")

                elif resource_type == "macie":
                    try:
                        self.macie_client.disable_macie()
                    except Exception as e:
                        logger.debug(f"Error disabling Macie: {e}")

                elif resource_type == "kms_key":
                    # Schedule key for deletion
                    self.kms_client.schedule_key_deletion(
                        KeyId=resource_name, PendingWindowInDays=7
                    )

                print_success(f"Deleted {resource_type}: {resource_name}")

            except Exception as e:
                print_error(f"Failed to delete {resource_type} {resource_name}: {e}")
                logger.error(f"Rollback error: {e}")

        # Delete config file
        try:
            os.remove("grc_config.json")
        except Exception:
            pass

        print_header("Rollback Complete")

    def deploy(self) -> None:
        """
        Deploy the complete GRC Evidence Platform.

        This method orchestrates the deployment of all resources in the correct order,
        with rollback on failure.
        """
        try:
            print_header("Starting GRC Evidence Platform Deployment")

            # Create resources in dependency order
            kms_key = self.create_kms_key()

            s3_buckets = self.create_s3_buckets()

            dynamodb_tables = self.create_dynamodb_tables()

            sns_topic = self.create_sns_topic()

            iam_roles = self.create_iam_roles()

            lambda_functions = self.create_lambda_functions()

            eventbridge_rules = self.create_eventbridge_rules()

            cloudtrail = self.enable_cloudtrail()

            config = self.enable_config()

            guardduty = self.enable_guardduty()

            securityhub = self.enable_securityhub()

            macie = self.enable_macie()

            # Save configuration
            self.save_config()

            # Print summary
            self.print_summary()

            print_header("Deployment Successful!")
            print_colored(
                "The GRC Evidence Platform v2.0 has been successfully deployed.",
                Colors.GREEN,
            )
            print()
            print_colored("Next steps:", Colors.BOLD)
            print_colored("1. Review the deployment summary above", Colors.CYAN)
            print_colored(
                "2. Test the collectors by running: python scripts/run_all_collectors.py",
                Colors.CYAN,
            )
            print_colored(
                "3. Generate your first report: python scripts/generate_report.py --type scorecard --period 24h",
                Colors.CYAN,
            )
            print_colored(
                "4. View the documentation in docs/ for more information", Colors.CYAN
            )
            print()

        except Exception as e:
            print_error(f"Deployment failed: {e}")
            logger.error(f"Deployment error: {e}", exc_info=True)
            print()
            print_colored("Initiating rollback...", Colors.YELLOW)
            self.rollback()
            print()
            print_error("Deployment failed and all resources have been rolled back.")
            sys.exit(1)


def main() -> None:
    """
    Main entry point for the setup script.
    """
    parser = argparse.ArgumentParser(
        description="Deploy the GRC Evidence Platform v2.0"
    )
    parser.add_argument(
        "--region",
        help="AWS region to deploy to (default: from AWS_DEFAULT_REGION or us-east-1)",
        default=None,
    )
    parser.add_argument(
        "--profile", help="AWS profile name to use (default: default)", default=None
    )

    args = parser.parse_args()

    try:
        setup = GRCPlatformSetup(region=args.region, profile=args.profile)
        setup.deploy()
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
