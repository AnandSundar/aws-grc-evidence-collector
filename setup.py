import boto3
import json
import uuid
import sys
import os
import zipfile
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


class GRCSetup:
    def __init__(self, profile=None):
        self.session = boto3.Session(profile_name=profile)
        self.region = self.session.region_name or "us-east-1"
        self.account_id = self.session.client("sts").get_caller_identity()["Account"]
        self.suffix = str(uuid.uuid4())[:8]
        self.config = {}

        self.s3 = self.session.client("s3", region_name=self.region)
        self.dynamodb = self.session.client("dynamodb", region_name=self.region)
        self.sns = self.session.client("sns", region_name=self.region)
        self.iam = self.session.client("iam", region_name=self.region)
        self.lambda_client = self.session.client("lambda", region_name=self.region)
        self.events = self.session.client("events", region_name=self.region)
        self.cloudtrail = self.session.client("cloudtrail", region_name=self.region)

    def create_s3_bucket(self):
        bucket_name = f"grc-evidence-{self.account_id}-{self.suffix}"
        print_info(f"Creating S3 bucket: {bucket_name}")
        try:
            if self.region == "us-east-1":
                self.s3.create_bucket(Bucket=bucket_name)
            else:
                self.s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": self.region},
                )

            self.s3.put_bucket_encryption(
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
            self.s3.put_bucket_versioning(
                Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
            )
            self.config["EvidenceBucket"] = bucket_name
            print_success(f"Created S3 bucket: {bucket_name}")
            return True
        except Exception as e:
            print_error(f"Failed to create S3 bucket: {e}")
            return False

    def create_dynamodb_table(self):
        table_name = f"GRC-Evidence-Metadata-{self.suffix}"
        print_info(f"Creating DynamoDB table: {table_name}")
        try:
            self.dynamodb.create_table(
                TableName=table_name,
                KeySchema=[
                    {"AttributeName": "evidence_id", "KeyType": "HASH"},
                    {"AttributeName": "timestamp", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "evidence_id", "AttributeType": "S"},
                    {"AttributeName": "timestamp", "AttributeType": "S"},
                    {"AttributeName": "event_type", "AttributeType": "S"},
                    {"AttributeName": "priority", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "EventTypeIndex",
                        "KeySchema": [
                            {"AttributeName": "event_type", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    },
                    {
                        "IndexName": "PriorityIndex",
                        "KeySchema": [
                            {"AttributeName": "priority", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    },
                ],
                BillingMode="PAY_PER_REQUEST",
            )
            waiter = self.dynamodb.get_waiter("table_exists")
            waiter.wait(TableName=table_name)

            self.dynamodb.update_time_to_live(
                TableName=table_name,
                TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
            )
            self.config["MetadataTable"] = table_name
            print_success(f"Created DynamoDB table: {table_name}")
            return True
        except Exception as e:
            print_error(f"Failed to create DynamoDB table: {e}")
            return False

    def create_sns_topic(self):
        topic_name = f"GRC-Compliance-Alerts-{self.suffix}"
        print_info(f"Creating SNS topic: {topic_name}")
        try:
            response = self.sns.create_topic(Name=topic_name)
            self.config["AlertTopicArn"] = response["TopicArn"]
            print_success(f"Created SNS topic: {topic_name}")
            return True
        except Exception as e:
            print_error(f"Failed to create SNS topic: {e}")
            return False

    def create_iam_role(self):
        role_name = f"GRC-Lambda-Role-{self.suffix}"
        print_info(f"Creating IAM role: {role_name}")
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        try:
            role = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy),
            )

            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{self.config['EvidenceBucket']}/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:PutItem",
                            "dynamodb:GetItem",
                            "dynamodb:Query",
                        ],
                        "Resource": f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{self.config['MetadataTable']}*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["sns:Publish"],
                        "Resource": self.config["AlertTopicArn"],
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    },
                ],
            }
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName="GRC-Lambda-Policy",
                PolicyDocument=json.dumps(policy),
            )
            self.config["LambdaRoleArn"] = role["Role"]["Arn"]
            print_success(f"Created IAM role: {role_name}")
            time.sleep(10)  # Wait for role to propagate
            return True
        except Exception as e:
            print_error(f"Failed to create IAM role: {e}")
            return False

    def create_lambda_function(self):
        func_name = f"GRC-Evidence-Processor-{self.suffix}"
        print_info(f"Creating Lambda function: {func_name}")
        try:
            with zipfile.ZipFile("function.zip", "w") as z:
                z.write("lambda/handler.py", "index.py")

            with open("function.zip", "rb") as f:
                zip_bytes = f.read()

            response = self.lambda_client.create_function(
                FunctionName=func_name,
                Runtime="python3.11",
                Role=self.config["LambdaRoleArn"],
                Handler="index.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=256,
                Environment={
                    "Variables": {
                        "EVIDENCE_BUCKET": self.config["EvidenceBucket"],
                        "METADATA_TABLE": self.config["MetadataTable"],
                        "ALERT_TOPIC_ARN": self.config["AlertTopicArn"],
                    }
                },
            )
            self.config["LambdaFunctionArn"] = response["FunctionArn"]
            self.config["LambdaFunctionName"] = func_name
            os.remove("function.zip")
            print_success(f"Created Lambda function: {func_name}")
            return True
        except Exception as e:
            print_error(f"Failed to create Lambda function: {e}")
            if os.path.exists("function.zip"):
                os.remove("function.zip")
            return False

    def create_eventbridge_rule(self):
        rule_name = f"GRC-CloudTrail-Rule-{self.suffix}"
        print_info(f"Creating EventBridge rule: {rule_name}")
        try:
            response = self.events.put_rule(
                Name=rule_name,
                EventPattern=json.dumps({"source": ["aws.cloudtrail"]}),
                State="ENABLED",
            )
            rule_arn = response["RuleArn"]

            self.lambda_client.add_permission(
                FunctionName=self.config["LambdaFunctionName"],
                StatementId=f"AllowEventBridge-{self.suffix}",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=rule_arn,
            )

            self.events.put_targets(
                Rule=rule_name,
                Targets=[{"Id": "1", "Arn": self.config["LambdaFunctionArn"]}],
            )
            self.config["EventBridgeRule"] = rule_name
            print_success(f"Created EventBridge rule: {rule_name}")
            return True
        except Exception as e:
            print_error(f"Failed to create EventBridge rule: {e}")
            return False

    def enable_cloudtrail(self):
        trail_name = f"GRC-Trail-{self.suffix}"
        print_info(f"Creating CloudTrail: {trail_name}")
        try:
            bucket_name = self.config["EvidenceBucket"]
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSCloudTrailAclCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket_name}",
                    },
                    {
                        "Sid": "AWSCloudTrailWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{self.account_id}/*",
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control"
                            }
                        },
                    },
                ],
            }
            self.s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

            self.cloudtrail.create_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
                IsMultiRegionTrail=False,
                IncludeGlobalServiceEvents=True,
            )
            self.cloudtrail.start_logging(Name=trail_name)
            self.config["CloudTrailName"] = trail_name
            print_success(f"Created and started CloudTrail: {trail_name}")
            return True
        except Exception as e:
            print_error(f"Failed to create CloudTrail: {e}")
            return False

    def run(self):
        print(f"\n{BOLD}GRC Evidence Collector Setup{RESET}")
        print("========================================\n")

        # Create resources in dependency order
        if not self.create_s3_bucket():
            self.teardown()
            return False

        if not self.create_dynamodb_table():
            self.teardown()
            return False

        if not self.create_sns_topic():
            self.teardown()
            return False

        if not self.create_iam_role():
            self.teardown()
            return False

        if not self.create_lambda_function():
            self.teardown()
            return False

        if not self.create_eventbridge_rule():
            self.teardown()
            return False

        if not self.enable_cloudtrail():
            self.teardown()
            return False

        # Save configuration and print summary
        self.save_config()
        self.print_summary()
        return True

    def teardown(self):
        print_warning("Setup failed. Tearing down created resources...")
        pass

    def save_config(self):
        with open("grc_config.json", "w") as f:
            json.dump(self.config, f, indent=2)
        print_success("Saved configuration to grc_config.json")

    def print_summary(self):
        print(f"\n{BOLD}GRC Evidence Collector Setup Complete!{RESET}")
        print(f"S3 Bucket: {self.config.get('EvidenceBucket')}")
        print(f"DynamoDB Table: {self.config.get('MetadataTable')}")
        print(f"SNS Topic: {self.config.get('AlertTopicArn')}")
        print(f"Lambda Function: {self.config.get('LambdaFunctionName')}")


import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS GRC Evidence Collector Setup")
    parser.add_argument("--profile", type=str, help="AWS CLI profile name")
    args = parser.parse_args()

    setup = GRCSetup(profile=args.profile)
    setup.run()
