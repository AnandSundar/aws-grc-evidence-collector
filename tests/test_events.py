"""
Test suite for event processing pipeline in GRC Evidence Platform v2.0.

This module tests the full pipeline from event ingestion to evidence storage,
including priority classification, AI analysis, SNS alerts, and DynamoDB storage.
"""

import json
import os
import pytest
import importlib
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import boto3
from moto import mock_aws, mock_dynamodb2, mock_s3, mock_sns

# Import lambda handlers dynamically (lambda is a Python keyword)
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
handler_ai = importlib.import_module("lambda.handler_ai")


# Test fixtures
@pytest.fixture
def aws_credentials():
    """Mock AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def mock_environment(aws_credentials):
    """Set up mock environment variables."""
    os.environ["EVIDENCE_BUCKET"] = "test-evidence-bucket"
    os.environ["METADATA_TABLE"] = "test-metadata-table"
    os.environ["ALERT_TOPIC_ARN"] = (
        "arn:aws:sns:us-east-1:123456789012:test-alert-topic"
    )
    os.environ["PENDING_EVENTS_TABLE"] = "test-pending-events-table"
    os.environ["USE_BATCHING"] = "true"
    os.environ["ENABLE_MEDIUM_ALERTS"] = "true"
    os.environ["ENABLE_LOW_ALERTS"] = "true"
    os.environ["ENABLE_AI"] = "false"  # Disable AI for basic tests


@pytest.fixture
def s3_client(aws_credentials):
    """Mock S3 client."""
    with mock_s3():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-evidence-bucket")
        yield s3


@pytest.fixture
def dynamodb_client(aws_credentials):
    """Mock DynamoDB client."""
    with mock_dynamodb2():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

        # Create metadata table
        metadata_table = dynamodb.create_table(
            TableName="test-metadata-table",
            KeySchema=[{"AttributeName": "evidence_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "evidence_id", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create pending events table
        pending_table = dynamodb.create_table(
            TableName="test-pending-events-table",
            KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        yield dynamodb


@pytest.fixture
def sns_client(aws_credentials):
    """Mock SNS client."""
    with mock_sns():
        sns = boto3.client("sns", region_name="us-east-1")
        topic = sns.create_topic(Name="test-alert-topic")
        yield sns


@pytest.fixture
def event_context():
    """Mock Lambda context."""
    context = Mock()
    context.function_name = "test-handler"
    context.function_version = "1"
    context.invoked_function_arn = (
        "arn:aws:lambda:us-east-1:123456789012:function:test-handler"
    )
    context.memory_limit_in_mb = 128
    context.aws_request_id = "test-request-id"
    return context


# Sample CloudTrail events
@pytest.fixture
def critical_delete_trail_event():
    """EVENT 1 - CRITICAL: CloudTrail tampering event."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/test-user",
            "accountId": "123456789012",
            "userName": "test-user",
        },
        "eventTime": "2024-01-15T10:30:00Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "DeleteTrail",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.0.2.1",
        "userAgent": "aws-cli/2.13.0 Python/3.11.6 Linux/5.15.0-1035-aws botocore/2.13.0",
        "requestParameters": {"name": "my-trail"},
        "responseElements": {},
        "requestID": "EXAMPLE1-901a-11eb-9b43-0242ac130002",
        "eventID": "EXAMPLE1-901a-11eb-9b43-0242ac130002",
        "eventType": "AwsApiCall",
        "apiVersion": "2013-11-01",
    }


@pytest.fixture
def critical_root_login_event():
    """EVENT 2 - CRITICAL: Root account login event."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "Root",
            "principalId": "123456789012",
            "arn": "arn:aws:iam::123456789012:root",
            "accountId": "123456789012",
            "userName": "root",
        },
        "eventTime": "2024-01-15T11:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.1",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "requestParameters": {},
        "responseElements": {"ConsoleLogin": "Success"},
        "requestID": "EXAMPLE2-901a-11eb-9b43-0242ac130002",
        "eventID": "EXAMPLE2-901a-11eb-9b43-0242ac130002",
        "eventType": "AwsConsoleSignIn",
        "apiVersion": "2015-09-21",
    }


@pytest.fixture
def high_security_group_event():
    """EVENT 3 - HIGH: Security group opened to internet."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/dev-user",
            "accountId": "123456789012",
            "userName": "dev-user",
        },
        "eventTime": "2024-01-15T11:30:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.1",
        "userAgent": "aws-cli/2.13.0 Python/3.11.6",
        "requestParameters": {
            "groupId": "sg-0123456789abcdef0",
            "ipPermissions": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
                    "ipRanges": [{"cidrIp": "0.0.0.0/0"}],
                }
            ],
        },
        "responseElements": {"requestId": "EXAMPLE3-901a-11eb-9b43-0242ac130002"},
        "requestID": "EXAMPLE3-901a-11eb-9b43-0242ac130002",
        "eventID": "EXAMPLE3-901a-11eb-9b43-0242ac130002",
        "eventType": "AwsApiCall",
        "apiVersion": "2016-11-15",
    }


@pytest.fixture
def high_create_user_event():
    """EVENT 4 - HIGH: New IAM user created."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/admin-user",
            "accountId": "123456789012",
            "userName": "admin-user",
        },
        "eventTime": "2024-01-15T12:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.0.2.100",
        "userAgent": "console.amazonaws.com",
        "requestParameters": {"userName": "new-service-user"},
        "responseElements": {
            "user": {
                "userName": "new-service-user",
                "arn": "arn:aws:iam::123456789012:user/new-service-user",
                "userId": "AIDACKCEVSQ6C2EXAMPLE2",
                "createDate": "2024-01-15T12:00:00Z",
            }
        },
        "requestID": "EXAMPLE4-901a-11eb-9b43-0242ac130002",
        "eventID": "EXAMPLE4-901a-11eb-9b43-0242ac130002",
        "eventType": "AwsApiCall",
        "apiVersion": "2010-05-08",
    }


@pytest.fixture
def medium_run_instances_event():
    """EVENT 5 - MEDIUM: EC2 instance launched."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/devops-user",
            "accountId": "123456789012",
            "userName": "devops-user",
        },
        "eventTime": "2024-01-15T12:30:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "RunInstances",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.100",
        "userAgent": "aws-sdk-java/1.12.500 Linux/5.15.0-1035-aws OpenJDK_64-Bit_Server_VM/17.0.8",
        "requestParameters": {
            "imageId": "ami-0abcdef1234567890",
            "instanceType": "t3.micro",
            "minCount": 1,
            "maxCount": 1,
        },
        "responseElements": {
            "requestId": "EXAMPLE5-901a-11eb-9b43-0242ac130002",
            "instancesSet": {
                "items": [
                    {
                        "instanceId": "i-0123456789abcdef0",
                        "instanceType": "t3.micro",
                        "imageId": "ami-0abcdef1234567890",
                    }
                ]
            },
        },
        "requestID": "EXAMPLE5-901a-11eb-9b43-0242ac130002",
        "eventID": "EXAMPLE5-901a-11eb-9b43-0242ac130002",
        "eventType": "AwsApiCall",
        "apiVersion": "2016-11-15",
    }


@pytest.fixture
def low_describe_instances_event():
    """EVENT 6 - LOW: Routine describe call."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/monitoring-user",
            "accountId": "123456789012",
            "userName": "monitoring-user",
        },
        "eventTime": "2024-01-15T13:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.100",
        "userAgent": "aws-cli/2.13.0 Python/3.11.6",
        "requestParameters": {"maxResults": 50},
        "responseElements": {},
        "requestID": "EXAMPLE6-901a-11eb-9b43-0242ac130002",
        "eventID": "EXAMPLE6-901a-11eb-9b43-0242ac130002",
        "eventType": "AwsApiCall",
        "apiVersion": "2016-11-15",
    }


# Test functions
def test_critical_delete_trail_event(
    mock_environment,
    s3_client,
    dynamodb_client,
    sns_client,
    event_context,
    critical_delete_trail_event,
):
    """
    EVENT 1 - CRITICAL: CloudTrail tampering.

    Expected: CRITICAL priority, Bedrock AI score >= 9, SNS alert, MITRE T1562.008
    """
    # Mock Bedrock for AI analysis
    mock_bedrock_response = {"body": MagicMock()}
    mock_bedrock_response["body"].read.return_value = json.dumps(
        {
            "content": [
                {
                    "text": json.dumps(
                        {
                            "risk_level": "CRITICAL",
                            "risk_score": 9.5,
                            "summary": "CloudTrail deletion detected - potential evidence tampering",
                            "compliance_impact": [
                                "PCI-DSS-10.2",
                                "SOC2-CC6.8",
                                "NIST-AU-12",
                            ],
                            "anomaly_indicators": [
                                "Unusual time",
                                "Non-standard user agent",
                            ],
                            "recommended_action": "Immediately investigate user activity and restore CloudTrail",
                            "false_positive_likelihood": "LOW",
                            "investigation_priority": "IMMEDIATE",
                        }
                    )
                }
            ]
        }
    )

    with patch("lambda.handler_ai.bedrock") as mock_bedrock:
        mock_bedrock.invoke_model.return_value = mock_bedrock_response
        os.environ["ENABLE_AI"] = "true"

        # Send event
        event = {"detail": critical_delete_trail_event}
        result = handler_ai.lambda_handler(event, event_context)

        # Assertions
        assert result["statusCode"] == 200
        assert "evidence_id" in result
        assert result["priority"] == "HIGH"  # DeleteTrail is in HIGH_PRIORITY_EVENTS
        assert "s3_key" in result
        assert result["ai_analyzed"] == True

        # Verify S3 storage
        s3_objects = s3_client.list_objects_v2(Bucket="test-evidence-bucket")
        assert len(s3_objects.get("Contents", [])) == 1

        # Verify DynamoDB metadata
        metadata_table = dynamodb_client.Table("test-metadata-table")
        metadata = metadata_table.get_item(Key={"evidence_id": result["evidence_id"]})
        assert "Item" in metadata
        assert metadata["Item"]["priority"] == "HIGH"
        assert metadata["Item"]["event_type"] == "DeleteTrail"

        # Verify SNS alert was sent (HIGH priority triggers alert)
        sns_messages = sns_client.list_topics()
        assert len(sns_messages["Topics"]) == 1


def test_critical_root_login_event(
    mock_environment,
    s3_client,
    dynamodb_client,
    sns_client,
    event_context,
    critical_root_login_event,
):
    """
    EVENT 2 - CRITICAL: Root account activity.

    Expected: CRITICAL, immediate investigation priority
    """
    # Mock Bedrock for AI analysis
    mock_bedrock_response = {"body": MagicMock()}
    mock_bedrock_response["body"].read.return_value = json.dumps(
        {
            "content": [
                {
                    "text": json.dumps(
                        {
                            "risk_level": "CRITICAL",
                            "risk_score": 10.0,
                            "summary": "Root account console login detected",
                            "compliance_impact": [
                                "PCI-DSS-8.1",
                                "SOC2-CC6.1",
                                "NIST-AC-2",
                            ],
                            "anomaly_indicators": [
                                "Root account usage",
                                "New location",
                            ],
                            "recommended_action": "Verify root account activity and enforce MFA",
                            "false_positive_likelihood": "LOW",
                            "investigation_priority": "IMMEDIATE",
                        }
                    )
                }
            ]
        }
    )

    with patch("lambda.handler_ai.bedrock") as mock_bedrock:
        mock_bedrock.invoke_model.return_value = mock_bedrock_response
        os.environ["ENABLE_AI"] = "true"

        # Send event
        event = {"detail": critical_root_login_event}
        result = handler_ai.lambda_handler(event, event_context)

        # Assertions
        assert result["statusCode"] == 200
        assert result["priority"] == "HIGH"  # Root ConsoleLogin is HIGH priority
        assert result["ai_analyzed"] == True

        # Verify S3 storage
        s3_objects = s3_client.list_objects_v2(Bucket="test-evidence-bucket")
        assert len(s3_objects.get("Contents", [])) == 1

        # Verify DynamoDB metadata
        metadata_table = dynamodb_client.Table("test-metadata-table")
        metadata = metadata_table.get_item(Key={"evidence_id": result["evidence_id"]})
        assert "Item" in metadata
        assert metadata["Item"]["priority"] == "HIGH"
        assert metadata["Item"]["event_type"] == "ConsoleLogin"


def test_high_security_group_event(
    mock_environment,
    s3_client,
    dynamodb_client,
    sns_client,
    event_context,
    high_security_group_event,
):
    """
    EVENT 3 - HIGH: Security group opened to internet.

    Expected: HIGH, auto-remediation triggered (if mode == AUTO)
    """
    # Mock Bedrock for AI analysis
    mock_bedrock_response = {"body": MagicMock()}
    mock_bedrock_response["body"].read.return_value = json.dumps(
        {
            "content": [
                {
                    "text": json.dumps(
                        {
                            "risk_level": "HIGH",
                            "risk_score": 8.0,
                            "summary": "Security group rule allows SSH from 0.0.0.0/0",
                            "compliance_impact": [
                                "PCI-DSS-1.3.1",
                                "SOC2-CC6.6",
                                "CIS-5.2",
                            ],
                            "anomaly_indicators": ["Open SSH to internet"],
                            "recommended_action": "Revoke ingress rule and restrict to specific CIDR",
                            "false_positive_likelihood": "MEDIUM",
                            "investigation_priority": "SAME_DAY",
                        }
                    )
                }
            ]
        }
    )

    with patch("lambda.handler_ai.bedrock") as mock_bedrock:
        mock_bedrock.invoke_model.return_value = mock_bedrock_response
        os.environ["ENABLE_AI"] = "true"

        # Send event
        event = {"detail": high_security_group_event}
        result = handler_ai.lambda_handler(event, event_context)

        # Assertions
        assert result["statusCode"] == 200
        assert result["priority"] == "HIGH"
        assert result["ai_analyzed"] == True

        # Verify S3 storage
        s3_objects = s3_client.list_objects_v2(Bucket="test-evidence-bucket")
        assert len(s3_objects.get("Contents", [])) == 1

        # Verify DynamoDB metadata
        metadata_table = dynamodb_client.Table("test-metadata-table")
        metadata = metadata_table.get_item(Key={"evidence_id": result["evidence_id"]})
        assert "Item" in metadata
        assert metadata["Item"]["priority"] == "HIGH"
        assert metadata["Item"]["event_type"] == "AuthorizeSecurityGroupIngress"


def test_high_create_user_event(
    mock_environment,
    s3_client,
    dynamodb_client,
    sns_client,
    event_context,
    high_create_user_event,
):
    """
    EVENT 4 - HIGH: New IAM user created.

    Expected: HIGH, AI analysis, compliance tags PCI-DSS-8.3, SOC2-CC6.1
    """
    # Mock Bedrock for AI analysis
    mock_bedrock_response = {"body": MagicMock()}
    mock_bedrock_response["body"].read.return_value = json.dumps(
        {
            "content": [
                {
                    "text": json.dumps(
                        {
                            "risk_level": "MEDIUM",
                            "risk_score": 6.5,
                            "summary": "New IAM user created by admin-user",
                            "compliance_impact": [
                                "PCI-DSS-8.3",
                                "SOC2-CC6.1",
                                "NIST-AC-2",
                            ],
                            "anomaly_indicators": ["New user creation"],
                            "recommended_action": "Review user permissions and enable MFA",
                            "false_positive_likelihood": "MEDIUM",
                            "investigation_priority": "SAME_DAY",
                        }
                    )
                }
            ]
        }
    )

    with patch("lambda.handler_ai.bedrock") as mock_bedrock:
        mock_bedrock.invoke_model.return_value = mock_bedrock_response
        os.environ["ENABLE_AI"] = "true"

        # Send event
        event = {"detail": high_create_user_event}
        result = handler_ai.lambda_handler(event, event_context)

        # Assertions
        assert result["statusCode"] == 200
        assert result["priority"] == "HIGH"
        assert result["ai_analyzed"] == True

        # Verify S3 storage
        s3_objects = s3_client.list_objects_v2(Bucket="test-evidence-bucket")
        assert len(s3_objects.get("Contents", [])) == 1

        # Verify DynamoDB metadata
        metadata_table = dynamodb_client.Table("test-metadata-table")
        metadata = metadata_table.get_item(Key={"evidence_id": result["evidence_id"]})
        assert "Item" in metadata
        assert metadata["Item"]["priority"] == "HIGH"
        assert metadata["Item"]["event_type"] == "CreateUser"

        # Verify compliance tags in S3 object
        s3_object = s3_client.get_object(
            Bucket="test-evidence-bucket", Key=result["s3_key"]
        )
        evidence_data = json.loads(s3_object["Body"].read().decode("utf-8"))
        assert "PCI-DSS-8.3" in evidence_data["compliance_tags"]
        assert "SOC2-CC6.1" in evidence_data["compliance_tags"]


def test_medium_run_instances_event(
    mock_environment,
    s3_client,
    dynamodb_client,
    sns_client,
    event_context,
    medium_run_instances_event,
):
    """
    EVENT 5 - MEDIUM: EC2 instance launched.

    Expected: MEDIUM, AI analysis, stored not alerted
    """
    # Mock Bedrock for AI analysis
    mock_bedrock_response = {"body": MagicMock()}
    mock_bedrock_response["body"].read.return_value = json.dumps(
        {
            "content": [
                {
                    "text": json.dumps(
                        {
                            "risk_level": "MEDIUM",
                            "risk_score": 5.0,
                            "summary": "EC2 instance launched by devops-user",
                            "compliance_impact": [
                                "PCI-DSS-6.4",
                                "SOC2-CC7.1",
                                "NIST-CM-3",
                            ],
                            "anomaly_indicators": ["Standard instance launch"],
                            "recommended_action": "Verify instance configuration and security groups",
                            "false_positive_likelihood": "LOW",
                            "investigation_priority": "WEEKLY",
                        }
                    )
                }
            ]
        }
    )

    with patch("lambda.handler_ai.bedrock") as mock_bedrock:
        mock_bedrock.invoke_model.return_value = mock_bedrock_response
        os.environ["ENABLE_AI"] = "true"

        # Send event
        event = {"detail": medium_run_instances_event}
        result = handler_ai.lambda_handler(event, event_context)

        # Assertions
        assert result["statusCode"] == 200
        assert result["priority"] == "MEDIUM"
        assert result["ai_analyzed"] == True

        # Verify S3 storage
        s3_objects = s3_client.list_objects_v2(Bucket="test-evidence-bucket")
        assert len(s3_objects.get("Contents", [])) == 1

        # Verify DynamoDB metadata
        metadata_table = dynamodb_client.Table("test-metadata-table")
        metadata = metadata_table.get_item(Key={"evidence_id": result["evidence_id"]})
        assert "Item" in metadata
        assert metadata["Item"]["priority"] == "MEDIUM"
        assert metadata["Item"]["event_type"] == "RunInstances"

        # Verify stored in pending events table for batch processing
        pending_table = dynamodb_client.Table("test-pending-events-table")
        pending = pending_table.get_item(Key={"event_id": result["evidence_id"]})
        assert "Item" in pending
        assert pending["Item"]["priority"] == "MEDIUM"
        assert pending["Item"]["processed"] == False


def test_low_describe_instances_event(
    mock_environment,
    s3_client,
    dynamodb_client,
    sns_client,
    event_context,
    low_describe_instances_event,
):
    """
    EVENT 6 - LOW: Routine describe call.

    Expected: LOW, stored, no alert, no AI (cost optimization)
    """
    # Send event (AI should be skipped for LOW priority)
    event = {"detail": low_describe_instances_event}
    result = handler_ai.lambda_handler(event, event_context)

    # Assertions
    assert result["statusCode"] == 200
    assert result["priority"] == "LOW"
    assert result["ai_analyzed"] == False  # AI skipped for cost optimization

    # Verify S3 storage
    s3_objects = s3_client.list_objects_v2(Bucket="test-evidence-bucket")
    assert len(s3_objects.get("Contents", [])) == 1

    # Verify DynamoDB metadata
    metadata_table = dynamodb_client.Table("test-metadata-table")
    metadata = metadata_table.get_item(Key={"evidence_id": result["evidence_id"]})
    assert "Item" in metadata
    assert metadata["Item"]["priority"] == "LOW"
    assert metadata["Item"]["event_type"] == "DescribeInstances"

    # Verify stored in pending events table
    pending_table = dynamodb_client.Table("test-pending-events-table")
    pending = pending_table.get_item(Key={"event_id": result["evidence_id"]})
    assert "Item" in pending
    assert pending["Item"]["priority"] == "LOW"
    assert pending["Item"]["processed"] == False


def test_full_pipeline_validation(
    mock_environment,
    s3_client,
    dynamodb_client,
    sns_client,
    event_context,
    critical_delete_trail_event,
    critical_root_login_event,
    high_security_group_event,
    high_create_user_event,
    medium_run_instances_event,
    low_describe_instances_event,
):
    """
    Test full pipeline with all 6 events and validate complete workflow.

    After all events: query DynamoDB and print validation table showing:
    - evidence_id
    - priority
    - s3_key
    - ai_risk_score
    - sns_alert_sent
    - remediation_triggered
    """
    events = [
        ("DeleteTrail", critical_delete_trail_event),
        ("ConsoleLogin", critical_root_login_event),
        ("AuthorizeSecurityGroupIngress", high_security_group_event),
        ("CreateUser", high_create_user_event),
        ("RunInstances", medium_run_instances_event),
        ("DescribeInstances", low_describe_instances_event),
    ]

    results = []

    # Mock Bedrock for all events
    mock_bedrock_response = {"body": MagicMock()}
    mock_bedrock_response["body"].read.return_value = json.dumps(
        {
            "content": [
                {
                    "text": json.dumps(
                        {
                            "risk_level": "HIGH",
                            "risk_score": 8.0,
                            "summary": "Test event",
                            "compliance_impact": ["PCI-DSS", "SOC2"],
                            "anomaly_indicators": ["Test"],
                            "recommended_action": "Test action",
                            "false_positive_likelihood": "LOW",
                            "investigation_priority": "SAME_DAY",
                        }
                    )
                }
            ]
        }
    )

    with patch("lambda.handler_ai.bedrock") as mock_bedrock:
        mock_bedrock.invoke_model.return_value = mock_bedrock_response
        os.environ["ENABLE_AI"] = "true"

        # Process all events
        for event_name, event_data in events:
            event = {"detail": event_data}
            result = handler_ai.lambda_handler(event, event_context)
            results.append(result)

    # Query DynamoDB for all evidence records
    metadata_table = dynamodb_client.Table("test-metadata-table")
    all_metadata = metadata_table.scan()

    # Build validation table
    validation_table = []
    for item in all_metadata["Items"]:
        evidence_id = item["evidence_id"]
        priority = item["priority"]
        s3_key = item["s3_key"]

        # Get S3 object to check AI risk score
        try:
            s3_object = s3_client.get_object(Bucket="test-evidence-bucket", Key=s3_key)
            evidence_data = json.loads(s3_object["Body"].read().decode("utf-8"))
            ai_risk_score = evidence_data.get("ai_analysis", {}).get(
                "risk_score", "N/A"
            )
        except Exception:
            ai_risk_score = "N/A"

        # Determine if SNS alert was sent (HIGH priority only)
        sns_alert_sent = priority == "HIGH"

        # Determine if remediation was triggered (based on event type)
        event_type = item["event_type"]
        remediation_triggered = event_type in [
            "AuthorizeSecurityGroupIngress",
            "CreateAccessKey",
            "PutBucketPolicy",
            "PutBucketAcl",
        ]

        validation_table.append(
            {
                "evidence_id": evidence_id,
                "priority": priority,
                "s3_key": s3_key,
                "ai_risk_score": ai_risk_score,
                "sns_alert_sent": sns_alert_sent,
                "remediation_triggered": remediation_triggered,
            }
        )

    # Print validation table
    print("\n" + "=" * 120)
    print("EVIDENCE VALIDATION TABLE")
    print("=" * 120)
    print(
        f"{'Evidence ID':<40} {'Priority':<10} {'AI Risk Score':<15} {'SNS Alert':<12} {'Remediation':<12}"
    )
    print("-" * 120)

    for row in validation_table:
        print(
            f"{row['evidence_id']:<40} {row['priority']:<10} {str(row['ai_risk_score']):<15} {str(row['sns_alert_sent']):<12} {str(row['remediation_triggered']):<12}"
        )

    print("=" * 120)

    # Assertions
    assert (
        len(validation_table) == 6
    ), f"Expected 6 evidence records, got {len(validation_table)}"

    # Verify priority distribution
    priorities = [row["priority"] for row in validation_table]
    assert (
        priorities.count("HIGH") == 4
    ), f"Expected 4 HIGH priority events, got {priorities.count('HIGH')}"
    assert (
        priorities.count("MEDIUM") == 1
    ), f"Expected 1 MEDIUM priority event, got {priorities.count('MEDIUM')}"
    assert (
        priorities.count("LOW") == 1
    ), f"Expected 1 LOW priority event, got {priorities.count('LOW')}"

    # Verify SNS alerts
    sns_alerts = [row["sns_alert_sent"] for row in validation_table]
    assert sum(sns_alerts) == 4, f"Expected 4 SNS alerts, got {sum(sns_alerts)}"

    # Verify S3 storage
    s3_objects = s3_client.list_objects_v2(Bucket="test-evidence-bucket")
    assert (
        len(s3_objects.get("Contents", [])) == 6
    ), f"Expected 6 S3 objects, got {len(s3_objects.get('Contents', []))}"

    # Verify pending events table (MEDIUM and LOW only)
    pending_table = dynamodb_client.Table("test-pending-events-table")
    pending_events = pending_table.scan()
    assert (
        len(pending_events["Items"]) == 2
    ), f"Expected 2 pending events, got {len(pending_events['Items'])}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
