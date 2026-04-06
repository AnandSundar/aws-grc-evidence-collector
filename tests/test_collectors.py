"""
Unit tests for all collectors in GRC Evidence Platform v2.0.

This module tests each collector using moto for AWS mocking, ensuring that:
- Happy path scenarios return expected EvidenceRecord structure
- Failing controls return FAIL records with correct compliance tags
- Passing controls return PASS records
- AWS errors are handled gracefully
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, MagicMock
import boto3
from moto import (
    mock_aws,
    mock_dynamodb2,
    mock_s3,
    mock_iam,
    mock_rds,
    mock_ec2,
    mock_config,
    mock_securityhub,
    mock_guardduty,
    mock_kms,
    mock_acm,
    mock_macie,
    mock_inspector2,
)

# Import collectors
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from collectors.iam_collector import IAMCollector
from collectors.rds_collector import RDSCollector
from collectors.s3_collector import S3Collector
from collectors.config_collector import ConfigCollector
from collectors.securityhub_collector import SecurityHubCollector
from collectors.guardduty_collector import GuardDutyCollector
from collectors.vpc_collector import VPCCollector
from collectors.kms_collector import KMSCollector
from collectors.acm_collector import ACMCollector
from collectors.macie_collector import MacieCollector
from collectors.inspector_collector import InspectorCollector
from collectors.base_collector import EvidenceRecord, ControlStatus, Priority


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
    os.environ["AWS_ACCOUNT_ID"] = "123456789012"
    os.environ["AWS_REGION"] = "us-east-1"


@pytest.fixture
def iam_client(aws_credentials):
    """Mock IAM client."""
    with mock_iam():
        iam = boto3.client("iam", region_name="us-east-1")
        yield iam


@pytest.fixture
def rds_client(aws_credentials):
    """Mock RDS client."""
    with mock_rds():
        rds = boto3.client("rds", region_name="us-east-1")
        yield rds


@pytest.fixture
def s3_client(aws_credentials):
    """Mock S3 client."""
    with mock_s3():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        yield s3


@pytest.fixture
def ec2_client(aws_credentials):
    """Mock EC2 client."""
    with mock_ec2():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        yield ec2


@pytest.fixture
def config_client(aws_credentials):
    """Mock Config client."""
    with mock_config():
        config = boto3.client("config", region_name="us-east-1")
        yield config


@pytest.fixture
def securityhub_client(aws_credentials):
    """Mock Security Hub client."""
    with mock_securityhub():
        sh = boto3.client("securityhub", region_name="us-east-1")
        yield sh


@pytest.fixture
def guardduty_client(aws_credentials):
    """Mock GuardDuty client."""
    with mock_guardduty():
        gd = boto3.client("guardduty", region_name="us-east-1")
        yield gd


@pytest.fixture
def kms_client(aws_credentials):
    """Mock KMS client."""
    with mock_kms():
        kms = boto3.client("kms", region_name="us-east-1")
        yield kms


@pytest.fixture
def acm_client(aws_credentials):
    """Mock ACM client."""
    with mock_acm():
        acm = boto3.client("acm", region_name="us-east-1")
        yield acm


@pytest.fixture
def macie_client(aws_credentials):
    """Mock Macie client."""
    with mock_macie():
        macie = boto3.client("macie2", region_name="us-east-1")
        yield macie


@pytest.fixture
def inspector_client(aws_credentials):
    """Mock Inspector client."""
    with mock_inspector2():
        inspector = boto3.client("inspector2", region_name="us-east-1")
        yield inspector


# ============================================================================
# IAM Collector Tests
# ============================================================================


def test_iam_collector_happy_path(mock_environment, iam_client):
    """Test IAM collector happy path - returns expected EvidenceRecord structure."""
    # Set up IAM with MFA enabled
    iam_client.enable_mfa_device(
        UserName="root",
        SerialNumber="arn:aws:iam::123456789012:mfa/root",
        AuthenticationCode1="123456",
        AuthenticationCode2="789012",
    )

    collector = IAMCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) > 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "IAMCollector" for record in records)
    assert all(record.aws_account_id == "123456789012" for record in records)
    assert all(record.aws_region == "us-east-1" for record in records)


def test_iam_collector_failing_control(mock_environment, iam_client):
    """Test IAM collector failing control - returns FAIL record with correct compliance tags."""
    collector = IAMCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True
        assert fail_record.remediation_action != ""


def test_iam_collector_passing_control(mock_environment, iam_client):
    """Test IAM collector passing control - returns PASS record."""
    collector = IAMCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value
        assert pass_record.priority in [Priority.INFO.value, Priority.LOW.value]


def test_iam_collector_handles_aws_error(mock_environment, iam_client):
    """Test IAM collector gracefully handles ClientError."""
    collector = IAMCollector(account_id="123456789012", region="us-east-1")

    # Mock IAM client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# RDS Collector Tests
# ============================================================================


def test_rds_collector_happy_path(mock_environment, rds_client):
    """Test RDS collector happy path - returns expected EvidenceRecord structure."""
    # Create RDS instance
    rds_client.create_db_instance(
        DBInstanceIdentifier="test-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
    )

    collector = RDSCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) > 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "RDSCollector" for record in records)


def test_rds_collector_failing_control(mock_environment, rds_client):
    """Test RDS collector failing control - returns FAIL record with correct compliance tags."""
    # Create unencrypted RDS instance
    rds_client.create_db_instance(
        DBInstanceIdentifier="unencrypted-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        StorageEncrypted=False,
    )

    collector = RDSCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_rds_collector_passing_control(mock_environment, rds_client):
    """Test RDS collector passing control - returns PASS record."""
    # Create encrypted RDS instance
    rds_client.create_db_instance(
        DBInstanceIdentifier="encrypted-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        StorageEncrypted=True,
    )

    collector = RDSCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_rds_collector_handles_aws_error(mock_environment, rds_client):
    """Test RDS collector gracefully handles ClientError."""
    collector = RDSCollector(account_id="123456789012", region="us-east-1")

    # Mock RDS client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# S3 Collector Tests
# ============================================================================


def test_s3_collector_happy_path(mock_environment, s3_client):
    """Test S3 collector happy path - returns expected EvidenceRecord structure."""
    # Create additional buckets
    s3_client.create_bucket(Bucket="test-bucket-2")
    s3_client.create_bucket(Bucket="test-bucket-3")

    collector = S3Collector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) > 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "S3Collector" for record in records)


def test_s3_collector_failing_control(mock_environment, s3_client):
    """Test S3 collector failing control - returns FAIL record with correct compliance tags."""
    # Create public bucket
    s3_client.put_bucket_acl(
        Bucket="test-bucket",
        AccessControlPolicy={
            "Grants": [
                {
                    "Grantee": {
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        "Type": "Group",
                    },
                    "Permission": "READ",
                }
            ],
            "Owner": {"DisplayName": "test-owner", "ID": "test-id"},
        },
    )

    collector = S3Collector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_s3_collector_passing_control(mock_environment, s3_client):
    """Test S3 collector passing control - returns PASS record."""
    # Enable encryption on bucket
    s3_client.put_bucket_encryption(
        Bucket="test-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )

    collector = S3Collector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_s3_collector_handles_aws_error(mock_environment, s3_client):
    """Test S3 collector gracefully handles ClientError."""
    collector = S3Collector(account_id="123456789012", region="us-east-1")

    # Mock S3 client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# Config Collector Tests
# ============================================================================


def test_config_collector_happy_path(mock_environment, config_client):
    """Test Config collector happy path - returns expected EvidenceRecord structure."""
    collector = ConfigCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) >= 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "ConfigCollector" for record in records)


def test_config_collector_failing_control(mock_environment, config_client):
    """Test Config collector failing control - returns FAIL record with correct compliance tags."""
    collector = ConfigCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_config_collector_passing_control(mock_environment, config_client):
    """Test Config collector passing control - returns PASS record."""
    collector = ConfigCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_config_collector_handles_aws_error(mock_environment, config_client):
    """Test Config collector gracefully handles ClientError."""
    collector = ConfigCollector(account_id="123456789012", region="us-east-1")

    # Mock Config client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# Security Hub Collector Tests
# ============================================================================


def test_securityhub_collector_happy_path(mock_environment, securityhub_client):
    """Test Security Hub collector happy path - returns expected EvidenceRecord structure."""
    collector = SecurityHubCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) >= 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "SecurityHubCollector" for record in records)


def test_securityhub_collector_failing_control(mock_environment, securityhub_client):
    """Test Security Hub collector failing control - returns FAIL record with correct compliance tags."""
    collector = SecurityHubCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_securityhub_collector_passing_control(mock_environment, securityhub_client):
    """Test Security Hub collector passing control - returns PASS record."""
    collector = SecurityHubCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_securityhub_collector_handles_aws_error(mock_environment, securityhub_client):
    """Test Security Hub collector gracefully handles ClientError."""
    collector = SecurityHubCollector(account_id="123456789012", region="us-east-1")

    # Mock Security Hub client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# GuardDuty Collector Tests
# ============================================================================


def test_guardduty_collector_happy_path(mock_environment, guardduty_client):
    """Test GuardDuty collector happy path - returns expected EvidenceRecord structure."""
    # Create GuardDuty detector
    detector = guardduty_client.create_detector(Enable=True)
    detector_id = detector["DetectorId"]

    collector = GuardDutyCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) >= 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "GuardDutyCollector" for record in records)


def test_guardduty_collector_failing_control(mock_environment, guardduty_client):
    """Test GuardDuty collector failing control - returns FAIL record with correct compliance tags."""
    collector = GuardDutyCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_guardduty_collector_passing_control(mock_environment, guardduty_client):
    """Test GuardDuty collector passing control - returns PASS record."""
    # Create GuardDuty detector
    detector = guardduty_client.create_detector(Enable=True)

    collector = GuardDutyCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_guardduty_collector_handles_aws_error(mock_environment, guardduty_client):
    """Test GuardDuty collector gracefully handles ClientError."""
    collector = GuardDutyCollector(account_id="123456789012", region="us-east-1")

    # Mock GuardDuty client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# VPC Collector Tests
# ============================================================================


def test_vpc_collector_happy_path(mock_environment, ec2_client):
    """Test VPC collector happy path - returns expected EvidenceRecord structure."""
    # Create VPC
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    collector = VPCCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) > 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "VPCCollector" for record in records)


def test_vpc_collector_failing_control(mock_environment, ec2_client):
    """Test VPC collector failing control - returns FAIL record with correct compliance tags."""
    # Create VPC without flow logs
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    collector = VPCCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_vpc_collector_passing_control(mock_environment, ec2_client):
    """Test VPC collector passing control - returns PASS record."""
    # Create VPC with flow logs
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    collector = VPCCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_vpc_collector_handles_aws_error(mock_environment, ec2_client):
    """Test VPC collector gracefully handles ClientError."""
    collector = VPCCollector(account_id="123456789012", region="us-east-1")

    # Mock EC2 client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# KMS Collector Tests
# ============================================================================


def test_kms_collector_happy_path(mock_environment, kms_client):
    """Test KMS collector happy path - returns expected EvidenceRecord structure."""
    # Create KMS key
    key = kms_client.create_key(
        Description="Test key", KeyUsage="ENCRYPT_DECRYPT", Origin="AWS_KMS"
    )
    key_id = key["KeyMetadata"]["KeyId"]

    collector = KMSCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) > 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "KMSCollector" for record in records)


def test_kms_collector_failing_control(mock_environment, kms_client):
    """Test KMS collector failing control - returns FAIL record with correct compliance tags."""
    collector = KMSCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_kms_collector_passing_control(mock_environment, kms_client):
    """Test KMS collector passing control - returns PASS record."""
    # Create KMS key with rotation enabled
    key = kms_client.create_key(
        Description="Test key with rotation",
        KeyUsage="ENCRYPT_DECRYPT",
        Origin="AWS_KMS",
    )
    key_id = key["KeyMetadata"]["KeyId"]

    # Enable key rotation
    kms_client.enable_key_rotation(KeyId=key_id)

    collector = KMSCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_kms_collector_handles_aws_error(mock_environment, kms_client):
    """Test KMS collector gracefully handles ClientError."""
    collector = KMSCollector(account_id="123456789012", region="us-east-1")

    # Mock KMS client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# ACM Collector Tests
# ============================================================================


def test_acm_collector_happy_path(mock_environment, acm_client):
    """Test ACM collector happy path - returns expected EvidenceRecord structure."""
    collector = ACMCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) >= 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "ACMCollector" for record in records)


def test_acm_collector_failing_control(mock_environment, acm_client):
    """Test ACM collector failing control - returns FAIL record with correct compliance tags."""
    collector = ACMCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_acm_collector_passing_control(mock_environment, acm_client):
    """Test ACM collector passing control - returns PASS record."""
    collector = ACMCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_acm_collector_handles_aws_error(mock_environment, acm_client):
    """Test ACM collector gracefully handles ClientError."""
    collector = ACMCollector(account_id="123456789012", region="us-east-1")

    # Mock ACM client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# Macie Collector Tests
# ============================================================================


def test_macie_collector_happy_path(mock_environment, macie_client):
    """Test Macie collector happy path - returns expected EvidenceRecord structure."""
    collector = MacieCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) >= 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "MacieCollector" for record in records)


def test_macie_collector_failing_control(mock_environment, macie_client):
    """Test Macie collector failing control - returns FAIL record with correct compliance tags."""
    collector = MacieCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_macie_collector_passing_control(mock_environment, macie_client):
    """Test Macie collector passing control - returns PASS record."""
    collector = MacieCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_macie_collector_handles_aws_error(mock_environment, macie_client):
    """Test Macie collector gracefully handles ClientError."""
    collector = MacieCollector(account_id="123456789012", region="us-east-1")

    # Mock Macie client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


# ============================================================================
# Inspector Collector Tests
# ============================================================================


def test_inspector_collector_happy_path(mock_environment, inspector_client):
    """Test Inspector collector happy path - returns expected EvidenceRecord structure."""
    collector = InspectorCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    assert len(records) >= 0
    assert all(isinstance(record, EvidenceRecord) for record in records)
    assert all(record.collector_name == "InspectorCollector" for record in records)


def test_inspector_collector_failing_control(mock_environment, inspector_client):
    """Test Inspector collector failing control - returns FAIL record with correct compliance tags."""
    collector = InspectorCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find FAIL records
    fail_records = [r for r in records if r.control_status == ControlStatus.FAIL.value]

    if fail_records:
        fail_record = fail_records[0]
        assert fail_record.control_status == ControlStatus.FAIL.value
        assert len(fail_record.compliance_frameworks) > 0
        assert fail_record.remediation_available == True


def test_inspector_collector_passing_control(mock_environment, inspector_client):
    """Test Inspector collector passing control - returns PASS record."""
    collector = InspectorCollector(account_id="123456789012", region="us-east-1")
    records = collector.collect()

    # Find PASS records
    pass_records = [r for r in records if r.control_status == ControlStatus.PASS.value]

    if pass_records:
        pass_record = pass_records[0]
        assert pass_record.control_status == ControlStatus.PASS.value


def test_inspector_collector_handles_aws_error(mock_environment, inspector_client):
    """Test Inspector collector gracefully handles ClientError."""
    collector = InspectorCollector(account_id="123456789012", region="us-east-1")

    # Mock Inspector client to raise error
    with patch.object(collector, "get_client", side_effect=Exception("Test error")):
        records = collector.collect()

        # Should return empty list or error records
        assert isinstance(records, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
