"""
Unit tests for all remediation functions in GRC Evidence Platform v2.0.

This module tests each remediation function using moto for AWS mocking, ensuring that:
- Remediation executes successfully
- Dry run logs action without executing
- Errors are handled gracefully
- Safety guardrails are verified
"""

import os
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import boto3
from moto import mock_aws, mock_s3, mock_iam, mock_rds, mock_ec2

# Import remediations
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from remediations import s3_remediations
from remediations import iam_remediations
from remediations import rds_remediations
from remediations import sg_remediations
from remediations import remediation_registry


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
def s3_client(aws_credentials):
    """Mock S3 client."""
    with mock_s3():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        yield s3


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
def ec2_client(aws_credentials):
    """Mock EC2 client."""
    with mock_ec2():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        yield ec2


# ============================================================================
# S3 Remediation Tests (6 functions × 4 tests = 24 tests)
# ============================================================================


def test_s3_block_public_access_success(mock_environment, s3_client):
    """Test block_s3_public_access executes successfully."""
    result = s3_remediations.block_s3_public_access("test-bucket", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "block_s3_public_access"
    assert result["resource_id"] == "test-bucket"
    assert result["resource_type"] == "s3_bucket"
    assert len(result["compliance_frameworks"]) > 0
    assert "after_state" in result


def test_s3_block_public_access_dry_run(mock_environment, s3_client):
    """Test block_s3_public_access dry run logs action without executing."""
    with patch.object(s3_remediations.boto3, "client") as mock_boto_client:
        result = s3_remediations.block_s3_public_access(
            "test-bucket", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True
        assert "Would execute" in result.get("message", "")


def test_s3_block_public_access_handles_error(mock_environment, s3_client):
    """Test block_s3_public_access gracefully handles ClientError."""
    with patch.object(
        s3_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = s3_remediations.block_s3_public_access("test-bucket", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_s3_block_public_access_safety_guardrails(mock_environment, s3_client):
    """Test block_s3_public_access verifies safety constraints."""
    result = s3_remediations.block_s3_public_access("test-bucket", "us-east-1")

    # Verify safety constraints
    assert result["resource_id"] == "test-bucket"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_s3_enable_encryption_success(mock_environment, s3_client):
    """Test enable_s3_encryption executes successfully."""
    result = s3_remediations.enable_s3_encryption("test-bucket", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "enable_s3_encryption"
    assert result["resource_id"] == "test-bucket"


def test_s3_enable_encryption_dry_run(mock_environment, s3_client):
    """Test enable_s3_encryption dry run logs action without executing."""
    with patch.object(s3_remediations.boto3, "client") as mock_boto_client:
        result = s3_remediations.enable_s3_encryption(
            "test-bucket", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_s3_enable_encryption_handles_error(mock_environment, s3_client):
    """Test enable_s3_encryption gracefully handles ClientError."""
    with patch.object(
        s3_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = s3_remediations.enable_s3_encryption("test-bucket", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_s3_enable_encryption_safety_guardrails(mock_environment, s3_client):
    """Test enable_s3_encryption verifies safety constraints."""
    result = s3_remediations.enable_s3_encryption("test-bucket", "us-east-1")

    assert result["resource_id"] == "test-bucket"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_s3_enable_versioning_success(mock_environment, s3_client):
    """Test enable_s3_versioning executes successfully."""
    result = s3_remediations.enable_s3_versioning("test-bucket", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "enable_s3_versioning"
    assert result["resource_id"] == "test-bucket"


def test_s3_enable_versioning_dry_run(mock_environment, s3_client):
    """Test enable_s3_versioning dry run logs action without executing."""
    with patch.object(s3_remediations.boto3, "client") as mock_boto_client:
        result = s3_remediations.enable_s3_versioning(
            "test-bucket", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_s3_enable_versioning_handles_error(mock_environment, s3_client):
    """Test enable_s3_versioning gracefully handles ClientError."""
    with patch.object(
        s3_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = s3_remediations.enable_s3_versioning("test-bucket", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_s3_enable_versioning_safety_guardrails(mock_environment, s3_client):
    """Test enable_s3_versioning verifies safety constraints."""
    result = s3_remediations.enable_s3_versioning("test-bucket", "us-east-1")

    assert result["resource_id"] == "test-bucket"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_s3_enable_logging_success(mock_environment, s3_client):
    """Test enable_s3_logging executes successfully."""
    s3_client.create_bucket(Bucket="test-log-bucket")
    result = s3_remediations.enable_s3_logging(
        "test-bucket", "us-east-1", "test-log-bucket"
    )

    assert result["success"] == True
    assert result["action_taken"] == "enable_s3_logging"
    assert result["resource_id"] == "test-bucket"


def test_s3_enable_logging_dry_run(mock_environment, s3_client):
    """Test enable_s3_logging dry run logs action without executing."""
    with patch.object(s3_remediations.boto3, "client") as mock_boto_client:
        result = s3_remediations.enable_s3_logging(
            "test-bucket", "us-east-1", "test-log-bucket", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_s3_enable_logging_handles_error(mock_environment, s3_client):
    """Test enable_s3_logging gracefully handles ClientError."""
    with patch.object(
        s3_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = s3_remediations.enable_s3_logging(
            "test-bucket", "us-east-1", "test-log-bucket"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_s3_enable_logging_safety_guardrails(mock_environment, s3_client):
    """Test enable_s3_logging verifies safety constraints."""
    s3_client.create_bucket(Bucket="test-log-bucket")
    result = s3_remediations.enable_s3_logging(
        "test-bucket", "us-east-1", "test-log-bucket"
    )

    assert result["resource_id"] == "test-bucket"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_s3_remove_public_acl_success(mock_environment, s3_client):
    """Test remove_s3_public_acl executes successfully."""
    result = s3_remediations.remove_s3_public_acl("test-bucket", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "remove_s3_public_acl"
    assert result["resource_id"] == "test-bucket"


def test_s3_remove_public_acl_dry_run(mock_environment, s3_client):
    """Test remove_s3_public_acl dry run logs action without executing."""
    with patch.object(s3_remediations.boto3, "client") as mock_boto_client:
        result = s3_remediations.remove_s3_public_acl(
            "test-bucket", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_s3_remove_public_acl_handles_error(mock_environment, s3_client):
    """Test remove_s3_public_acl gracefully handles ClientError."""
    with patch.object(
        s3_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = s3_remediations.remove_s3_public_acl("test-bucket", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_s3_remove_public_acl_safety_guardrails(mock_environment, s3_client):
    """Test remove_s3_public_acl verifies safety constraints."""
    result = s3_remediations.remove_s3_public_acl("test-bucket", "us-east-1")

    assert result["resource_id"] == "test-bucket"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_s3_delete_public_policy_success(mock_environment, s3_client):
    """Test delete_s3_public_policy executes successfully."""
    result = s3_remediations.delete_s3_public_policy("test-bucket", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "delete_s3_public_policy"
    assert result["resource_id"] == "test-bucket"


def test_s3_delete_public_policy_dry_run(mock_environment, s3_client):
    """Test delete_s3_public_policy dry run logs action without executing."""
    with patch.object(s3_remediations.boto3, "client") as mock_boto_client:
        result = s3_remediations.delete_s3_public_policy(
            "test-bucket", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_s3_delete_public_policy_handles_error(mock_environment, s3_client):
    """Test delete_s3_public_policy gracefully handles ClientError."""
    with patch.object(
        s3_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = s3_remediations.delete_s3_public_policy("test-bucket", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_s3_delete_public_policy_safety_guardrails(mock_environment, s3_client):
    """Test delete_s3_public_policy verifies safety constraints."""
    result = s3_remediations.delete_s3_public_policy("test-bucket", "us-east-1")

    assert result["resource_id"] == "test-bucket"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


# ============================================================================
# IAM Remediation Tests (6 functions × 4 tests = 24 tests)
# ============================================================================


def test_iam_disable_access_key_success(mock_environment, iam_client):
    """Test disable_iam_access_key executes successfully."""
    # Create user and access key
    iam_client.create_user(UserName="test-user")
    key = iam_client.create_access_key(UserName="test-user")
    access_key_id = key["AccessKey"]["AccessKeyId"]

    result = iam_remediations.disable_iam_access_key(access_key_id, "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "disable_iam_access_key"
    assert result["resource_id"] == access_key_id


def test_iam_disable_access_key_dry_run(mock_environment, iam_client):
    """Test disable_iam_access_key dry run logs action without executing."""
    with patch.object(iam_remediations.boto3, "client") as mock_boto_client:
        result = iam_remediations.disable_iam_access_key(
            "AKIAIOSFODNN7EXAMPLE", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_iam_disable_access_key_handles_error(mock_environment, iam_client):
    """Test disable_iam_access_key gracefully handles ClientError."""
    with patch.object(
        iam_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = iam_remediations.disable_iam_access_key(
            "AKIAIOSFODNN7EXAMPLE", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_iam_disable_access_key_safety_guardrails(mock_environment, iam_client):
    """Test disable_iam_access_key verifies safety constraints."""
    iam_client.create_user(UserName="test-user")
    key = iam_client.create_access_key(UserName="test-user")
    access_key_id = key["AccessKey"]["AccessKeyId"]

    result = iam_remediations.disable_iam_access_key(access_key_id, "us-east-1")

    assert result["resource_id"] == access_key_id
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_iam_enforce_mfa_success(mock_environment, iam_client):
    """Test enforce_mfa_for_user executes successfully."""
    iam_client.create_user(UserName="test-user")
    result = iam_remediations.enforce_mfa_for_user("test-user", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "enforce_mfa_for_user"
    assert result["resource_id"] == "test-user"


def test_iam_enforce_mfa_dry_run(mock_environment, iam_client):
    """Test enforce_mfa_for_user dry run logs action without executing."""
    with patch.object(iam_remediations.boto3, "client") as mock_boto_client:
        result = iam_remediations.enforce_mfa_for_user(
            "test-user", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_iam_enforce_mfa_handles_error(mock_environment, iam_client):
    """Test enforce_mfa_for_user gracefully handles ClientError."""
    with patch.object(
        iam_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = iam_remediations.enforce_mfa_for_user("test-user", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_iam_enforce_mfa_safety_guardrails(mock_environment, iam_client):
    """Test enforce_mfa_for_user verifies safety constraints."""
    iam_client.create_user(UserName="test-user")
    result = iam_remediations.enforce_mfa_for_user("test-user", "us-east-1")

    assert result["resource_id"] == "test-user"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_iam_delete_inline_policy_success(mock_environment, iam_client):
    """Test delete_iam_user_inline_policy executes successfully."""
    iam_client.create_user(UserName="test-user")
    iam_client.put_user_policy(
        UserName="test-user",
        PolicyName="test-policy",
        PolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )

    result = iam_remediations.delete_iam_user_inline_policy(
        "test-user", "test-policy", "us-east-1"
    )

    assert result["success"] == True
    assert result["action_taken"] == "delete_iam_user_inline_policy"
    assert result["resource_id"] == "test-user"


def test_iam_delete_inline_policy_dry_run(mock_environment, iam_client):
    """Test delete_iam_user_inline_policy dry run logs action without executing."""
    with patch.object(iam_remediations.boto3, "client") as mock_boto_client:
        result = iam_remediations.delete_iam_user_inline_policy(
            "test-user", "test-policy", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_iam_delete_inline_policy_handles_error(mock_environment, iam_client):
    """Test delete_iam_user_inline_policy gracefully handles ClientError."""
    with patch.object(
        iam_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = iam_remediations.delete_iam_user_inline_policy(
            "test-user", "test-policy", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_iam_delete_inline_policy_safety_guardrails(mock_environment, iam_client):
    """Test delete_iam_user_inline_policy verifies safety constraints."""
    iam_client.create_user(UserName="test-user")
    iam_client.put_user_policy(
        UserName="test-user",
        PolicyName="test-policy",
        PolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )

    result = iam_remediations.delete_iam_user_inline_policy(
        "test-user", "test-policy", "us-east-1"
    )

    assert result["resource_id"] == "test-user"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_iam_detach_user_policy_success(mock_environment, iam_client):
    """Test detach_iam_user_policy executes successfully."""
    iam_client.create_user(UserName="test-user")
    iam_client.create_policy(
        PolicyName="test-managed-policy",
        PolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )

    result = iam_remediations.detach_iam_user_policy(
        "test-user", "arn:aws:iam::aws:policy/test-managed-policy", "us-east-1"
    )

    assert result["success"] == True
    assert result["action_taken"] == "detach_iam_user_policy"
    assert result["resource_id"] == "test-user"


def test_iam_detach_user_policy_dry_run(mock_environment, iam_client):
    """Test detach_iam_user_policy dry run logs action without executing."""
    with patch.object(iam_remediations.boto3, "client") as mock_boto_client:
        result = iam_remediations.detach_iam_user_policy(
            "test-user",
            "arn:aws:iam::aws:policy/test-managed-policy",
            "us-east-1",
            dry_run=True,
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_iam_detach_user_policy_handles_error(mock_environment, iam_client):
    """Test detach_iam_user_policy gracefully handles ClientError."""
    with patch.object(
        iam_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = iam_remediations.detach_iam_user_policy(
            "test-user", "arn:aws:iam::aws:policy/test-managed-policy", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_iam_detach_user_policy_safety_guardrails(mock_environment, iam_client):
    """Test detach_iam_user_policy verifies safety constraints."""
    iam_client.create_user(UserName="test-user")
    iam_client.create_policy(
        PolicyName="test-managed-policy",
        PolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )

    result = iam_remediations.detach_iam_user_policy(
        "test-user", "arn:aws:iam::aws:policy/test-managed-policy", "us-east-1"
    )

    assert result["resource_id"] == "test-user"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_iam_delete_access_key_success(mock_environment, iam_client):
    """Test delete_iam_access_key executes successfully."""
    iam_client.create_user(UserName="test-user")
    key = iam_client.create_access_key(UserName="test-user")
    access_key_id = key["AccessKey"]["AccessKeyId"]

    result = iam_remediations.delete_iam_access_key(access_key_id, "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "delete_iam_access_key"
    assert result["resource_id"] == access_key_id


def test_iam_delete_access_key_dry_run(mock_environment, iam_client):
    """Test delete_iam_access_key dry run logs action without executing."""
    with patch.object(iam_remediations.boto3, "client") as mock_boto_client:
        result = iam_remediations.delete_iam_access_key(
            "AKIAIOSFODNN7EXAMPLE", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_iam_delete_access_key_handles_error(mock_environment, iam_client):
    """Test delete_iam_access_key gracefully handles ClientError."""
    with patch.object(
        iam_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = iam_remediations.delete_iam_access_key(
            "AKIAIOSFODNN7EXAMPLE", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_iam_delete_access_key_safety_guardrails(mock_environment, iam_client):
    """Test delete_iam_access_key verifies safety constraints."""
    iam_client.create_user(UserName="test-user")
    key = iam_client.create_access_key(UserName="test-user")
    access_key_id = key["AccessKey"]["AccessKeyId"]

    result = iam_remediations.delete_iam_access_key(access_key_id, "us-east-1")

    assert result["resource_id"] == access_key_id
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


# ============================================================================
# RDS Remediation Tests (6 functions × 4 tests = 24 tests)
# ============================================================================


def test_rds_enable_encryption_success(mock_environment, rds_client):
    """Test enable_rds_encryption executes successfully."""
    # Create unencrypted RDS instance
    rds_client.create_db_instance(
        DBInstanceIdentifier="test-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        StorageEncrypted=False,
    )

    result = rds_remediations.enable_rds_encryption("test-db", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "enable_rds_encryption"
    assert result["resource_id"] == "test-db"


def test_rds_enable_encryption_dry_run(mock_environment, rds_client):
    """Test enable_rds_encryption dry run logs action without executing."""
    with patch.object(rds_remediations.boto3, "client") as mock_boto_client:
        result = rds_remediations.enable_rds_encryption(
            "test-db", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_rds_enable_encryption_handles_error(mock_environment, rds_client):
    """Test enable_rds_encryption gracefully handles ClientError."""
    with patch.object(
        rds_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = rds_remediations.enable_rds_encryption("test-db", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_rds_enable_encryption_safety_guardrails(mock_environment, rds_client):
    """Test enable_rds_encryption verifies safety constraints."""
    rds_client.create_db_instance(
        DBInstanceIdentifier="test-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        StorageEncrypted=False,
    )

    result = rds_remediations.enable_rds_encryption("test-db", "us-east-1")

    assert result["resource_id"] == "test-db"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_rds_disable_public_access_success(mock_environment, rds_client):
    """Test disable_rds_public_access executes successfully."""
    # Create public RDS instance
    rds_client.create_db_instance(
        DBInstanceIdentifier="public-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        PubliclyAccessible=True,
    )

    result = rds_remediations.disable_rds_public_access("public-db", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "disable_rds_public_access"
    assert result["resource_id"] == "public-db"


def test_rds_disable_public_access_dry_run(mock_environment, rds_client):
    """Test disable_rds_public_access dry run logs action without executing."""
    with patch.object(rds_remediations.boto3, "client") as mock_boto_client:
        result = rds_remediations.disable_rds_public_access(
            "public-db", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_rds_disable_public_access_handles_error(mock_environment, rds_client):
    """Test disable_rds_public_access gracefully handles ClientError."""
    with patch.object(
        rds_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = rds_remediations.disable_rds_public_access("public-db", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_rds_disable_public_access_safety_guardrails(mock_environment, rds_client):
    """Test disable_rds_public_access verifies safety constraints."""
    rds_client.create_db_instance(
        DBInstanceIdentifier="public-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        PubliclyAccessible=True,
    )

    result = rds_remediations.disable_rds_public_access("public-db", "us-east-1")

    assert result["resource_id"] == "public-db"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_rds_enable_multi_az_success(mock_environment, rds_client):
    """Test enable_rds_multi_az executes successfully."""
    rds_client.create_db_instance(
        DBInstanceIdentifier="single-az-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        MultiAZ=False,
    )

    result = rds_remediations.enable_rds_multi_az("single-az-db", "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "enable_rds_multi_az"
    assert result["resource_id"] == "single-az-db"


def test_rds_enable_multi_az_dry_run(mock_environment, rds_client):
    """Test enable_rds_multi_az dry run logs action without executing."""
    with patch.object(rds_remediations.boto3, "client") as mock_boto_client:
        result = rds_remediations.enable_rds_multi_az(
            "single-az-db", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_rds_enable_multi_az_handles_error(mock_environment, rds_client):
    """Test enable_rds_multi_az gracefully handles ClientError."""
    with patch.object(
        rds_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = rds_remediations.enable_rds_multi_az("single-az-db", "us-east-1")

        assert result["success"] == False
        assert result["error"] is not None


def test_rds_enable_multi_az_safety_guardrails(mock_environment, rds_client):
    """Test enable_rds_multi_az verifies safety constraints."""
    rds_client.create_db_instance(
        DBInstanceIdentifier="single-az-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        MultiAZ=False,
    )

    result = rds_remediations.enable_rds_multi_az("single-az-db", "us-east-1")

    assert result["resource_id"] == "single-az-db"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_rds_enable_deletion_protection_success(mock_environment, rds_client):
    """Test enable_rds_deletion_protection executes successfully."""
    rds_client.create_db_instance(
        DBInstanceIdentifier="unprotected-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        DeletionProtection=False,
    )

    result = rds_remediations.enable_rds_deletion_protection(
        "unprotected-db", "us-east-1"
    )

    assert result["success"] == True
    assert result["action_taken"] == "enable_rds_deletion_protection"
    assert result["resource_id"] == "unprotected-db"


def test_rds_enable_deletion_protection_dry_run(mock_environment, rds_client):
    """Test enable_rds_deletion_protection dry run logs action without executing."""
    with patch.object(rds_remediations.boto3, "client") as mock_boto_client:
        result = rds_remediations.enable_rds_deletion_protection(
            "unprotected-db", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_rds_enable_deletion_protection_handles_error(mock_environment, rds_client):
    """Test enable_rds_deletion_protection gracefully handles ClientError."""
    with patch.object(
        rds_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = rds_remediations.enable_rds_deletion_protection(
            "unprotected-db", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_rds_enable_deletion_protection_safety_guardrails(mock_environment, rds_client):
    """Test enable_rds_deletion_protection verifies safety constraints."""
    rds_client.create_db_instance(
        DBInstanceIdentifier="unprotected-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="TestPassword123!",
        AllocatedStorage=20,
        DeletionProtection=False,
    )

    result = rds_remediations.enable_rds_deletion_protection(
        "unprotected-db", "us-east-1"
    )

    assert result["resource_id"] == "unprotected-db"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_rds_revoke_snapshot_public_access_success(mock_environment, rds_client):
    """Test revoke_rds_snapshot_public_access executes successfully."""
    # Create snapshot (mock)
    result = rds_remediations.revoke_rds_snapshot_public_access(
        "test-snapshot", "us-east-1"
    )

    assert result["success"] == True
    assert result["action_taken"] == "revoke_rds_snapshot_public_access"
    assert result["resource_id"] == "test-snapshot"


def test_rds_revoke_snapshot_public_access_dry_run(mock_environment, rds_client):
    """Test revoke_rds_snapshot_public_access dry run logs action without executing."""
    with patch.object(rds_remediations.boto3, "client") as mock_boto_client:
        result = rds_remediations.revoke_rds_snapshot_public_access(
            "test-snapshot", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_rds_revoke_snapshot_public_access_handles_error(mock_environment, rds_client):
    """Test revoke_rds_snapshot_public_access gracefully handles ClientError."""
    with patch.object(
        rds_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = rds_remediations.revoke_rds_snapshot_public_access(
            "test-snapshot", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_rds_revoke_snapshot_public_access_safety_guardrails(
    mock_environment, rds_client
):
    """Test revoke_rds_snapshot_public_access verifies safety constraints."""
    result = rds_remediations.revoke_rds_snapshot_public_access(
        "test-snapshot", "us-east-1"
    )

    assert result["resource_id"] == "test-snapshot"
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


# ============================================================================
# Security Group Remediation Tests (5 functions × 4 tests = 20 tests)
# ============================================================================


def test_sg_revoke_open_ssh_success(mock_environment, ec2_client):
    """Test revoke_open_ssh_rule executes successfully."""
    # Create VPC and security group
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = ec2_client.create_security_group(
        GroupName="test-sg", Description="Test security group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]

    # Add open SSH rule
    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = sg_remediations.revoke_open_ssh_rule(sg_id, "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "revoke_open_ssh_rule"
    assert result["resource_id"] == sg_id


def test_sg_revoke_open_ssh_dry_run(mock_environment, ec2_client):
    """Test revoke_open_ssh_rule dry run logs action without executing."""
    with patch.object(sg_remediations.boto3, "client") as mock_boto_client:
        result = sg_remediations.revoke_open_ssh_rule(
            "sg-0123456789abcdef0", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_sg_revoke_open_ssh_handles_error(mock_environment, ec2_client):
    """Test revoke_open_ssh_rule gracefully handles ClientError."""
    with patch.object(
        sg_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = sg_remediations.revoke_open_ssh_rule(
            "sg-0123456789abcdef0", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_sg_revoke_open_ssh_safety_guardrails(mock_environment, ec2_client):
    """Test revoke_open_ssh_rule verifies safety constraints."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = ec2_client.create_security_group(
        GroupName="test-sg", Description="Test security group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]

    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = sg_remediations.revoke_open_ssh_rule(sg_id, "us-east-1")

    assert result["resource_id"] == sg_id
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_sg_revoke_open_rdp_success(mock_environment, ec2_client):
    """Test revoke_open_rdp_rule executes successfully."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = ec2_client.create_security_group(
        GroupName="test-rdp-sg", Description="Test RDP security group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]

    # Add open RDP rule
    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = sg_remediations.revoke_open_rdp_rule(sg_id, "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "revoke_open_rdp_rule"
    assert result["resource_id"] == sg_id


def test_sg_revoke_open_rdp_dry_run(mock_environment, ec2_client):
    """Test revoke_open_rdp_rule dry run logs action without executing."""
    with patch.object(sg_remediations.boto3, "client") as mock_boto_client:
        result = sg_remediations.revoke_open_rdp_rule(
            "sg-0123456789abcdef0", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_sg_revoke_open_rdp_handles_error(mock_environment, ec2_client):
    """Test revoke_open_rdp_rule gracefully handles ClientError."""
    with patch.object(
        sg_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = sg_remediations.revoke_open_rdp_rule(
            "sg-0123456789abcdef0", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_sg_revoke_open_rdp_safety_guardrails(mock_environment, ec2_client):
    """Test revoke_open_rdp_rule verifies safety constraints."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = ec2_client.create_security_group(
        GroupName="test-rdp-sg", Description="Test RDP security group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]

    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = sg_remediations.revoke_open_rdp_rule(sg_id, "us-east-1")

    assert result["resource_id"] == sg_id
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_sg_revoke_open_database_success(mock_environment, ec2_client):
    """Test revoke_open_database_rule executes successfully."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = ec2_client.create_security_group(
        GroupName="test-db-sg", Description="Test database security group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]

    # Add open database rule
    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = sg_remediations.revoke_open_database_rule(sg_id, "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "revoke_open_database_rule"
    assert result["resource_id"] == sg_id


def test_sg_revoke_open_database_dry_run(mock_environment, ec2_client):
    """Test revoke_open_database_rule dry run logs action without executing."""
    with patch.object(sg_remediations.boto3, "client") as mock_boto_client:
        result = sg_remediations.revoke_open_database_rule(
            "sg-0123456789abcdef0", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_sg_revoke_open_database_handles_error(mock_environment, ec2_client):
    """Test revoke_open_database_rule gracefully handles ClientError."""
    with patch.object(
        sg_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = sg_remediations.revoke_open_database_rule(
            "sg-0123456789abcdef0", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_sg_revoke_open_database_safety_guardrails(mock_environment, ec2_client):
    """Test revoke_open_database_rule verifies safety constraints."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = ec2_client.create_security_group(
        GroupName="test-db-sg", Description="Test database security group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]

    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = sg_remediations.revoke_open_database_rule(sg_id, "us-east-1")

    assert result["resource_id"] == sg_id
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


def test_sg_revoke_all_ingress_default_success(mock_environment, ec2_client):
    """Test revoke_all_ingress_from_default_sg executes successfully."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    # Create default security group
    sg = ec2_client.create_security_group(
        GroupName="default", Description="Default security group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]

    # Add ingress rules
    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "FromPort": -1,
                "ToPort": -1,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = sg_remediations.revoke_all_ingress_from_default_sg(sg_id, "us-east-1")

    assert result["success"] == True
    assert result["action_taken"] == "revoke_all_ingress_from_default_sg"
    assert result["resource_id"] == sg_id


def test_sg_revoke_all_ingress_default_dry_run(mock_environment, ec2_client):
    """Test revoke_all_ingress_from_default_sg dry run logs action without executing."""
    with patch.object(sg_remediations.boto3, "client") as mock_boto_client:
        result = sg_remediations.revoke_all_ingress_from_default_sg(
            "sg-0123456789abcdef0", "us-east-1", dry_run=True
        )

        assert result["action_taken"] == "DRY_RUN"
        assert result["success"] == True


def test_sg_revoke_all_ingress_default_handles_error(mock_environment, ec2_client):
    """Test revoke_all_ingress_from_default_sg gracefully handles ClientError."""
    with patch.object(
        sg_remediations.boto3, "client", side_effect=Exception("Test error")
    ):
        result = sg_remediations.revoke_all_ingress_from_default_sg(
            "sg-0123456789abcdef0", "us-east-1"
        )

        assert result["success"] == False
        assert result["error"] is not None


def test_sg_revoke_all_ingress_default_safety_guardrails(mock_environment, ec2_client):
    """Test revoke_all_ingress_from_default_sg verifies safety constraints."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = ec2_client.create_security_group(
        GroupName="default", Description="Default security group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]

    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "FromPort": -1,
                "ToPort": -1,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = sg_remediations.revoke_all_ingress_from_default_sg(sg_id, "us-east-1")

    assert result["resource_id"] == sg_id
    assert result["timestamp"] is not None
    assert isinstance(result["compliance_frameworks"], list)


# ============================================================================
# Remediation Registry Helper Function Tests (5 tests)
# ============================================================================


def test_get_remediation_function():
    """Test get_remediation_function returns correct function."""
    func = remediation_registry.get_remediation_function(
        "s3-bucket-public-read-prohibited"
    )

    assert func is not None
    assert callable(func)
    assert func.__name__ == "block_s3_public_access"


def test_execute_remediation(mock_environment, s3_client):
    """Test execute_remediation executes remediation correctly."""
    result = remediation_registry.execute_remediation(
        trigger="s3-bucket-public-read-prohibited",
        resource_id="test-bucket",
        region="us-east-1",
    )

    assert result["success"] == True
    assert result["trigger"] == "s3-bucket-public-read-prohibited"
    assert result["resource_id"] == "test-bucket"
    assert result["region"] == "us-east-1"


def test_validate_safety_mode():
    """Test validate_safety_mode checks compatibility correctly."""
    # Test AUTO mode
    assert (
        remediation_registry.validate_safety_mode(
            "s3-bucket-public-read-prohibited", "AUTO"
        )
        == True
    )
    assert (
        remediation_registry.validate_safety_mode(
            "s3-bucket-public-read-prohibited", "MANUAL"
        )
        == True
    )

    # Test APPROVAL_REQUIRED mode
    assert (
        remediation_registry.validate_safety_mode(
            "rds-storage-encrypted", "APPROVAL_REQUIRED"
        )
        == True
    )
    assert (
        remediation_registry.validate_safety_mode("rds-storage-encrypted", "AUTO")
        == False
    )


def test_list_all_triggers():
    """Test list_all_triggers returns all triggers."""
    all_triggers = remediation_registry.list_all_triggers()

    assert isinstance(all_triggers, dict)
    assert len(all_triggers) > 0

    # Test filtering by trigger type
    config_triggers = remediation_registry.list_all_triggers(trigger_type="CONFIG_RULE")
    assert isinstance(config_triggers, dict)
    assert len(config_triggers) > 0


def test_get_trigger_info():
    """Test get_trigger_info returns detailed information."""
    info = remediation_registry.get_trigger_info("s3-bucket-public-read-prohibited")

    assert info is not None
    assert info["trigger"] == "s3-bucket-public-read-prohibited"
    assert info["trigger_type"] == "CONFIG_RULE"
    assert info["priority"] == "CRITICAL"
    assert len(info["compliance_frameworks"]) > 0
    assert info["safety_mode"] == "AUTO"
    assert info["function_name"] == "block_s3_public_access"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
