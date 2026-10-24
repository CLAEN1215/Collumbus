from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from collumbus.collectors import AwsCollector, AwsCredentialsError
from collumbus.collectors.base import CLOUDTRAIL_REGION, CLOUDTRAIL_TRAIL, IAM_POLICY, S3_BUCKET
from collumbus.models import Source


def make_client_error(code: str, message: str = "Error") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "Operation")


def test_aws_collector_missing_credentials():
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = NoCredentialsError()
    mock_session.client.return_value = mock_sts

    collector = AwsCollector(session=mock_session)
    with pytest.raises(AwsCredentialsError, match="AWS credentials not found"):
        collector.collect()


def test_aws_collector_sts_client_error():
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = make_client_error("InvalidClientTokenId")
    mock_session.client.return_value = mock_sts

    collector = AwsCollector(session=mock_session)
    with pytest.raises(AwsCredentialsError, match="InvalidClientTokenId"):
        collector.collect()


def test_aws_collector_successful_collection():
    mock_session = MagicMock()

    # STS
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "111122223333"}

    # S3
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "prod-secure"}, {"Name": "prod-unconfigured"}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}  # us-east-1

    # Bucket 1: secure
    # Bucket 2: unconfigured (returns NoSuch... and ServerSide...NotFoundError)
    def s3_pab(Bucket):
        if Bucket == "prod-secure":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        raise make_client_error("NoSuchPublicAccessBlockConfiguration")

    def s3_enc(Bucket):
        if Bucket == "prod-secure":
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"},
                            "BucketKeyEnabled": True,
                        }
                    ]
                }
            }
        raise make_client_error("ServerSideEncryptionConfigurationNotFoundError")

    mock_s3.get_public_access_block.side_effect = s3_pab
    mock_s3.get_bucket_encryption.side_effect = s3_enc

    # IAM
    mock_iam = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::111122223333:policy/CustomAdmin", "DefaultVersionId": "v1"}
            ]
        }
    ]
    mock_iam.get_paginator.return_value = paginator
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        }
    }

    # CloudTrail
    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "main-trail",
                "HomeRegion": "us-east-1",
                "IsMultiRegionTrail": True,
                "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/main-trail",
            }
        ]
    }
    mock_ct.get_trail_status.return_value = {"IsLogging": True}

    def client_factory(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "s3":
            return mock_s3
        if service == "iam":
            return mock_iam
        if service == "cloudtrail":
            return mock_ct
        return MagicMock()

    mock_session.client.side_effect = client_factory

    collector = AwsCollector(session=mock_session, regions=["us-east-1"])
    result = collector.collect()

    assert result.source == Source.AWS
    assert result.account_id == "111122223333"
    assert len(result.gaps) == 0

    # S3 buckets verification
    s3_items = [r for r in result.resources if r.resource_type == S3_BUCKET]
    assert len(s3_items) == 2
    b1 = next(r for r in s3_items if r.resource_id == "prod-secure")
    assert b1.attributes["public_access_block"]["BlockPublicAcls"] is True
    assert b1.attributes["encryption_rules"][0]["sse_algorithm"] == "aws:kms"

    b2 = next(r for r in s3_items if r.resource_id == "prod-unconfigured")
    assert b2.attributes["public_access_block"] is None
    assert b2.attributes["encryption_rules"] is None

    # IAM verification
    iam_items = [r for r in result.resources if r.resource_type == IAM_POLICY]
    assert len(iam_items) == 1
    assert "Statement" in iam_items[0].attributes["policy_document"]

    # CloudTrail verification
    ct_trails = [r for r in result.resources if r.resource_type == CLOUDTRAIL_TRAIL]
    assert len(ct_trails) == 1
    assert ct_trails[0].attributes["is_logging"] is True

    ct_regions = [r for r in result.resources if r.resource_type == CLOUDTRAIL_REGION]
    assert len(ct_regions) == 1
    assert ct_regions[0].region == "us-east-1"


def test_aws_collector_handles_permission_gaps():
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "111122223333"}

    mock_s3 = MagicMock()
    mock_s3.list_buckets.side_effect = make_client_error("AccessDenied", "Access Denied")

    mock_iam = MagicMock()
    mock_iam.get_paginator.side_effect = make_client_error("AccessDenied", "Access Denied")

    mock_ct = MagicMock()
    mock_ct.describe_trails.side_effect = make_client_error("AccessDenied", "Access Denied")

    def client_factory(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "s3":
            return mock_s3
        if service == "iam":
            return mock_iam
        if service == "cloudtrail":
            return mock_ct
        return MagicMock()

    mock_session.client.side_effect = client_factory

    collector = AwsCollector(session=mock_session, regions=["us-east-1"])
    result = collector.collect()

    assert result.source == Source.AWS
    assert len(result.gaps) == 3
    reasons = {g.missing_permission for g in result.gaps}
    assert "s3:ListAllMyBuckets" in reasons
    assert "iam:ListPolicies" in reasons
    assert "cloudtrail:DescribeTrails" in reasons


def test_aws_collector_fetch_error_per_resource():
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "111122223333"}

    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "throttled-bucket"}]}
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}
    mock_s3.get_public_access_block.side_effect = make_client_error("Throttling", "Rate exceeded")
    mock_s3.get_bucket_encryption.side_effect = make_client_error("AccessDenied", "Denied")

    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = []

    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {"trailList": []}

    def client_factory(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "s3":
            return mock_s3
        if service == "iam":
            return mock_iam
        if service == "cloudtrail":
            return mock_ct
        return MagicMock()

    mock_session.client.side_effect = client_factory

    collector = AwsCollector(session=mock_session, regions=["us-east-1"])
    result = collector.collect()

    s3_items = [r for r in result.resources if r.resource_type == S3_BUCKET]
    assert len(s3_items) == 1
    bucket = s3_items[0]
    assert len(bucket.fetch_errors) == 2
    attr_errors = {e.attribute: e.code for e in bucket.fetch_errors}
    assert attr_errors["public_access_block"] == "Throttling"
    assert attr_errors["encryption_rules"] == "AccessDenied"
