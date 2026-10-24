import json

import pytest
from pydantic import ValidationError

from collumbus.collectors import (
    CollectionResult,
    DemoCollector,
    DemoDataError,
    FetchError,
    Resource,
)
from collumbus.collectors.base import S3_BUCKET
from collumbus.collectors.demo import MAX_DEMO_FILE_BYTES
from collumbus.models import Source


def test_demo_collector_default():
    collector = DemoCollector()
    result = collector.collect()
    assert result.source == Source.DEMO
    assert result.account_id == "111122223333"
    assert result.regions == ["us-east-1", "eu-west-1"]
    assert result.resource_categories == ["s3", "iam", "cloudtrail"]
    assert len(result.resources) == 10
    assert len(result.gaps) == 1

    # Verify deterministic sorting: category, resource_type, region, resource_id
    keys = [(r.category, r.resource_type, r.region, r.resource_id) for r in result.resources]
    assert keys == sorted(keys)


def test_demo_collector_missing_file(tmp_path):
    collector = DemoCollector(tmp_path / "nonexistent.json")
    with pytest.raises(DemoDataError, match="cannot read demo file"):
        collector.collect()


def test_demo_collector_oversized_file(tmp_path):
    oversized = tmp_path / "large.json"
    oversized.write_bytes(b"x" * (MAX_DEMO_FILE_BYTES + 10))
    collector = DemoCollector(oversized)
    with pytest.raises(DemoDataError, match="limit is"):
        collector.collect()


def test_demo_collector_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    collector = DemoCollector(bad)
    with pytest.raises(DemoDataError, match="not valid JSON"):
        collector.collect()


def test_demo_collector_validation_error(tmp_path):
    bad_schema = tmp_path / "bad_schema.json"
    bad_schema.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "account_id": "123",  # invalid: needs 12 digits
                "regions": ["us-east-1"],
                "resource_categories": ["s3"],
                "resources": [],
            }
        ),
        encoding="utf-8",
    )
    collector = DemoCollector(bad_schema)
    with pytest.raises(DemoDataError, match="is invalid: account_id"):
        collector.collect()


def test_resource_rejects_attribute_in_both_attributes_and_fetch_errors():
    with pytest.raises(ValidationError, match="attributes cannot be both collected and failed"):
        Resource(
            resource_type=S3_BUCKET,
            resource_id="bucket-1",
            region="us-east-1",
            category="s3",
            attributes={"public_access_block": {}},
            fetch_errors=[
                FetchError(
                    attribute="public_access_block",
                    code="AccessDenied",
                    permission="s3:GetBucketPublicAccessBlock",
                )
            ],
        )


def test_resource_forbids_extra_fields():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Resource(
            resource_type=S3_BUCKET,
            resource_id="bucket-1",
            region="us-east-1",
            category="s3",
            extra_field="invalid",  # type: ignore
        )


def test_collection_result_rejects_duplicate_resource():
    r1 = Resource(
        resource_type=S3_BUCKET,
        resource_id="bucket-1",
        region="us-east-1",
        category="s3",
    )
    r2 = Resource(
        resource_type=S3_BUCKET,
        resource_id="bucket-1",
        region="us-east-1",
        category="s3",
    )
    with pytest.raises(ValidationError, match="duplicate resource"):
        CollectionResult(
            source=Source.DEMO,
            account_id="111122223333",
            regions=["us-east-1"],
            resource_categories=["s3"],
            resources=[r1, r2],
        )


def test_collection_result_rejects_unrequested_region():
    r = Resource(
        resource_type=S3_BUCKET,
        resource_id="bucket-1",
        region="us-west-2",
        category="s3",
    )
    with pytest.raises(ValidationError, match="unrequested region us-west-2"):
        CollectionResult(
            source=Source.DEMO,
            account_id="111122223333",
            regions=["us-east-1"],
            resource_categories=["s3"],
            resources=[r],
        )


def test_collection_result_allows_global_region():
    r = Resource(
        resource_type="AWS::IAM::Policy",
        resource_id="policy-1",
        region="global",
        category="iam",
    )
    cr = CollectionResult(
        source=Source.DEMO,
        account_id="111122223333",
        regions=["us-east-1"],
        resource_categories=["iam"],
        resources=[r],
    )
    assert len(cr.resources) == 1


def test_collection_result_rejects_unrequested_category():
    r = Resource(
        resource_type=S3_BUCKET,
        resource_id="bucket-1",
        region="us-east-1",
        category="s3",
    )
    with pytest.raises(ValidationError, match="unrequested category s3"):
        CollectionResult(
            source=Source.DEMO,
            account_id="111122223333",
            regions=["us-east-1"],
            resource_categories=["iam"],
            resources=[r],
        )


def test_fetch_error_validation():
    fe = FetchError(
        attribute="encryption",
        code="AccessDenied",
        message="Simulated error",
        permission="s3:GetEncryptionConfiguration",
    )
    assert fe.attribute == "encryption"
    assert fe.code == "AccessDenied"
    assert fe.permission == "s3:GetEncryptionConfiguration"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        FetchError(attribute="enc", code="Err", extra_prop=123)  # type: ignore
