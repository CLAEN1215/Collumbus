import json

import pytest
from pydantic import ValidationError

from collumbus.collectors.base import (
    CLOUDTRAIL_REGION,
    CLOUDTRAIL_TRAIL,
    IAM_POLICY,
    S3_BUCKET,
    FetchError,
    Resource,
)
from collumbus.config import AppConfig, RuleSettings, S3EncryptionSettings
from collumbus.models import Severity, Status
from collumbus.rules import (
    CloudTrailLoggingRule,
    IamWildcardRule,
    RuleResult,
    S3DefaultEncryptionRule,
    S3PublicAccessBlockRule,
    build_rules,
)


def test_rule_result_requires_non_blank_summary():
    with pytest.raises(ValidationError, match="summary must not be blank"):
        RuleResult(status=Status.PASS, summary="   ")


def test_rule_applies_to():
    s3_rule = S3PublicAccessBlockRule()
    s3_res = Resource(resource_type=S3_BUCKET, resource_id="b1", region="us-east-1", category="s3")
    iam_res = Resource(resource_type=IAM_POLICY, resource_id="p1", region="global", category="iam")
    assert s3_rule.applies_to(s3_res) is True
    assert s3_rule.applies_to(iam_res) is False


# --- S3PublicAccessBlockRule (S3-001) ---


def test_s3_public_access_pass():
    rule = S3PublicAccessBlockRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    )
    result = rule.evaluate(res)
    assert result.status == Status.PASS
    assert "All four" in result.summary


def test_s3_public_access_fail_incomplete():
    rule = S3PublicAccessBlockRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            }
        },
    )
    result = rule.evaluate(res)
    assert result.status == Status.FAIL
    assert "BlockPublicPolicy not enabled" in result.summary


def test_s3_public_access_fail_none_config():
    rule = S3PublicAccessBlockRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={"public_access_block": None},
    )
    result = rule.evaluate(res)
    assert result.status == Status.FAIL
    assert "No bucket-level Block Public Access" in result.summary


def test_s3_public_access_error_fetch_error():
    rule = S3PublicAccessBlockRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        fetch_errors=[
            FetchError(
                attribute="public_access_block",
                code="AccessDenied",
                permission="s3:GetBucketPublicAccessBlock",
            )
        ],
    )
    result = rule.evaluate(res)
    assert result.status == Status.ERROR
    assert "Could not read public_access_block (AccessDenied)" in result.summary
    assert "Grant the scanning identity s3:GetBucketPublicAccessBlock" in (result.remediation or "")


def test_s3_public_access_error_missing_attribute():
    rule = S3PublicAccessBlockRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={},
    )
    result = rule.evaluate(res)
    assert result.status == Status.ERROR
    assert "No data was collected" in result.summary


def test_s3_public_access_error_malformed():
    rule = S3PublicAccessBlockRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={"public_access_block": "not a dict"},
    )
    result = rule.evaluate(res)
    assert result.status == Status.ERROR
    assert "unexpected format" in result.summary

    res_non_bool = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={
            "public_access_block": {
                "BlockPublicAcls": "yes",
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    )
    result = rule.evaluate(res_non_bool)
    assert result.status == Status.ERROR
    assert "non-boolean values" in result.summary


# --- S3DefaultEncryptionRule (S3-002) ---


def test_s3_encryption_pass():
    rule = S3DefaultEncryptionRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={"encryption_rules": [{"sse_algorithm": "AES256"}]},
    )
    result = rule.evaluate(res)
    assert result.status == Status.PASS
    assert "AES256" in result.summary


def test_s3_encryption_fail_unapproved():
    rule = S3DefaultEncryptionRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={"encryption_rules": [{"sse_algorithm": "DES"}]},
    )
    result = rule.evaluate(res)
    assert result.status == Status.FAIL
    assert "unapproved method: DES" in result.summary


def test_s3_encryption_fail_none():
    rule = S3DefaultEncryptionRule()
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={"encryption_rules": None},
    )
    result = rule.evaluate(res)
    assert result.status == Status.FAIL
    assert "No default encryption configuration is set" in result.summary


def test_s3_encryption_error_fetch_and_malformed():
    rule = S3DefaultEncryptionRule()
    res_err = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        fetch_errors=[
            FetchError(
                attribute="encryption_rules",
                code="Throttling",
            )
        ],
    )
    result = rule.evaluate(res_err)
    assert result.status == Status.ERROR
    assert "Throttling" in result.summary

    res_empty = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={"encryption_rules": []},
    )
    assert rule.evaluate(res_empty).status == Status.ERROR

    res_bad_elem = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={"encryption_rules": [{"not_sse": 123}]},
    )
    assert rule.evaluate(res_bad_elem).status == Status.ERROR


def test_s3_encryption_uses_config():
    config = AppConfig(
        rules={"S3-002": RuleSettings(enabled=True, severity=Severity.LOW)},
        s3_encryption=S3EncryptionSettings(approved_algorithms=["aws:kms"]),
    )
    rule = S3DefaultEncryptionRule(config)
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        attributes={"encryption_rules": [{"sse_algorithm": "AES256"}]},
    )
    # Since only aws:kms is approved in config, AES256 should now fail
    result = rule.evaluate(res)
    assert result.status == Status.FAIL


# --- IamWildcardRule (IAM-001) ---


def test_iam_wildcard_unavailable():
    rule = IamWildcardRule()
    res = Resource(
        resource_type=IAM_POLICY,
        resource_id="p1",
        region="global",
        category="iam",
        fetch_errors=[FetchError(attribute="policy_document", code="AccessDenied")],
    )
    assert rule.evaluate(res).status == Status.ERROR


def test_iam_wildcard_pass():
    rule = IamWildcardRule()
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::bucket/file"],
            }
        ],
    }
    res = Resource(
        resource_type=IAM_POLICY,
        resource_id="p1",
        region="global",
        category="iam",
        attributes={"policy_document": doc},
    )
    result = rule.evaluate(res)
    assert result.status == Status.PASS


def test_iam_wildcard_fail_star_on_star():
    rule = IamWildcardRule()
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    res = Resource(
        resource_type=IAM_POLICY,
        resource_id="p1",
        region="global",
        category="iam",
        attributes={"policy_document": doc},
    )
    result = rule.evaluate(res)
    assert result.status == Status.FAIL
    assert "grant broad wildcard permissions" in result.summary


def test_iam_wildcard_fail_patterns():
    rule = IamWildcardRule()

    # Action * with specific resource
    doc1 = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket"}]}
    res1 = Resource(
        resource_type=IAM_POLICY,
        resource_id="p1",
        region="global",
        category="iam",
        attributes={"policy_document": doc1},
    )
    assert rule.evaluate(res1).status == Status.FAIL

    # Service wildcard on Resource *
    doc2 = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    res2 = Resource(
        resource_type=IAM_POLICY,
        resource_id="p2",
        region="global",
        category="iam",
        attributes={"policy_document": doc2},
    )
    assert rule.evaluate(res2).status == Status.FAIL

    # NotAction
    doc3 = {"Statement": [{"Effect": "Allow", "NotAction": "s3:DeleteBucket", "Resource": "*"}]}
    res3 = Resource(
        resource_type=IAM_POLICY,
        resource_id="p3",
        region="global",
        category="iam",
        attributes={"policy_document": doc3},
    )
    assert rule.evaluate(res3).status == Status.FAIL


def test_iam_wildcard_string_doc_and_deny_ignored():
    rule = IamWildcardRule()
    doc_str = json.dumps(
        {
            "Statement": [
                {"Effect": "Deny", "Action": "*", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
            ]
        }
    )
    res = Resource(
        resource_type=IAM_POLICY,
        resource_id="p1",
        region="global",
        category="iam",
        attributes={"policy_document": doc_str},
    )
    result = rule.evaluate(res)
    assert result.status == Status.PASS


def test_iam_wildcard_malformed():
    rule = IamWildcardRule()

    res_bad_json = Resource(
        resource_type=IAM_POLICY,
        resource_id="p1",
        region="global",
        category="iam",
        attributes={"policy_document": "{invalid json"},
    )
    assert rule.evaluate(res_bad_json).status == Status.ERROR

    res_missing_stmt = Resource(
        resource_type=IAM_POLICY,
        resource_id="p1",
        region="global",
        category="iam",
        attributes={"policy_document": {"Version": "2012-10-17"}},
    )
    assert rule.evaluate(res_missing_stmt).status == Status.ERROR

    res_stmt_not_dict = Resource(
        resource_type=IAM_POLICY,
        resource_id="p1",
        region="global",
        category="iam",
        attributes={"policy_document": {"Statement": ["not a dict"]}},
    )
    assert rule.evaluate(res_stmt_not_dict).status == Status.ERROR


# --- CloudTrailLoggingRule (CT-001) ---


def test_cloudtrail_trail_evaluation():
    rule = CloudTrailLoggingRule()

    # Pass: trail logging
    res_pass = Resource(
        resource_type=CLOUDTRAIL_TRAIL,
        resource_id="trail-1",
        region="us-east-1",
        category="cloudtrail",
        attributes={"is_logging": True, "is_multi_region": False},
    )
    assert rule.evaluate(res_pass).status == Status.PASS

    # Fail: trail stopped
    res_fail = Resource(
        resource_type=CLOUDTRAIL_TRAIL,
        resource_id="trail-2",
        region="us-east-1",
        category="cloudtrail",
        attributes={"is_logging": False, "is_multi_region": False},
    )
    res_fail_res = rule.evaluate(res_fail)
    assert res_fail_res.status == Status.FAIL
    assert "logging is stopped" in res_fail_res.summary

    # Error: is_logging not boolean
    res_err = Resource(
        resource_type=CLOUDTRAIL_TRAIL,
        resource_id="trail-3",
        region="us-east-1",
        category="cloudtrail",
        attributes={"is_logging": "yes"},
    )
    assert rule.evaluate(res_err).status == Status.ERROR

    # Error: unavailable attribute
    res_unavail = Resource(
        resource_type=CLOUDTRAIL_TRAIL,
        resource_id="trail-4",
        region="us-east-1",
        category="cloudtrail",
        fetch_errors=[FetchError(attribute="is_logging", code="AccessDenied")],
    )
    assert rule.evaluate(res_unavail).status == Status.ERROR


def test_cloudtrail_region_evaluation():
    rule = CloudTrailLoggingRule()

    # Pass: covered by logging trail
    res_pass = Resource(
        resource_type=CLOUDTRAIL_REGION,
        resource_id="region-coverage",
        region="us-east-1",
        category="cloudtrail",
        attributes={
            "trails": [
                {
                    "name": "t1",
                    "home_region": "us-east-1",
                    "is_multi_region": False,
                    "is_logging": True,
                }
            ]
        },
    )
    assert rule.evaluate(res_pass).status == Status.PASS

    # Fail: trail covers but not logging
    res_fail = Resource(
        resource_type=CLOUDTRAIL_REGION,
        resource_id="region-coverage",
        region="eu-west-1",
        category="cloudtrail",
        attributes={
            "trails": [
                {
                    "name": "t2",
                    "home_region": "eu-west-1",
                    "is_multi_region": False,
                    "is_logging": False,
                }
            ]
        },
    )
    res_fail_res = rule.evaluate(res_fail)
    assert res_fail_res.status == Status.FAIL
    assert "none of them is logging" in res_fail_res.summary

    # Fail: no trail covers region
    res_no_trail = Resource(
        resource_type=CLOUDTRAIL_REGION,
        resource_id="region-coverage",
        region="ap-southeast-1",
        category="cloudtrail",
        attributes={
            "trails": [
                {
                    "name": "t1",
                    "home_region": "us-east-1",
                    "is_multi_region": False,
                    "is_logging": True,
                }
            ]
        },
    )
    res_no_trail_res = rule.evaluate(res_no_trail)
    assert res_no_trail_res.status == Status.FAIL
    assert "No CloudTrail trail covers region" in res_no_trail_res.summary

    # Error: trail status unknown
    res_unknown = Resource(
        resource_type=CLOUDTRAIL_REGION,
        resource_id="region-coverage",
        region="us-east-1",
        category="cloudtrail",
        attributes={
            "trails": [
                {
                    "name": "t1",
                    "home_region": "us-east-1",
                    "is_multi_region": False,
                    "is_logging": None,
                }
            ]
        },
    )
    assert rule.evaluate(res_unknown).status == Status.ERROR

    # Error: malformed trails
    res_bad = Resource(
        resource_type=CLOUDTRAIL_REGION,
        resource_id="region-coverage",
        region="us-east-1",
        category="cloudtrail",
        attributes={"trails": "not a list"},
    )
    assert rule.evaluate(res_bad).status == Status.ERROR

    # Error: unavailable trails
    res_unavail = Resource(
        resource_type=CLOUDTRAIL_REGION,
        resource_id="region-coverage",
        region="us-east-1",
        category="cloudtrail",
        fetch_errors=[FetchError(attribute="trails", code="AccessDenied")],
    )
    assert rule.evaluate(res_unavail).status == Status.ERROR

    # Error: trail dict missing required keys
    res_missing_keys = Resource(
        resource_type=CLOUDTRAIL_REGION,
        resource_id="region-coverage",
        region="us-east-1",
        category="cloudtrail",
        attributes={"trails": [{"only_name": "t1"}]},
    )
    assert rule.evaluate(res_missing_keys).status == Status.ERROR


def test_build_rules():
    config = AppConfig(
        rules={
            "S3-001": RuleSettings(enabled=True, severity=Severity.HIGH),
            "S3-002": RuleSettings(enabled=False, severity=Severity.MEDIUM),
            "IAM-001": RuleSettings(enabled=True, severity=Severity.HIGH),
            "CT-001": RuleSettings(enabled=True, severity=Severity.HIGH),
        },
        s3_encryption=S3EncryptionSettings(approved_algorithms=["AES256"]),
    )
    rules = build_rules(config)
    rule_ids = [r.rule_id for r in rules]
    assert "S3-001" in rule_ids
    assert "S3-002" not in rule_ids
    assert len(rules) == 3
