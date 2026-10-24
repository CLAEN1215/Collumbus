"""Tests for MemoryCollector and parse_input_to_collection."""

import pytest

from collumbus.collectors import (
    FileParseError,
    MemoryCollector,
    parse_input_to_collection,
)
from collumbus.config import load_config
from collumbus.engine import run_scan
from collumbus.models import Status


def test_parse_vulnerable_iam_policy():
    raw = """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        }
      ]
    }"""
    collection = parse_input_to_collection(raw, target_name="VulnerablePolicy.json")
    assert len(collection.resources) == 1
    assert collection.resources[0].resource_type == "AWS::IAM::Policy"
    assert collection.resources[0].category == "iam"

    scan = run_scan(MemoryCollector(collection), load_config())
    assert len(scan.findings) >= 1
    iam_findings = [f for f in scan.findings if f.rule_id == "IAM-001"]
    assert len(iam_findings) == 1
    assert iam_findings[0].status == Status.FAIL


def test_parse_secure_iam_policy():
    raw = """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": ["s3:GetObject"],
          "Resource": ["arn:aws:s3:::my-bucket/*"]
        }
      ]
    }"""
    collection = parse_input_to_collection(raw, target_name="SecurePolicy.json")
    scan = run_scan(MemoryCollector(collection), load_config())
    iam_findings = [f for f in scan.findings if f.rule_id == "IAM-001"]
    assert len(iam_findings) == 1
    assert iam_findings[0].status == Status.PASS


def test_parse_vulnerable_s3_config():
    raw = """{
      "BucketName": "unprotected-data",
      "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
      }
    }"""
    collection = parse_input_to_collection(raw)
    assert len(collection.resources) == 1
    assert collection.resources[0].resource_type == "AWS::S3::Bucket"

    scan = run_scan(MemoryCollector(collection), load_config())
    s3_findings = [f for f in scan.findings if f.rule_id == "S3-001"]
    assert len(s3_findings) == 1
    assert s3_findings[0].status == Status.FAIL


def test_parse_cloudformation_template():
    raw = """{
      "AWSTemplateFormatVersion": "2010-09-09",
      "Resources": {
        "TestBucket": {
          "Type": "AWS::S3::Bucket",
          "Properties": {
            "BucketName": "cfn-test-bucket",
            "PublicAccessBlockConfiguration": {
              "BlockPublicAcls": false,
              "BlockPublicPolicy": false
            }
          }
        },
        "TestPolicy": {
          "Type": "AWS::IAM::Policy",
          "Properties": {
            "PolicyName": "CfnAdminPolicy",
            "PolicyDocument": {
              "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
          }
        }
      }
    }"""
    collection = parse_input_to_collection(raw)
    assert len(collection.resources) == 2
    types = {r.resource_type for r in collection.resources}
    assert "AWS::S3::Bucket" in types
    assert "AWS::IAM::Policy" in types

    scan = run_scan(MemoryCollector(collection), load_config())
    failures = [f for f in scan.findings if f.status == Status.FAIL]
    assert len(failures) >= 2


def test_parse_invalid_json():
    with pytest.raises(FileParseError, match="Invalid JSON syntax"):
        parse_input_to_collection("{invalid json}")


def test_parse_empty_content():
    with pytest.raises(FileParseError, match="Input content is empty"):
        parse_input_to_collection("   ")


def test_parse_unrecognized_format():
    with pytest.raises(FileParseError, match="Could not detect recognized AWS resource format"):
        parse_input_to_collection('{"unknown_key": "some_value"}')
