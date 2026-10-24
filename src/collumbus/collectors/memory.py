"""In-memory and file-based collectors for Shift-Left Security audits.

Enables auditing:
  * Raw IAM policy documents (JSON),
  * S3 Public Access Block configurations,
  * AWS CloudFormation templates,
  * Columbus inventory / demo JSON exports.
"""

from __future__ import annotations

import json

from pydantic import ValidationError

from collumbus.collectors.base import (
    IAM_POLICY,
    S3_BUCKET,
    CollectionResult,
    Collector,
    Resource,
)
from collumbus.collectors.demo import DemoFile
from collumbus.models import Source


class FileParseError(Exception):
    """Raised when an uploaded or pasted document cannot be parsed."""


class MemoryCollector(Collector):
    """Collector that returns a pre-parsed CollectionResult from memory."""

    def __init__(self, result: CollectionResult) -> None:
        self.result = result

    def collect(self) -> CollectionResult:
        return self.result


def parse_input_to_collection(
    content: str,
    target_name: str = "Uploaded Document",
) -> CollectionResult:
    """Parse JSON text into a normalized CollectionResult for audit.

    Intelligently handles:
      1. Full Columbus JSON / Demo format
      2. IAM Policy Document ('Statement')
      3. S3 Public Access Block config ('BlockPublicAcls')
      4. AWS CloudFormation template ('Resources')
      5. List of resource dicts
    """
    cleaned = content.strip()
    if not cleaned:
        raise FileParseError("Input content is empty.")

    try:
        raw = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise FileParseError(f"Invalid JSON syntax at line {exc.lineno}: {exc.msg}") from exc

    resources: list[Resource] = []
    categories: set[str] = set()
    regions: set[str] = set()
    account_id = "111122223333"

    # Case 1: Full Columbus / Demo schema
    if isinstance(raw, dict) and ("resources" in raw or "schema_version" in raw):
        try:
            demo = DemoFile.model_validate(raw)
            return CollectionResult(
                source=Source.DEMO,
                account_id=demo.account_id,
                regions=demo.regions,
                resource_categories=demo.resource_categories,
                resources=demo.resources,
                gaps=demo.gaps,
            )
        except ValidationError:
            raw_resources = raw.get("resources", [])
            for item in raw_resources:
                if isinstance(item, dict):
                    res = Resource.model_validate(item)
                    resources.append(res)
                    categories.add(res.category)
                    regions.add(res.region)
            if resources:
                return CollectionResult(
                    source=Source.DEMO,
                    account_id=str(raw.get("account_id", account_id)),
                    regions=sorted(regions) or ["us-east-1"],
                    resource_categories=sorted(categories) or ["s3", "iam"],
                    resources=resources,
                    gaps=[],
                )

    # Case 2: AWS CloudFormation Template
    if isinstance(raw, dict) and "Resources" in raw and isinstance(raw["Resources"], dict):
        cfn_resources = raw["Resources"]
        for res_id, res_body in cfn_resources.items():
            if not isinstance(res_body, dict):
                continue
            res_type = res_body.get("Type", "")
            properties = res_body.get("Properties", {})
            if res_type == "AWS::S3::Bucket":
                pab = properties.get("PublicAccessBlockConfiguration")
                enc = properties.get("BucketEncryption")
                enc_rules = None
                if isinstance(enc, dict) and "ServerSideEncryptionConfiguration" in enc:
                    enc_rules = enc["ServerSideEncryptionConfiguration"]
                bucket_name = properties.get("BucketName", res_id)
                resources.append(
                    Resource(
                        resource_type=S3_BUCKET,
                        resource_id=bucket_name,
                        region="us-east-1",
                        category="s3",
                        attributes={
                            "public_access_block": pab,
                            "encryption_rules": enc_rules,
                        },
                    )
                )
                categories.add("s3")
                regions.add("us-east-1")
            elif res_type in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
                doc = properties.get("PolicyDocument")
                if doc:
                    policy_name = properties.get("PolicyName", res_id)
                    resources.append(
                        Resource(
                            resource_type=IAM_POLICY,
                            resource_id=policy_name,
                            region="global",
                            category="iam",
                            attributes={
                                "policy_document": doc,
                            },
                        )
                    )
                    categories.add("iam")
                    regions.add("global")

        if resources:
            return CollectionResult(
                source=Source.DEMO,
                account_id=account_id,
                regions=sorted(regions),
                resource_categories=sorted(categories),
                resources=resources,
                gaps=[],
            )

    # Case 3: AWS IAM Policy Document (has Statement)
    if isinstance(raw, dict) and ("Statement" in raw or "PolicyDocument" in raw):
        doc = raw.get("PolicyDocument", raw)
        clean_name = target_name.replace(".json", "") or "Uploaded-IAM-Policy"
        policy_name = raw.get("PolicyName", clean_name)
        resources.append(
            Resource(
                resource_type=IAM_POLICY,
                resource_id=str(policy_name),
                region="global",
                category="iam",
                attributes={
                    "policy_document": doc,
                },
            )
        )
        return CollectionResult(
            source=Source.DEMO,
            account_id=account_id,
            regions=["global"],
            resource_categories=["iam"],
            resources=resources,
            gaps=[],
        )

    # Case 4: S3 Public Access Block Configuration or Bucket Details
    if isinstance(raw, dict) and (
        "BlockPublicAcls" in raw
        or "PublicAccessBlockConfiguration" in raw
        or "public_access_block" in raw
    ):
        pab = raw.get("PublicAccessBlockConfiguration") or raw.get("public_access_block") or raw
        enc_rules = raw.get("encryption_rules") or raw.get("ServerSideEncryptionConfiguration")
        clean_bucket = target_name.replace(".json", "") or "uploaded-s3-bucket"
        bucket_name = raw.get("BucketName", raw.get("bucket_name", clean_bucket))
        resources.append(
            Resource(
                resource_type=S3_BUCKET,
                resource_id=str(bucket_name),
                region="us-east-1",
                category="s3",
                attributes={
                    "public_access_block": pab,
                    "encryption_rules": enc_rules,
                },
            )
        )
        return CollectionResult(
            source=Source.DEMO,
            account_id=account_id,
            regions=["us-east-1"],
            resource_categories=["s3"],
            resources=resources,
            gaps=[],
        )

    # Case 5: Raw list of statements
    if isinstance(raw, list) and all(isinstance(item, dict) and "Effect" in item for item in raw):
        doc = {"Version": "2012-10-17", "Statement": raw}
        resources.append(
            Resource(
                resource_type=IAM_POLICY,
                resource_id="Uploaded-IAM-Policy",
                region="global",
                category="iam",
                attributes={"policy_document": doc},
            )
        )
        return CollectionResult(
            source=Source.DEMO,
            account_id=account_id,
            regions=["global"],
            resource_categories=["iam"],
            resources=resources,
            gaps=[],
        )

    # Case 6: Raw list of Resource objects
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                try:
                    res = Resource.model_validate(item)
                    resources.append(res)
                    categories.add(res.category)
                    regions.add(res.region)
                except ValidationError:
                    pass
        if resources:
            return CollectionResult(
                source=Source.DEMO,
                account_id=account_id,
                regions=sorted(regions) or ["us-east-1"],
                resource_categories=sorted(categories) or ["s3", "iam"],
                resources=resources,
                gaps=[],
            )

    raise FileParseError(
        "Could not detect recognized AWS resource format. "
        "Expected an IAM Policy ('Statement'), S3 Block Public Access ('BlockPublicAcls'), "
        "CloudFormation ('Resources'), or Columbus JSON inventory format."
    )
