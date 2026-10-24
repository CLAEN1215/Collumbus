"""AWS read-only collector using official boto3 SDK.

Follows non-negotiable principles:
  * Read-only operations only. Never creates, modifies, or deletes any cloud resource.
  * Standard AWS credential chain (environment variables, ~/.aws/credentials, IAM roles).
  * API errors, missing permissions, and throttling are recorded as gaps or fetch_errors.
  * Results are labeled as AWS source.
"""

import json
import logging
from collections.abc import Sequence
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from collumbus.collectors.base import (
    CLOUDTRAIL_REGION,
    CLOUDTRAIL_TRAIL,
    IAM_POLICY,
    S3_BUCKET,
    CollectionResult,
    Collector,
    FetchError,
    Resource,
)
from collumbus.models import CoverageGap, Source

logger = logging.getLogger(__name__)

DEFAULT_REGIONS = ("us-east-1", "eu-west-1")


class AwsCredentialsError(Exception):
    """Raised when AWS credentials are not configured or cannot be resolved."""


class AwsCollector(Collector):
    """Gathers AWS configurations using read-only boto3 calls."""

    def __init__(
        self,
        session: boto3.Session | None = None,
        profile_name: str | None = None,
        regions: Sequence[str] | None = None,
    ) -> None:
        self.session = session or boto3.Session(profile_name=profile_name)
        self.regions = list(regions or DEFAULT_REGIONS)
        self.resource_categories = ["s3", "iam", "cloudtrail"]

    def _get_account_id(self) -> str:
        """Resolve current AWS account ID via STS get_caller_identity."""
        try:
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()
            account = identity.get("Account")
            if not account or len(account) != 12 or not account.isdigit():
                raise AwsCredentialsError(f"Unexpected AWS account format from STS: {account}")
            return account
        except (NoCredentialsError, PartialCredentialsError) as exc:
            raise AwsCredentialsError(
                "AWS credentials not found. Configure them with 'aws configure' "
                "or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
            ) from exc
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            msg = exc.response.get("Error", {}).get("Message", str(exc))
            raise AwsCredentialsError(f"Failed to authenticate with AWS ({code}): {msg}") from exc

    def collect(self) -> CollectionResult:
        account_id = self._get_account_id()
        resources: list[Resource] = []
        gaps: list[CoverageGap] = []

        # 1. Collect S3 Buckets
        s3_res, s3_gaps = self._collect_s3()
        resources.extend(s3_res)
        gaps.extend(s3_gaps)

        # 2. Collect IAM Policies
        iam_res, iam_gaps = self._collect_iam()
        resources.extend(iam_res)
        gaps.extend(iam_gaps)

        # 3. Collect CloudTrail Trails & Regional Coverage
        ct_res, ct_gaps = self._collect_cloudtrail()
        resources.extend(ct_res)
        gaps.extend(ct_gaps)

        # Deterministic sorting
        resources.sort(key=lambda r: (r.category, r.resource_type, r.region, r.resource_id))

        return CollectionResult(
            source=Source.AWS,
            account_id=account_id,
            regions=self.regions,
            resource_categories=self.resource_categories,
            resources=resources,
            gaps=gaps,
        )

    # --- S3 Collection -------------------------------------------------------

    def _collect_s3(self) -> tuple[list[Resource], list[CoverageGap]]:
        resources: list[Resource] = []
        gaps: list[CoverageGap] = []
        s3 = self.session.client("s3")

        try:
            response = s3.list_buckets()
            buckets = response.get("Buckets", [])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Error")
            gaps.append(
                CoverageGap(
                    category="s3",
                    region="global",
                    reason=code,
                    missing_permission="s3:ListAllMyBuckets",
                    detail="List S3 buckets",
                )
            )
            return resources, gaps

        for b in buckets:
            name = b["Name"]
            region = self._get_bucket_region(s3, name)

            # Only inspect buckets located in the requested regions
            if region not in self.regions:
                continue

            attributes: dict[str, object] = {}
            fetch_errors: list[FetchError] = []

            # Check Public Access Block
            pab_val, pab_err = self._get_public_access_block(s3, name)
            if pab_err:
                fetch_errors.append(pab_err)
            else:
                attributes["public_access_block"] = pab_val

            # Check Default Encryption
            enc_val, enc_err = self._get_bucket_encryption(s3, name)
            if enc_err:
                fetch_errors.append(enc_err)
            else:
                attributes["encryption_rules"] = enc_val

            resources.append(
                Resource(
                    resource_type=S3_BUCKET,
                    resource_id=name,
                    region=region,
                    category="s3",
                    attributes=attributes,
                    fetch_errors=fetch_errors,
                )
            )

        return resources, gaps

    @staticmethod
    def _get_bucket_region(s3, bucket_name: str) -> str:
        """Resolve bucket region, normalizing AWS location constraints."""
        try:
            resp = s3.get_bucket_location(Bucket=bucket_name)
            loc = resp.get("LocationConstraint")
            if not loc:
                return "us-east-1"
            if loc == "EU":
                return "eu-west-1"
            return loc
        except ClientError:
            return "us-east-1"

    @staticmethod
    def _get_public_access_block(s3, bucket_name: str) -> tuple[dict | None, FetchError | None]:
        try:
            resp = s3.get_public_access_block(Bucket=bucket_name)
            config = resp.get("PublicAccessBlockConfiguration", {})
            return {
                "BlockPublicAcls": config.get("BlockPublicAcls", False),
                "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
                "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
                "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False),
            }, None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Error")
            if code == "NoSuchPublicAccessBlockConfiguration":
                return None, None
            return None, FetchError(
                attribute="public_access_block",
                code=code,
                message=exc.response.get("Error", {}).get("Message", ""),
                permission="s3:GetBucketPublicAccessBlock",
            )

    @staticmethod
    def _get_bucket_encryption(s3, bucket_name: str) -> tuple[list[dict] | None, FetchError | None]:
        try:
            resp = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            formatted = []
            for r in rules:
                default_apply = r.get("ApplyServerSideEncryptionByDefault", {})
                formatted.append(
                    {
                        "sse_algorithm": default_apply.get("SSEAlgorithm", ""),
                        "bucket_key_enabled": r.get("BucketKeyEnabled", False),
                    }
                )
            return formatted, None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Error")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                return None, None
            return None, FetchError(
                attribute="encryption_rules",
                code=code,
                message=exc.response.get("Error", {}).get("Message", ""),
                permission="s3:GetEncryptionConfiguration",
            )

    # --- IAM Collection ------------------------------------------------------

    def _collect_iam(self) -> tuple[list[Resource], list[CoverageGap]]:
        resources: list[Resource] = []
        gaps: list[CoverageGap] = []
        iam = self.session.client("iam")

        try:
            # Audit customer-managed policies only (Scope='Local')
            paginator = iam.get_paginator("list_policies")
            policies = []
            for page in paginator.paginate(Scope="Local"):
                policies.extend(page.get("Policies", []))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Error")
            gaps.append(
                CoverageGap(
                    category="iam",
                    region="global",
                    reason=code,
                    missing_permission="iam:ListPolicies",
                    detail="Customer managed IAM policies",
                )
            )
            return resources, gaps

        for pol in policies:
            arn = pol["Arn"]
            version_id = pol.get("DefaultVersionId")
            attributes: dict[str, object] = {"policy_type": "customer-managed"}
            fetch_errors: list[FetchError] = []

            try:
                ver_resp = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                raw_doc = ver_resp.get("PolicyVersion", {}).get("Document", {})
                if isinstance(raw_doc, str):
                    raw_doc = json.loads(unquote(raw_doc))
                attributes["policy_document"] = raw_doc
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Error")
                fetch_errors.append(
                    FetchError(
                        attribute="policy_document",
                        code=code,
                        message=exc.response.get("Error", {}).get("Message", ""),
                        permission="iam:GetPolicyVersion",
                    )
                )

            resources.append(
                Resource(
                    resource_type=IAM_POLICY,
                    resource_id=arn,
                    region="global",
                    category="iam",
                    attributes=attributes,
                    fetch_errors=fetch_errors,
                )
            )

        return resources, gaps

    # --- CloudTrail Collection -----------------------------------------------

    def _collect_cloudtrail(self) -> tuple[list[Resource], list[CoverageGap]]:
        resources: list[Resource] = []
        gaps: list[CoverageGap] = []
        all_discovered_trails: list[dict] = []

        # First pass: collect trails from all requested regions
        for region in self.regions:
            ct = self.session.client("cloudtrail", region_name=region)
            try:
                resp = ct.describe_trails(includeShadowTrails=False)
                trails = resp.get("trailList", [])
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Error")
                gaps.append(
                    CoverageGap(
                        category="cloudtrail",
                        region=region,
                        reason=code,
                        missing_permission="cloudtrail:DescribeTrails",
                        detail=f"CloudTrail trails in {region}",
                    )
                )
                continue

            for t in trails:
                name = t["Name"]
                home_region = t.get("HomeRegion", region)
                is_multi = t.get("IsMultiRegionTrail", False)

                # Query trail status
                is_logging = None
                fetch_errors: list[FetchError] = []
                try:
                    status_resp = ct.get_trail_status(Name=t.get("TrailARN", name))
                    is_logging = status_resp.get("IsLogging", False)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "Error")
                    fetch_errors.append(
                        FetchError(
                            attribute="is_logging",
                            code=code,
                            message=exc.response.get("Error", {}).get("Message", ""),
                            permission="cloudtrail:GetTrailStatus",
                        )
                    )

                # Only emit a Trail resource in its HomeRegion to prevent duplicate resources
                if home_region == region:
                    attributes: dict[str, object] = {"is_multi_region": is_multi}
                    if is_logging is not None:
                        attributes["is_logging"] = is_logging

                    resources.append(
                        Resource(
                            resource_type=CLOUDTRAIL_TRAIL,
                            resource_id=name,
                            region=home_region,
                            category="cloudtrail",
                            attributes=attributes,
                            fetch_errors=fetch_errors,
                        )
                    )

                all_discovered_trails.append(
                    {
                        "name": name,
                        "home_region": home_region,
                        "is_multi_region": is_multi,
                        "is_logging": is_logging,
                    }
                )

        # Second pass: synthesize region coverage resource for each requested region
        for region in self.regions:
            resources.append(
                Resource(
                    resource_type=CLOUDTRAIL_REGION,
                    resource_id="region-coverage",
                    region=region,
                    category="cloudtrail",
                    attributes={"trails": all_discovered_trails},
                )
            )

        return resources, gaps
