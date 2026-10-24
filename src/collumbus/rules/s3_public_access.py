"""S3-001: S3 Block Public Access settings on each bucket."""

from collumbus.collectors.base import S3_BUCKET, Resource
from collumbus.models import Severity, Status
from collumbus.rules.base import Rule, RuleResult

REQUIRED_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


class S3PublicAccessBlockRule(Rule):
    rule_id = "S3-001"
    title = "S3 bucket Block Public Access settings"
    resource_types = frozenset({S3_BUCKET})
    default_severity = Severity.HIGH
    risk = (
        "With a Block Public Access setting off, an ACL or bucket policy could make data in "
        "this bucket public. This check does not prove the bucket is currently public, and a "
        "pass does not prove every path to public access is closed (account-level settings, "
        "access points, and existing policies are not evaluated)."
    )
    remediation = (
        "Turn on all four Block Public Access settings for the bucket: S3 console > bucket > "
        "Permissions > Block public access > Edit. First confirm nothing legitimately depends "
        "on public access."
    )
    references = [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    ]

    def evaluate(self, resource: Resource) -> RuleResult:
        if error := self.unavailable(resource, "public_access_block"):
            return error
        config = resource.attributes["public_access_block"]

        if config is None:
            return RuleResult(
                status=Status.FAIL,
                summary="No bucket-level Block Public Access configuration exists.",
                evidence={"public_access_block": None},
            )
        if not isinstance(config, dict):
            return self.malformed("public_access_block", "expected an object")

        settings = {name: config.get(name) for name in REQUIRED_SETTINGS}
        not_bool = [n for n, v in settings.items() if v is not None and not isinstance(v, bool)]
        if not_bool:
            return self.malformed("public_access_block", f"non-boolean values: {not_bool}")

        # A missing setting (None) is treated the same as a disabled one: not a pass.
        not_enabled = [name for name, value in settings.items() if value is not True]
        if not_enabled:
            return RuleResult(
                status=Status.FAIL,
                summary=f"Block Public Access is incomplete: {', '.join(not_enabled)} not enabled.",
                evidence={**settings, "not_enabled": not_enabled},
            )
        return RuleResult(
            status=Status.PASS,
            summary="All four Block Public Access settings are enabled on this bucket.",
            evidence=settings,
        )
