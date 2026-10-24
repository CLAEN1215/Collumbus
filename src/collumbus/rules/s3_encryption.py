"""S3-002: S3 default encryption matches the project's approved list."""

from collumbus.collectors.base import S3_BUCKET, Resource
from collumbus.models import Severity, Status
from collumbus.rules.base import Rule, RuleResult

# Used when no config is supplied (e.g. in some tests). Normally from rules.yaml.
DEFAULT_APPROVED = ("AES256", "aws:kms", "aws:kms:dsse")


class S3DefaultEncryptionRule(Rule):
    rule_id = "S3-002"
    title = "S3 bucket default encryption"
    resource_types = frozenset({S3_BUCKET})
    default_severity = Severity.MEDIUM
    risk = (
        "New objects might not be encrypted at rest with an approved method. Note: since "
        "January 2023 AWS applies SSE-S3 to new objects by default, so a Fail here usually "
        "means the bucket configuration does not match this project's policy, not that data "
        "is stored unencrypted."
    )
    remediation = (
        "Set default encryption to an approved method: S3 console > bucket > Properties > "
        "Default encryption > Edit. Choose SSE-S3 or SSE-KMS."
    )
    references = [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html",
    ]

    def approved_algorithms(self) -> list[str]:
        if self.config is None:
            return list(DEFAULT_APPROVED)
        return self.config.s3_encryption.approved_algorithms

    def evaluate(self, resource: Resource) -> RuleResult:
        if error := self.unavailable(resource, "encryption_rules"):
            return error
        rules = resource.attributes["encryption_rules"]

        # None = AWS reported no default encryption configuration
        # (ServerSideEncryptionConfigurationNotFoundError). This is a real answer, not an error.
        if rules is None:
            return RuleResult(
                status=Status.FAIL,
                summary="No default encryption configuration is set on this bucket.",
                evidence={"encryption_rules": None},
            )
        if not isinstance(rules, list) or not rules:
            return self.malformed("encryption_rules", "expected a non-empty list")

        algorithms: list[str] = []
        for rule in rules:
            if not isinstance(rule, dict):
                return self.malformed("encryption_rules", "each rule needs an sse_algorithm")
            alg = rule.get("sse_algorithm")
            if not isinstance(alg, str):
                return self.malformed("encryption_rules", "each rule needs an sse_algorithm")
            algorithms.append(alg)

        approved = self.approved_algorithms()
        unapproved = [a for a in algorithms if a not in approved]
        evidence = {"sse_algorithms": algorithms, "approved_algorithms": approved}
        if unapproved:
            return RuleResult(
                status=Status.FAIL,
                summary=f"Default encryption uses an unapproved method: {', '.join(unapproved)}.",
                evidence={**evidence, "unapproved": unapproved},
            )
        return RuleResult(
            status=Status.PASS,
            summary=f"Default encryption uses an approved method: {', '.join(algorithms)}.",
            evidence=evidence,
        )
