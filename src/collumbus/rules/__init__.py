"""Security rules. Each rule evaluates one normalized resource and returns a verdict."""

from collumbus.config import AppConfig
from collumbus.rules.base import Rule, RuleResult
from collumbus.rules.cloudtrail_logging import CloudTrailLoggingRule
from collumbus.rules.iam_wildcard import IamWildcardRule
from collumbus.rules.s3_encryption import S3DefaultEncryptionRule
from collumbus.rules.s3_public_access import S3PublicAccessBlockRule

ALL_RULES: list[type[Rule]] = [
    S3PublicAccessBlockRule,
    S3DefaultEncryptionRule,
    IamWildcardRule,
    CloudTrailLoggingRule,
]


def build_rules(config: AppConfig) -> list[Rule]:
    """Create the rules enabled in config. Rules missing from config are enabled."""
    rules = []
    for rule_cls in ALL_RULES:
        settings = config.rules.get(rule_cls.rule_id)
        if settings is None or settings.enabled:
            rules.append(rule_cls(config))
    return rules


__all__ = ["ALL_RULES", "Rule", "RuleResult", "build_rules"]
