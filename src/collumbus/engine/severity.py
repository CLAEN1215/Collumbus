"""Severity assignment, kept separate from pass/fail evaluation.

A rule decides *whether* something is wrong (status). This module decides *how
serious* it is (severity), using only the status and the configured level.
"""

from collumbus.config import AppConfig
from collumbus.models import Severity, Status
from collumbus.rules.base import Rule


def assign_severity(rule: Rule, status: Status, config: AppConfig | None) -> Severity:
    """Fail -> the rule's configured severity. Anything else -> Informational.

    Error is Informational because it does not establish a weakness; it means the
    check could not run. Error findings are still counted and shown separately,
    and they make the scan incomplete, so they cannot be overlooked as passes.
    """
    if status != Status.FAIL:
        return Severity.INFORMATIONAL
    if config is not None and rule.rule_id in config.rules:
        return config.rules[rule.rule_id].severity
    return rule.default_severity
