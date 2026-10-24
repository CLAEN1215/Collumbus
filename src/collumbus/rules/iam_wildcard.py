"""IAM-001: IAM policy statements with wildcard permissions that deserve review.

This is a pattern check, not a full IAM policy-evaluation engine. It does not
evaluate Conditions, permission boundaries, SCPs, resource policies, or Deny
statements in other policies. A flagged statement is a candidate for review,
not proof that it is exploitable.
"""

import json

from collumbus.collectors.base import IAM_POLICY, Resource
from collumbus.models import Severity, Status
from collumbus.rules.base import Rule, RuleResult


def _as_list(value):
    return value if isinstance(value, list) else [value]


class IamWildcardRule(Rule):
    rule_id = "IAM-001"
    title = "IAM policy wildcard permissions"
    resource_types = frozenset({IAM_POLICY})
    default_severity = Severity.HIGH
    risk = (
        "Wildcard permissions can grant far more access than a user or service needs. If the "
        "identity is compromised, the attacker gets all of that access."
    )
    remediation = (
        "Replace wildcards with the specific actions and resources this identity needs. IAM "
        "Access Analyzer can generate a policy from actual activity in CloudTrail."
    )
    references = [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_elements_action.html",
    ]

    def evaluate(self, resource: Resource) -> RuleResult:
        if error := self.unavailable(resource, "policy_document"):
            return error
        document = resource.attributes["policy_document"]

        # AWS sometimes returns the document as a JSON string.
        if isinstance(document, str):
            try:
                document = json.loads(document)
            except json.JSONDecodeError:
                return self.malformed("policy_document", "not valid JSON")
        if not isinstance(document, dict) or "Statement" not in document:
            return self.malformed("policy_document", "missing Statement")

        flagged = []
        for index, statement in enumerate(_as_list(document["Statement"])):
            if not isinstance(statement, dict):
                return self.malformed("policy_document", f"statement {index} is not an object")
            if statement.get("Effect") != "Allow":
                continue
            pattern = self._broad_pattern(statement)
            if pattern:
                flagged.append(
                    {
                        "statement_index": index,
                        "sid": statement.get("Sid"),
                        "pattern": pattern,
                        "has_condition": "Condition" in statement,
                    }
                )

        if flagged:
            return RuleResult(
                status=Status.FAIL,
                summary=f"{len(flagged)} statement(s) grant broad wildcard permissions; review.",
                evidence={"flagged_statements": flagged},
            )
        return RuleResult(
            status=Status.PASS,
            summary="No broad wildcard patterns found in Allow statements.",
            evidence={"statements_checked": len(_as_list(document["Statement"]))},
        )

    @staticmethod
    def _broad_pattern(statement: dict) -> str | None:
        """Describe the broad pattern in one Allow statement, or None."""
        resources = [str(r) for r in _as_list(statement.get("Resource", []))]
        all_resources = "*" in resources

        if "NotAction" in statement:
            # Allow + NotAction grants every action except the listed ones.
            return "Allow with NotAction (grants all actions except those listed)"

        actions = [str(a) for a in _as_list(statement.get("Action", []))]
        if "*" in actions:
            if all_resources:
                return 'Action "*" on Resource "*" (administrator-equivalent)'
            return 'Action "*" (all actions)'
        service_wildcards = [a for a in actions if a.endswith(":*")]
        if service_wildcards and all_resources:
            return f'{", ".join(service_wildcards)} on Resource "*"'
        return None
