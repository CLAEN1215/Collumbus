"""CT-001: CloudTrail is configured and logging.

Checks two things:
  * each trail found is actually logging (not stopped), and
  * each scanned region is covered by at least one logging trail.
Only the regions that were scanned are evaluated; no claim is made about others.
"""

from collumbus.collectors.base import CLOUDTRAIL_REGION, CLOUDTRAIL_TRAIL, Resource
from collumbus.models import Severity, Status
from collumbus.rules.base import Rule, RuleResult


class CloudTrailLoggingRule(Rule):
    rule_id = "CT-001"
    title = "CloudTrail logging"
    resource_types = frozenset({CLOUDTRAIL_TRAIL, CLOUDTRAIL_REGION})
    default_severity = Severity.HIGH
    risk = (
        "Without active CloudTrail logging, API activity in this region is not recorded, so "
        "misuse or an attack may be impossible to investigate afterwards."
    )
    remediation = (
        "Create a multi-region trail, or start logging on the existing trail: CloudTrail "
        "console > Trails > select trail > Start logging."
    )
    references = [
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
    ]

    def evaluate(self, resource: Resource) -> RuleResult:
        if resource.resource_type == CLOUDTRAIL_TRAIL:
            return self._evaluate_trail(resource)
        return self._evaluate_region(resource)

    def _evaluate_trail(self, resource: Resource) -> RuleResult:
        if error := self.unavailable(resource, "is_logging"):
            return error
        is_logging = resource.attributes["is_logging"]
        if not isinstance(is_logging, bool):
            return self.malformed("is_logging", "expected true or false")
        multi_region = resource.attributes.get("is_multi_region")
        evidence = {"is_logging": is_logging, "is_multi_region": multi_region}
        if not is_logging:
            return RuleResult(
                status=Status.FAIL,
                summary="This trail exists but logging is stopped.",
                evidence=evidence,
                remediation=(
                    "Start logging: CloudTrail console > Trails > this trail > Start logging."
                ),
            )
        return RuleResult(status=Status.PASS, summary="This trail is logging.", evidence=evidence)

    def _evaluate_region(self, resource: Resource) -> RuleResult:
        if error := self.unavailable(resource, "trails"):
            return error
        trails = resource.attributes["trails"]
        if not isinstance(trails, list):
            return self.malformed("trails", "expected a list")
        for trail in trails:
            if not isinstance(trail, dict) or not {"name", "home_region"} <= set(trail):
                return self.malformed("trails", "each trail needs name and home_region")

        region = resource.region
        covering = [
            t for t in trails if t.get("is_multi_region") is True or t["home_region"] == region
        ]
        logging_names = [t["name"] for t in covering if t.get("is_logging") is True]
        unknown_names = [t["name"] for t in covering if not isinstance(t.get("is_logging"), bool)]
        evidence = {
            "region": region,
            "trails_covering_region": [t["name"] for t in covering],
            "logging_trails": logging_names,
            "trails_with_unknown_status": unknown_names,
        }

        if logging_names:
            trails_str = ", ".join(logging_names)
            return RuleResult(
                status=Status.PASS,
                summary=f"Region {region} is covered by logging trail(s): {trails_str}.",
                evidence=evidence,
            )
        if unknown_names:
            return RuleResult(
                status=Status.ERROR,
                summary=(
                    f"Could not confirm logging in {region}: status unknown for "
                    f"{', '.join(unknown_names)}. Result unknown."
                ),
                evidence=evidence,
                remediation="Grant cloudtrail:GetTrailStatus or retry, then scan again.",
            )
        if covering:
            return RuleResult(
                status=Status.FAIL,
                summary=f"Trails cover {region} but none of them is logging.",
                evidence=evidence,
            )
        return RuleResult(
            status=Status.FAIL,
            summary=f"No CloudTrail trail covers region {region}.",
            evidence=evidence,
        )
