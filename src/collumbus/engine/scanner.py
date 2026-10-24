"""Run every rule against every resource and build a validated Scan.

Responsibilities:
  * call each applicable rule once per resource,
  * turn unexpected rule crashes into Error findings (one bad rule cannot stop the scan),
  * turn collection gaps into SYS-001 Error findings and coverage records,
  * mark the scan incomplete whenever anything could not be inspected.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime

from collumbus.collectors.base import Collector, Resource
from collumbus.config import AppConfig
from collumbus.engine.severity import assign_severity
from collumbus.models import Coverage, CoverageGap, Finding, Scan, Severity, Status, new_scan_id
from collumbus.rules import Rule, RuleResult, build_rules

logger = logging.getLogger(__name__)

SYS_RULE_ID = "SYS-001"
SYS_REFERENCES = [
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html",
]


def _now() -> datetime:
    return datetime.now(UTC)


def run_scan(
    collector: Collector,
    config: AppConfig,
    rules: list[Rule] | None = None,
    clock: Callable[[], datetime] = _now,
    scan_id: str | None = None,
) -> Scan:
    """Collect, evaluate, and return a validated Scan. Never modifies any resource."""
    started_at = clock()
    scan_id = scan_id or new_scan_id()
    collection = collector.collect()
    if rules is None:
        rules = build_rules(config)

    def make_finding(rule: Rule, resource: Resource, result: RuleResult) -> Finding:
        detected = clock()
        return Finding(
            rule_id=rule.rule_id,
            title=rule.title,
            severity=assign_severity(rule, result.status, config),
            status=result.status,
            resource_type=resource.resource_type,
            resource_id=resource.resource_id,
            region=resource.region,
            account_id=collection.account_id,
            summary=result.summary,
            evidence=result.evidence,
            risk=rule.risk if result.status in (Status.FAIL, Status.ERROR) else "",
            remediation=result.remediation or rule.remediation,
            references=rule.references,
            # No history exists yet, so first_detected is this scan. Phase 4 adds history.
            first_detected=detected,
            last_detected=detected,
            scan_id=scan_id,
            source=collection.source,
        )

    findings: list[Finding] = []
    for resource in collection.resources:
        for rule in rules:
            if not rule.applies_to(resource):
                continue
            try:
                result = rule.evaluate(resource)
                if not isinstance(result, RuleResult):
                    raise TypeError(f"rule returned {type(result).__name__}, not RuleResult")
            except Exception as exc:
                # Log full details locally; keep the finding free of internals.
                logger.exception("Rule %s crashed on %s", rule.rule_id, resource.resource_id)
                result = RuleResult(
                    status=Status.ERROR,
                    summary="Internal error while evaluating this rule. Result unknown.",
                    evidence={"error_type": type(exc).__name__},
                    remediation="This is a Collumbus bug. Check the logs, then report it.",
                )
            findings.append(make_finding(rule, resource, result))

    # Coverage gaps: whole areas that could not be listed, plus per-attribute fetch errors.
    gaps = list(collection.gaps)
    for resource in collection.resources:
        for err in resource.fetch_errors:
            gaps.append(
                CoverageGap(
                    category=resource.category,
                    region=resource.region,
                    resource_id=resource.resource_id,
                    reason=err.code,
                    missing_permission=err.permission,
                    detail=f"Could not read {err.attribute}",
                )
            )
    # Resource-level errors already have their own Error findings from the rules.
    # Area-level gaps get a SYS-001 finding so they appear in the findings list too.
    for gap in collection.gaps:
        findings.append(_gap_finding(gap, collection.account_id, collection.source, scan_id, clock))

    findings.sort(key=lambda f: (f.rule_id, f.region, f.resource_type, f.resource_id))
    ids = [f.finding_id for f in findings]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate finding IDs; a rule ran twice on the same resource")

    has_errors = any(f.status == Status.ERROR for f in findings)
    return Scan(
        scan_id=scan_id,
        source=collection.source,
        account_id=collection.account_id,
        regions=collection.regions,
        resource_categories=collection.resource_categories,
        started_at=started_at,
        finished_at=clock(),
        coverage=Coverage(
            inspected_categories=sorted({r.category for r in collection.resources}),
            resources_inspected=len(collection.resources),
            gaps=gaps,
        ),
        is_complete=not gaps and not has_errors,
        findings=findings,
    )


def _gap_finding(gap, account_id, source, scan_id, clock) -> Finding:
    detected = clock()
    target = gap.missing_permission or gap.reason
    if gap.missing_permission:
        remediation = f"Grant the scanning identity {gap.missing_permission}, then scan again."
    else:
        remediation = "This may be temporary. Scan again later."
    return Finding(
        rule_id=SYS_RULE_ID,
        title="Configuration could not be inspected",
        severity=Severity.INFORMATIONAL,
        status=Status.ERROR,
        resource_type="Collumbus::CoverageGap",
        resource_id=f"{gap.category}:{gap.resource_id or '*'}:{target}",
        region=gap.region,
        account_id=account_id,
        summary=(
            f"{gap.detail or 'Part of ' + gap.category} could not be inspected ({gap.reason}). "
            "Resources here were not checked; this is not a pass."
        ),
        evidence={
            "category": gap.category,
            "reason": gap.reason,
            "missing_permission": gap.missing_permission,
        },
        risk="Misconfigurations in the uninspected area would not be reported.",
        remediation=remediation,
        references=SYS_REFERENCES,
        first_detected=detected,
        last_detected=detected,
        scan_id=scan_id,
        source=source,
    )
