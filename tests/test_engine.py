from datetime import UTC, datetime

import pytest

from collumbus.collectors.base import (
    S3_BUCKET,
    CollectionResult,
    Collector,
    FetchError,
    Resource,
)
from collumbus.config import AppConfig, RuleSettings, S3EncryptionSettings
from collumbus.engine.scanner import SYS_RULE_ID, run_scan
from collumbus.engine.severity import assign_severity
from collumbus.models import CoverageGap, Severity, Source, Status
from collumbus.rules.base import Rule, RuleResult


def make_config(rules: dict[str, RuleSettings] | None = None) -> AppConfig:
    return AppConfig(
        rules=rules or {},
        s3_encryption=S3EncryptionSettings(approved_algorithms=["AES256"]),
    )


class DummyRule(Rule):
    rule_id = "S3-001"
    title = "Dummy S3 Rule"
    resource_types = frozenset({S3_BUCKET})
    default_severity = Severity.HIGH
    risk = "Dummy risk"
    remediation = "Fix it"
    references = ["https://example.com/dummy"]

    def __init__(self, verdict: Status = Status.PASS):
        super().__init__()
        self.verdict = verdict

    def evaluate(self, resource: Resource) -> RuleResult:
        return RuleResult(status=self.verdict, summary="Evaluated dummy")


class CrashingRule(Rule):
    rule_id = "S3-002"
    title = "Crashing Rule"
    resource_types = frozenset({S3_BUCKET})
    default_severity = Severity.MEDIUM
    risk = "Crash risk"
    remediation = "Report bug"
    references = ["https://example.com/crash"]

    def evaluate(self, resource: Resource) -> RuleResult:
        raise RuntimeError("Rule crash simulation")


class BadReturnRule(Rule):
    rule_id = "S3-002"
    title = "Bad Return Rule"
    resource_types = frozenset({S3_BUCKET})
    default_severity = Severity.MEDIUM
    risk = "Bad return"
    remediation = "Fix bug"
    references = ["https://example.com/bad"]

    def evaluate(self, resource: Resource) -> RuleResult:
        return "not a RuleResult"  # type: ignore


class SimpleCollector(Collector):
    def __init__(
        self,
        resources: list[Resource] | None = None,
        gaps: list[CoverageGap] | None = None,
    ):
        self.resources = resources or []
        self.gaps = gaps or []

    def collect(self) -> CollectionResult:
        return CollectionResult(
            source=Source.DEMO,
            account_id="123456789012",
            regions=["us-east-1"],
            resource_categories=["s3"],
            resources=self.resources,
            gaps=self.gaps,
        )


def test_assign_severity():
    rule = DummyRule()
    cfg = make_config(rules={"S3-001": RuleSettings(enabled=True, severity=Severity.LOW)})

    # Non-fail is always Informational
    assert assign_severity(rule, Status.PASS, cfg) == Severity.INFORMATIONAL
    assert assign_severity(rule, Status.ERROR, cfg) == Severity.INFORMATIONAL
    assert assign_severity(rule, Status.NOT_APPLICABLE, cfg) == Severity.INFORMATIONAL

    # Fail uses config
    assert assign_severity(rule, Status.FAIL, cfg) == Severity.LOW

    # Fail uses default if not in config
    empty_cfg = make_config(rules={})
    assert assign_severity(rule, Status.FAIL, empty_cfg) == Severity.HIGH
    assert assign_severity(rule, Status.FAIL, None) == Severity.HIGH


def test_run_scan_complete_when_clean():
    t0 = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="clean-bucket",
        region="us-east-1",
        category="s3",
    )
    collector = SimpleCollector(resources=[res])
    scan = run_scan(
        collector=collector,
        config=make_config(),
        rules=[DummyRule(Status.PASS)],
        clock=lambda: t0,
        scan_id="test-scan-id",
    )

    assert scan.scan_id == "test-scan-id"
    assert scan.started_at == t0
    assert scan.finished_at == t0
    assert scan.is_complete is True
    assert len(scan.findings) == 1
    assert scan.findings[0].status == Status.PASS
    assert scan.coverage.resources_inspected == 1
    assert len(scan.coverage.gaps) == 0


def test_run_scan_rule_crash_becomes_error():
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
    )
    collector = SimpleCollector(resources=[res])
    scan = run_scan(
        collector=collector,
        config=make_config(),
        rules=[CrashingRule()],
    )

    assert scan.is_complete is False
    assert len(scan.findings) == 1
    f = scan.findings[0]
    assert f.status == Status.ERROR
    assert "Internal error" in f.summary
    assert f.evidence.get("error_type") == "RuntimeError"


def test_run_scan_rule_bad_return_becomes_error():
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
    )
    collector = SimpleCollector(resources=[res])
    scan = run_scan(
        collector=collector,
        config=make_config(),
        rules=[BadReturnRule()],
    )

    assert scan.is_complete is False
    assert len(scan.findings) == 1
    f = scan.findings[0]
    assert f.status == Status.ERROR
    assert "Internal error" in f.summary
    assert f.evidence.get("error_type") == "TypeError"


def test_run_scan_gaps_and_fetch_errors():
    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
        fetch_errors=[
            FetchError(
                attribute="encryption",
                code="Throttling",
                permission="s3:GetEncryption",
            )
        ],
    )
    gap = CoverageGap(
        category="iam",
        region="global",
        reason="AccessDenied",
        missing_permission="iam:ListRoles",
        detail="IAM roles list",
    )
    collector = SimpleCollector(resources=[res], gaps=[gap])
    scan = run_scan(
        collector=collector,
        config=make_config(),
        rules=[DummyRule(Status.PASS)],
    )

    assert scan.is_complete is False
    # Check coverage gaps: 1 from collection gap, 1 from resource fetch_errors
    assert len(scan.coverage.gaps) == 2
    # Check findings: 1 from DummyRule + 1 SYS-001 finding for the area gap
    assert len(scan.findings) == 2
    sys_finding = [f for f in scan.findings if f.rule_id == SYS_RULE_ID][0]
    assert sys_finding.status == Status.ERROR
    assert "IAM roles list could not be inspected" in sys_finding.summary
    assert "Grant the scanning identity iam:ListRoles" in sys_finding.remediation


def test_run_scan_gap_without_missing_permission():
    gap = CoverageGap(
        category="s3",
        region="us-east-1",
        reason="Throttling",
        detail="Rate exceeded",
    )
    collector = SimpleCollector(resources=[], gaps=[gap])
    scan = run_scan(collector=collector, config=make_config())
    assert scan.findings[0].remediation == "This may be temporary. Scan again later."


def test_run_scan_duplicate_finding_id_check():
    # If two rules have the same rule_id and run on the same resource
    class DupRule(DummyRule):
        pass

    res = Resource(
        resource_type=S3_BUCKET,
        resource_id="b1",
        region="us-east-1",
        category="s3",
    )
    collector = SimpleCollector(resources=[res])
    with pytest.raises(RuntimeError, match="duplicate finding IDs"):
        run_scan(
            collector=collector,
            config=make_config(),
            rules=[DummyRule(), DupRule()],
        )
