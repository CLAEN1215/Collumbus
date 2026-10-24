from datetime import timedelta

import pytest
from conftest import T0
from pydantic import ValidationError

from collumbus.models import (
    Coverage,
    CoverageGap,
    Finding,
    Scan,
    Source,
    Status,
    make_finding_id,
)
from collumbus.security import REDACTED

# --- Finding -----------------------------------------------------------------


def test_valid_finding_serializes_and_round_trips(finding_data):
    finding = Finding(**finding_data)
    as_json = finding.model_dump_json()
    assert Finding.model_validate_json(as_json) == finding


def test_finding_id_is_stable_and_deterministic(finding_data):
    a = Finding(**finding_data)
    b = Finding(**{**finding_data, "scan_id": "scan-2", "summary": "different text"})
    assert a.finding_id == b.finding_id
    assert a.finding_id == make_finding_id("S3-001", "111122223333", "us-east-1", "demo-bucket")


@pytest.mark.parametrize(
    "field, value",
    [
        ("rule_id", "S3-002"),
        ("account_id", "444455556666"),
        ("region", "eu-west-1"),
        ("resource_id", "other-bucket"),
    ],
)
def test_finding_id_changes_with_identity_fields(finding_data, field, value):
    original = Finding(**finding_data)
    changed = Finding(**{**finding_data, field: value})
    assert original.finding_id != changed.finding_id


def test_finding_id_has_no_separator_ambiguity():
    assert make_finding_id("a|b", "c", "d", "e") != make_finding_id("a", "b|c", "d", "e")


def test_tampered_finding_id_is_rejected(finding_data):
    with pytest.raises(ValidationError, match="finding_id does not match"):
        Finding(**{**finding_data, "finding_id": "0000000000000000"})


@pytest.mark.parametrize(
    "field, value",
    [
        ("severity", "Super Bad"),
        ("status", "Unknown"),
        ("source", "Production"),
        ("account_id", "1234"),
        ("account_id", "abcdabcdabcd"),
        ("rule_id", "s3 rule"),
        ("title", ""),
        ("first_detected", "2025-01-01T12:00:00"),  # no timezone
    ],
)
def test_invalid_field_values_are_rejected(finding_data, field, value):
    with pytest.raises(ValidationError):
        Finding(**{**finding_data, field: value})


def test_missing_required_field_gives_useful_error(finding_data):
    del finding_data["resource_id"]
    with pytest.raises(ValidationError) as exc_info:
        Finding(**finding_data)
    assert "resource_id" in str(exc_info.value)


def test_unknown_field_is_rejected(finding_data):
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Finding(**{**finding_data, "is_secure": True})


def test_non_https_reference_is_rejected(finding_data):
    with pytest.raises(ValidationError, match="https"):
        Finding(**{**finding_data, "references": ["http://example.com"]})


def test_first_detected_after_last_detected_is_rejected(finding_data):
    with pytest.raises(ValidationError, match="first_detected"):
        Finding(**{**finding_data, "first_detected": T0 + timedelta(days=1)})


def test_failed_finding_requires_remediation(finding_data):
    with pytest.raises(ValidationError, match="remediation"):
        Finding(**{**finding_data, "remediation": ""})


def test_passing_finding_may_omit_remediation(finding_data):
    finding = Finding(**{**finding_data, "status": "Pass", "remediation": "", "risk": ""})
    assert finding.status == Status.PASS


def test_finding_is_immutable(finding_data):
    finding = Finding(**finding_data)
    with pytest.raises(ValidationError):
        finding.status = Status.PASS


def test_secrets_in_evidence_are_redacted(finding_data):
    finding_data["evidence"] = {
        "BlockPublicPolicy": False,
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "nested": {"SessionToken": "abc123"},
        "message": "denied for AKIAIOSFODNN7EXAMPLE",
    }
    evidence = Finding(**finding_data).evidence
    assert evidence["BlockPublicPolicy"] is False
    assert evidence["SecretAccessKey"] == REDACTED
    assert evidence["nested"] == {"SessionToken": REDACTED}
    assert "AKIAIOSFODNN7EXAMPLE" not in evidence["message"]


def test_evidence_must_be_json_compatible(finding_data):
    with pytest.raises(ValidationError):
        Finding(**{**finding_data, "evidence": {"obj": object()}})


# --- Scan --------------------------------------------------------------------


def _scan_data(**overrides) -> dict:
    data = {
        "scan_id": "scan-1",
        "source": "Demo",
        "account_id": "111122223333",
        "regions": ["us-east-1"],
        "resource_categories": ["s3"],
        "started_at": T0,
        "finished_at": T0 + timedelta(seconds=5),
        "is_complete": True,
        "findings": [],
    }
    data.update(overrides)
    return data


def test_valid_scan_round_trips(finding_data):
    scan = Scan(**_scan_data(findings=[Finding(**finding_data)]))
    assert Scan.model_validate_json(scan.model_dump_json()) == scan


def test_scan_rejects_mixed_sources(finding_data):
    aws_finding = Finding(**{**finding_data, "source": "AWS"})
    with pytest.raises(ValidationError, match="source does not match"):
        Scan(**_scan_data(findings=[aws_finding]))


def test_scan_rejects_findings_from_other_scan(finding_data):
    other = Finding(**{**finding_data, "scan_id": "scan-99"})
    with pytest.raises(ValidationError, match="different scan"):
        Scan(**_scan_data(findings=[other]))


def test_scan_rejects_findings_from_other_account(finding_data):
    other = Finding(**{**finding_data, "account_id": "444455556666"})
    with pytest.raises(ValidationError, match="account does not match"):
        Scan(**_scan_data(findings=[other]))


def test_scan_with_gaps_cannot_be_complete():
    gap = CoverageGap(
        category="s3",
        region="us-east-1",
        reason="AccessDenied",
        missing_permission="s3:GetEncryptionConfiguration",
    )
    with pytest.raises(ValidationError, match="cannot be complete"):
        Scan(**_scan_data(coverage=Coverage(gaps=[gap])))
    scan = Scan(**_scan_data(coverage=Coverage(gaps=[gap]), is_complete=False))
    assert scan.coverage.gaps[0].missing_permission == "s3:GetEncryptionConfiguration"


def test_scan_with_error_finding_cannot_be_complete(finding_data):
    error_finding = Finding(**{**finding_data, "status": "Error"})
    with pytest.raises(ValidationError, match="cannot be complete"):
        Scan(**_scan_data(findings=[error_finding]))


def test_scan_end_before_start_is_rejected():
    with pytest.raises(ValidationError, match="started_at"):
        Scan(**_scan_data(finished_at=T0 - timedelta(seconds=1)))


def test_scan_requires_at_least_one_region():
    with pytest.raises(ValidationError):
        Scan(**_scan_data(regions=[]))


def test_source_enum_values():
    assert {s.value for s in Source} == {"Demo", "AWS"}
