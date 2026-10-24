from datetime import UTC, datetime

import pytest

from collumbus.collectors import DemoCollector
from collumbus.config import load_config
from collumbus.engine import run_scan
from collumbus.history import (
    compare_scans,
    correlate_scan_with_history,
    get_scan_by_id,
    list_historical_scans,
    save_scan_to_history,
)
from collumbus.models import Source


@pytest.fixture
def base_scan():
    config = load_config()
    return run_scan(DemoCollector(), config)


def test_save_and_list_history(base_scan, tmp_path):
    assert list_historical_scans(tmp_path) == []

    file_path = save_scan_to_history(base_scan, tmp_path)
    assert file_path.exists()
    assert base_scan.scan_id[:8] in file_path.name

    history = list_historical_scans(tmp_path)
    assert len(history) == 1
    assert history[0].scan_id == base_scan.scan_id


def test_list_history_ordering_and_corrupt_files(base_scan, tmp_path):
    t1 = datetime(2025, 1, 1, 10, 0, tzinfo=UTC)
    t2 = datetime(2025, 1, 2, 10, 0, tzinfo=UTC)

    scan1 = base_scan.model_copy(
        update={
            "scan_id": "scan0001",
            "started_at": t1,
            "finished_at": t1,
            "findings": [f.model_copy(update={"scan_id": "scan0001"}) for f in base_scan.findings],
        }
    )
    scan2 = base_scan.model_copy(
        update={
            "scan_id": "scan0002",
            "started_at": t2,
            "finished_at": t2,
            "findings": [f.model_copy(update={"scan_id": "scan0002"}) for f in base_scan.findings],
        }
    )

    save_scan_to_history(scan1, tmp_path)
    save_scan_to_history(scan2, tmp_path)

    # Put a corrupted JSON file in history directory
    bad_file = tmp_path / "corrupted.json"
    bad_file.write_text("{corrupt json", encoding="utf-8")

    scans = list_historical_scans(tmp_path)
    assert len(scans) == 2
    # Verify newest first (scan2 before scan1)
    assert scans[0].scan_id == "scan0002"
    assert scans[1].scan_id == "scan0001"


def test_get_scan_by_id(base_scan, tmp_path):
    save_scan_to_history(base_scan, tmp_path)

    found = get_scan_by_id(base_scan.scan_id, tmp_path)
    assert found is not None
    assert found.scan_id == base_scan.scan_id

    # Test prefix matching
    found_prefix = get_scan_by_id(base_scan.scan_id[:6], tmp_path)
    assert found_prefix is not None
    assert found_prefix.scan_id == base_scan.scan_id

    # Nonexistent
    assert get_scan_by_id("nonexistent-id", tmp_path) is None


def test_correlate_scan_with_history(base_scan):
    t_past = datetime(2024, 6, 1, 12, 0, tzinfo=UTC)
    t_now = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)

    # Past scan with earlier first_detected for the first finding
    target_id = base_scan.findings[0].finding_id
    past_finding = base_scan.findings[0].model_copy(
        update={"first_detected": t_past, "last_detected": t_past}
    )
    past_scan = base_scan.model_copy(
        update={
            "scan_id": "past-scan",
            "started_at": t_past,
            "finished_at": t_past,
            "findings": [past_finding],
        }
    )

    # Current scan with newer timestamps
    current_finding = base_scan.findings[0].model_copy(
        update={"first_detected": t_now, "last_detected": t_now}
    )
    current_scan = base_scan.model_copy(
        update={
            "scan_id": "curr-scan",
            "started_at": t_now,
            "finished_at": t_now,
            "findings": [current_finding],
        }
    )

    correlated = correlate_scan_with_history(current_scan, [past_scan])
    assert correlated.findings[0].finding_id == target_id
    assert correlated.findings[0].first_detected == t_past
    assert correlated.findings[0].last_detected == t_now


def test_correlate_scan_ignores_incompatible_accounts_or_sources(base_scan):
    t_past = datetime(2024, 6, 1, 12, 0, tzinfo=UTC)
    t_now = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)

    diff_account_finding = base_scan.findings[0].model_copy(
        update={"account_id": "999999999999", "first_detected": t_past}
    )
    diff_account_scan = base_scan.model_copy(
        update={"account_id": "999999999999", "findings": [diff_account_finding]}
    )

    diff_source_finding = base_scan.findings[0].model_copy(
        update={"source": Source.AWS, "first_detected": t_past}
    )
    diff_source_scan = base_scan.model_copy(
        update={"source": Source.AWS, "findings": [diff_source_finding]}
    )

    current_finding = base_scan.findings[0].model_copy(update={"first_detected": t_now})
    current_scan = base_scan.model_copy(update={"findings": [current_finding]})

    # Neither diff_account nor diff_source should alter first_detected
    result = correlate_scan_with_history(current_scan, [diff_account_scan, diff_source_scan])
    assert result.findings[0].first_detected == t_now


def test_compare_scans(base_scan):
    f1 = base_scan.findings[0]
    f2 = base_scan.findings[1]
    f3 = base_scan.findings[2]

    # Baseline has f1 and f2
    scan_baseline = base_scan.model_copy(update={"scan_id": "scan-base", "findings": [f1, f2]})
    # Current has f2 and f3
    scan_current = base_scan.model_copy(update={"scan_id": "scan-curr", "findings": [f2, f3]})

    diff = compare_scans(scan_baseline, scan_current)
    assert diff.baseline_id == "scan-base"
    assert diff.current_id == "scan-curr"
    assert [f.finding_id for f in diff.recurring_findings] == [f2.finding_id]
    assert [f.finding_id for f in diff.new_findings] == [f3.finding_id]
    assert [f.finding_id for f in diff.resolved_findings] == [f1.finding_id]


def test_compare_scans_rejects_mismatched_account_or_source(base_scan):
    scan_aws = base_scan.model_copy(
        update={
            "source": Source.AWS,
            "findings": [f.model_copy(update={"source": Source.AWS}) for f in base_scan.findings],
        }
    )
    with pytest.raises(ValueError, match="cannot compare demo scan with AWS scan"):
        compare_scans(base_scan, scan_aws)

    scan_other_acc = base_scan.model_copy(
        update={
            "account_id": "888888888888",
            "findings": [
                f.model_copy(update={"account_id": "888888888888"}) for f in base_scan.findings
            ],
        }
    )
    with pytest.raises(ValueError, match="cannot compare scans from different AWS accounts"):
        compare_scans(base_scan, scan_other_acc)
