import csv
import io

import pytest

from collumbus.collectors import DemoCollector
from collumbus.config import load_config
from collumbus.engine import run_scan
from collumbus.models import Finding, Severity, Status
from collumbus.reporting import (
    FINDING_CSV_COLUMNS,
    ReportError,
    export_csv,
    export_json,
    read_json_report,
    sanitize_csv_cell,
    write_csv_report,
    write_json_report,
)


@pytest.fixture
def demo_scan():
    config = load_config()
    return run_scan(DemoCollector(), config)


# --- JSON Reporting Tests ---


def test_json_export_and_read_roundtrip(demo_scan, tmp_path):
    json_path = tmp_path / "scan.json"
    written_path = write_json_report(demo_scan, json_path)
    assert written_path == json_path
    assert json_path.exists()

    loaded_scan = read_json_report(json_path)
    assert loaded_scan == demo_scan
    assert loaded_scan.scan_id == demo_scan.scan_id
    assert len(loaded_scan.findings) == len(demo_scan.findings)
    assert loaded_scan.is_complete == demo_scan.is_complete


def test_json_export_string(demo_scan):
    content = export_json(demo_scan)
    assert demo_scan.scan_id in content
    assert "111122223333" in content


def test_write_json_report_creates_parent_directories(demo_scan, tmp_path):
    nested_path = tmp_path / "sub" / "folder" / "report.json"
    write_json_report(demo_scan, nested_path)
    assert nested_path.exists()


def test_read_json_report_missing_file_raises_report_error(tmp_path):
    missing = tmp_path / "nonexistent.json"
    with pytest.raises(ReportError, match="cannot read JSON report"):
        read_json_report(missing)


def test_read_json_report_invalid_json_syntax(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not: valid: json", encoding="utf-8")
    with pytest.raises(ReportError, match="is invalid: .* Invalid JSON"):
        read_json_report(bad_json)


def test_read_json_report_invalid_schema(tmp_path):
    invalid_schema = tmp_path / "invalid_schema.json"
    invalid_schema.write_text('{"scan_id": "123", "unknown_field": true}', encoding="utf-8")
    with pytest.raises(ReportError, match="JSON report at .* is invalid"):
        read_json_report(invalid_schema)


def test_write_json_report_io_error_raises_report_error(demo_scan, tmp_path):
    dir_path = tmp_path / "directory"
    dir_path.mkdir()
    # Attempting to write a file where a directory already exists
    with pytest.raises(ReportError, match="cannot write JSON report"):
        write_json_report(demo_scan, dir_path)


# --- CSV Reporting Tests ---


def test_csv_export_headers_and_row_count(demo_scan):
    csv_text = export_csv(demo_scan)
    reader = csv.DictReader(io.StringIO(csv_text))

    assert reader.fieldnames == FINDING_CSV_COLUMNS
    rows = list(reader)
    assert len(rows) == len(demo_scan.findings)


def test_csv_export_sorting_order(demo_scan):
    csv_text = export_csv(demo_scan)
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)

    statuses = [r["status"] for r in rows]
    # Check that all Fails come before Errors, which come before Passes
    fail_indices = [i for i, s in enumerate(statuses) if s == "Fail"]
    error_indices = [i for i, s in enumerate(statuses) if s == "Error"]
    pass_indices = [i for i, s in enumerate(statuses) if s == "Pass"]

    assert max(fail_indices) < min(error_indices)
    assert max(error_indices) < min(pass_indices)


def test_csv_export_failures_only(demo_scan):
    csv_text = export_csv(demo_scan, failures_only=True)
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)

    assert len(rows) > 0
    assert all(r["status"] in ("Fail", "Error") for r in rows)
    assert not any(r["status"] == "Pass" for r in rows)


def test_sanitize_csv_cell():
    assert sanitize_csv_cell(None) == ""
    assert sanitize_csv_cell("normal text") == "normal text"
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd") == "'+cmd"
    assert sanitize_csv_cell("-minus") == "'-minus"
    assert sanitize_csv_cell("@lookup") == "'@lookup"
    assert sanitize_csv_cell("\ttab") == "'\ttab"
    assert sanitize_csv_cell("\rcarriage") == "'\rcarriage"


def test_csv_export_sanitizes_dangerous_formulas(demo_scan):
    # Create a mock finding with a potentially dangerous summary
    # Omitting finding_id lets the model compute the valid hash for -calc-resource
    malicious_finding = Finding(
        rule_id=demo_scan.findings[0].rule_id,
        title=demo_scan.findings[0].title,
        severity=Severity.HIGH,
        status=Status.FAIL,
        resource_type="AWS::S3::Bucket",
        resource_id="-calc-resource",
        region=demo_scan.findings[0].region,
        account_id=demo_scan.findings[0].account_id,
        summary="=cmd|'/C calc'!A0",
        evidence={},
        risk="Dangerous formula injection",
        remediation="Fix it immediately",
        references=[],
        first_detected=demo_scan.findings[0].first_detected,
        last_detected=demo_scan.findings[0].last_detected,
        scan_id=demo_scan.scan_id,
        source=demo_scan.source,
    )

    scan_with_malicious = demo_scan.model_copy(update={"findings": [malicious_finding]})

    # Default sanitize=True
    sanitized_csv = export_csv(scan_with_malicious, sanitize=True)
    reader = csv.DictReader(io.StringIO(sanitized_csv))
    row = next(reader)
    assert row["summary"] == "'=cmd|'/C calc'!A0"
    assert row["resource_id"] == "'-calc-resource"

    # Explicit sanitize=False leaves triggers untouched
    raw_csv = export_csv(scan_with_malicious, sanitize=False)
    reader_raw = csv.DictReader(io.StringIO(raw_csv))
    row_raw = next(reader_raw)
    assert row_raw["summary"] == "=cmd|'/C calc'!A0"
    assert row_raw["resource_id"] == "-calc-resource"


def test_write_csv_report_creates_directories_and_writes(demo_scan, tmp_path):
    nested_csv = tmp_path / "reports" / "findings.csv"
    written_path = write_csv_report(demo_scan, nested_csv)
    assert written_path == nested_csv
    assert nested_csv.exists()

    with nested_csv.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert len(list(reader)) == len(demo_scan.findings)


def test_write_csv_report_io_error_raises_report_error(demo_scan, tmp_path):
    dir_path = tmp_path / "directory"
    dir_path.mkdir()
    with pytest.raises(ReportError, match="cannot write CSV report"):
        write_csv_report(demo_scan, dir_path)
