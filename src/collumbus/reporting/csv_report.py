"""CSV report generation for Collumbus scans."""

import csv
import io
import json
from pathlib import Path
from typing import Any

from collumbus.models import Finding, Scan, Severity, Status
from collumbus.reporting.json_report import ReportError

FINDING_CSV_COLUMNS = [
    "finding_id",
    "rule_id",
    "title",
    "severity",
    "status",
    "source",
    "account_id",
    "region",
    "resource_type",
    "resource_id",
    "summary",
    "risk",
    "remediation",
    "references",
    "evidence",
    "first_detected",
    "last_detected",
    "scan_id",
]

# Order for sorting findings: highest-priority issues appear at the top of the spreadsheet
STATUS_ORDER = [Status.FAIL, Status.ERROR, Status.PASS, Status.NOT_APPLICABLE]
SEVERITY_ORDER = list(reversed(Severity))

# Characters that spreadsheet programs (Excel, Calc) treat as formula triggers
FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> str:
    """Neutralize formula injection by prefixing formula triggers with a single quote."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in FORMULA_TRIGGERS:
        return f"'{text}"
    return text


def _finding_to_row(finding: Finding, sanitize: bool) -> dict[str, str]:
    """Convert a Finding model into a flat dictionary of strings for CSV output."""
    raw = {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "source": finding.source.value,
        "account_id": finding.account_id,
        "region": finding.region,
        "resource_type": finding.resource_type,
        "resource_id": finding.resource_id,
        "summary": finding.summary,
        "risk": finding.risk,
        "remediation": finding.remediation,
        "references": " ".join(finding.references),
        "evidence": json.dumps(finding.evidence, sort_keys=True) if finding.evidence else "",
        "first_detected": finding.first_detected.isoformat(),
        "last_detected": finding.last_detected.isoformat(),
        "scan_id": finding.scan_id,
    }
    if sanitize:
        return {k: sanitize_csv_cell(v) for k, v in raw.items()}
    return raw


def export_csv(scan: Scan, failures_only: bool = False, sanitize: bool = True) -> str:
    """Render findings as a CSV string.

    Findings are ordered with High/Critical Failures first, followed by Errors,
    Passes, and Not Applicable, making the most critical action items immediate
    when opened in spreadsheet software.
    """
    findings = scan.findings
    if failures_only:
        findings = [f for f in findings if f.status in (Status.FAIL, Status.ERROR)]

    ordered = sorted(
        findings,
        key=lambda f: (
            STATUS_ORDER.index(f.status),
            SEVERITY_ORDER.index(f.severity),
            f.rule_id,
            f.resource_id,
        ),
    )

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FINDING_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for f in ordered:
        writer.writerow(_finding_to_row(f, sanitize=sanitize))

    return output.getvalue()


def write_csv_report(
    scan: Scan, path: Path, failures_only: bool = False, sanitize: bool = True
) -> Path:
    """Write scan findings to a CSV file. Creates parent directories if needed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = export_csv(scan, failures_only=failures_only, sanitize=sanitize)
        path.write_text(content, encoding="utf-8")
        return path
    except OSError as exc:
        raise ReportError(f"cannot write CSV report to {path}: {exc.strerror}") from exc
