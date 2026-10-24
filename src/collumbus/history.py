"""Scan history storage, correlation, and diffing for Collumbus.

Phase 4 adds scan history so that:
  * Scans can be persisted and viewed over time in the dashboard,
  * Findings track when they were first detected across consecutive audits,
  * Consecutive scans can be compared (new vs. resolved vs. recurring findings).
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from collumbus.models import Finding, Scan
from collumbus.reporting.json_report import ReportError, read_json_report, write_json_report

DEFAULT_HISTORY_DIR = Path(__file__).resolve().parents[2] / "data" / "history"


@dataclass(frozen=True)
class ScanDiff:
    """Comparison between a baseline scan and a newer scan."""

    baseline_id: str
    current_id: str
    new_findings: list[Finding]
    resolved_findings: list[Finding]
    recurring_findings: list[Finding]


def save_scan_to_history(scan: Scan, history_dir: Path = DEFAULT_HISTORY_DIR) -> Path:
    """Save a scan report to the history directory.

    Files are named using UTC timestamp and scan ID prefix for predictable sorting:
    e.g. '20261024_051521_baad9379.json'
    """
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = scan.started_at.strftime("%Y%m%d_%H%M%S")
    filename = f"{stamp}_{scan.scan_id[:8]}.json"
    file_path = history_dir / filename
    write_json_report(scan, file_path)
    return file_path


def list_historical_scans(history_dir: Path = DEFAULT_HISTORY_DIR) -> list[Scan]:
    """Load and validate all historical scans from disk, sorted newest first."""
    if not history_dir.exists():
        return []

    scans: list[Scan] = []
    # Sort files by name (which starts with timestamp)
    for path in sorted(history_dir.glob("*.json"), reverse=True):
        try:
            scans.append(read_json_report(path))
        except ReportError:
            # Skip corrupted or non-scan JSON files rather than crashing history view
            continue
    # Ensure sorted by started_at descending
    scans.sort(key=lambda s: s.started_at, reverse=True)
    return scans


def get_scan_by_id(scan_id: str, history_dir: Path = DEFAULT_HISTORY_DIR) -> Scan | None:
    """Retrieve a scan by its exact scan_id or leading prefix."""
    for scan in list_historical_scans(history_dir):
        if scan.scan_id == scan_id or scan.scan_id.startswith(scan_id):
            return scan
    return None


def correlate_scan_with_history(current_scan: Scan, history: list[Scan]) -> Scan:
    """Update `first_detected` timestamps on findings based on historical records.

    Finds the earliest previous scan for the same account and source that reported
    each finding_id, preserving the true age of recurring issues.
    """
    if not history:
        return current_scan

    # Build index of earliest first_detected per finding_id in compatible scans
    earliest_seen: dict[str, datetime] = {}
    for past_scan in history:
        if (
            past_scan.account_id != current_scan.account_id
            or past_scan.source != current_scan.source
        ):
            continue
        for f in past_scan.findings:
            current_earliest = earliest_seen.get(f.finding_id)
            if current_earliest is None or f.first_detected < current_earliest:
                earliest_seen[f.finding_id] = f.first_detected

    if not earliest_seen:
        return current_scan

    updated_findings: list[Finding] = []
    for f in current_scan.findings:
        if f.finding_id in earliest_seen:
            historical_first = earliest_seen[f.finding_id]
            if historical_first < f.first_detected:
                # Use model_copy because Finding is frozen
                f = f.model_copy(update={"first_detected": historical_first})
        updated_findings.append(f)

    return current_scan.model_copy(update={"findings": updated_findings})


def compare_scans(baseline: Scan, current: Scan) -> ScanDiff:
    """Diff two scans to identify new, resolved, and recurring findings.

    Only scans with matching account_id and source can be diffed.
    """
    if baseline.account_id != current.account_id:
        raise ValueError("cannot compare scans from different AWS accounts")
    if baseline.source != current.source:
        raise ValueError("cannot compare demo scan with AWS scan")

    baseline_map = {f.finding_id: f for f in baseline.findings}
    current_map = {f.finding_id: f for f in current.findings}

    recurring_ids = set(baseline_map) & set(current_map)
    new_ids = set(current_map) - set(baseline_map)
    resolved_ids = set(baseline_map) - set(current_map)

    return ScanDiff(
        baseline_id=baseline.scan_id,
        current_id=current.scan_id,
        new_findings=[current_map[fid] for fid in sorted(new_ids)],
        resolved_findings=[baseline_map[fid] for fid in sorted(resolved_ids)],
        recurring_findings=[current_map[fid] for fid in sorted(recurring_ids)],
    )
