"""Command-line entry point: `collumbus ...` or `python -m collumbus ...`.

Commands:
  validate-config   check config/rules.yaml
  sample-finding    print one SIMULATED finding as JSON (proves the model works)
  demo-scan         scan the fictional demo dataset and print the results
"""

import argparse
import logging
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from collumbus import __version__
from collumbus.collectors import DemoCollector, DemoDataError
from collumbus.collectors.demo import DEFAULT_DEMO_PATH
from collumbus.config import DEFAULT_CONFIG_PATH, ConfigError, load_config
from collumbus.engine import run_scan
from collumbus.logging_setup import setup_logging
from collumbus.models import Finding, Scan, Severity, Source, Status
from collumbus.reporting import (
    ReportError,
    export_csv,
    read_json_report,
    write_csv_report,
    write_json_report,
)

SIMULATED_BANNER = "SIMULATED DATA: fictional demo finding, not a real AWS result."
SIMULATED_SCAN_BANNER = "SIMULATED DATA: fictional demo resources, not a real AWS account."

STATUS_ORDER = [Status.FAIL, Status.ERROR, Status.PASS, Status.NOT_APPLICABLE]
SEVERITY_ORDER = list(reversed(Severity))  # Critical first


def build_sample_finding() -> Finding:
    """A fixed, fictional finding used to demonstrate the data model."""
    detected = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)
    return Finding(
        rule_id="S3-001",
        title="S3 bucket Public Access Block is incomplete",
        severity=Severity.HIGH,
        status=Status.FAIL,
        resource_type="AWS::S3::Bucket",
        resource_id="demo-marketing-assets",
        region="us-east-1",
        account_id="111122223333",  # AWS's documented example account number
        summary="BlockPublicPolicy is disabled for this bucket.",
        evidence={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
        risk="A bucket policy could be added that grants public access.",
        remediation="Enable all four S3 Block Public Access settings on the bucket.",
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
        ],
        first_detected=detected,
        last_detected=detected,
        scan_id="demo-sample",
        source=Source.DEMO,
    )


def _cmd_validate_config(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    enabled = [rule_id for rule_id, s in config.rules.items() if s.enabled]
    print(f"Config OK: {args.config}")
    print(f"Enabled rules: {', '.join(enabled) or '(none)'}")
    print(f"Approved S3 encryption: {', '.join(config.s3_encryption.approved_algorithms)}")
    return 0


def _cmd_sample_finding(args: argparse.Namespace) -> int:
    print(SIMULATED_BANNER, file=sys.stderr)
    print(build_sample_finding().model_dump_json(indent=2))
    return 0


def format_scan_summary(scan: Scan) -> str:
    """Human-readable scan summary. One finding = one rule's verdict on one resource."""
    counts = Counter(f.status for f in scan.findings)
    lines = [
        f"Scan {scan.scan_id}  source={scan.source}  account={scan.account_id}",
        f"Regions: {', '.join(scan.regions)}   Categories: {', '.join(scan.resource_categories)}",
        f"Resources inspected: {scan.coverage.resources_inspected}   "
        f"Findings: {len(scan.findings)}   "
        + "   ".join(f"{s}: {counts.get(s, 0)}" for s in STATUS_ORDER),
        f"Complete: {'yes' if scan.is_complete else 'NO (see coverage gaps and Error findings)'}",
        "",
    ]
    ordered = sorted(
        scan.findings,
        key=lambda f: (
            STATUS_ORDER.index(f.status),
            SEVERITY_ORDER.index(f.severity),
            f.rule_id,
            f.resource_id,
        ),
    )
    for f in ordered:
        lines.append(
            f"[{f.status:<5}] {f.severity:<13} {f.rule_id:<8} {f.region:<10} {f.resource_id}"
        )
        lines.append(f"        {f.summary}")
    if scan.coverage.gaps:
        lines += ["", "Coverage gaps (not inspected, NOT passes):"]
        for g in scan.coverage.gaps:
            perm = f", needs {g.missing_permission}" if g.missing_permission else ""
            lines.append(
                f"  - {g.category}/{g.region}/{g.resource_id or '*'}: "
                f"{g.detail or 'not inspected'} ({g.reason}{perm})"
            )
    return "\n".join(lines)


def _cmd_demo_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    scan = run_scan(DemoCollector(args.data), config)
    print(SIMULATED_SCAN_BANNER)
    print(format_scan_summary(scan))
    if args.json:
        write_json_report(scan, args.json)
        print(f"Wrote JSON report to {args.json}")
    if args.csv:
        write_csv_report(scan, args.csv, failures_only=args.failures_only)
        print(f"Wrote CSV report to {args.csv}")
    return 0


def _cmd_export_csv(args: argparse.Namespace) -> int:
    scan = read_json_report(args.scan_json)
    if args.output:
        write_csv_report(scan, args.output, failures_only=args.failures_only)
        print(f"Wrote CSV report to {args.output}")
    else:
        print(export_csv(scan, failures_only=args.failures_only), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="collumbus",
        description="Read-only AWS configuration auditor (demo mode only so far).",
    )
    parser.add_argument("--version", action="version", version=f"collumbus {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logs")
    sub = parser.add_subparsers(dest="command", required=True)

    p_config = sub.add_parser("validate-config", help="validate the rules config file")
    p_config.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    p_config.set_defaults(func=_cmd_validate_config)

    p_sample = sub.add_parser("sample-finding", help="print one SIMULATED finding as JSON")
    p_sample.set_defaults(func=_cmd_sample_finding)

    p_demo = sub.add_parser(
        "demo-scan", help="scan the fictional demo dataset and print the results"
    )
    p_demo.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    p_demo.add_argument(
        "--data", type=Path, default=DEFAULT_DEMO_PATH, help="path to demo JSON file"
    )
    p_demo.add_argument("--json", type=Path, default=None, help="write full scan JSON report")
    p_demo.add_argument("--csv", type=Path, default=None, help="write findings CSV report")
    p_demo.add_argument(
        "--failures-only", action="store_true", help="include only Fail/Error in CSV report"
    )
    p_demo.set_defaults(func=_cmd_demo_scan)

    p_export = sub.add_parser("export-csv", help="export an existing scan JSON report to CSV")
    p_export.add_argument("scan_json", type=Path, help="path to scan JSON report")
    p_export.add_argument("-o", "--output", type=Path, default=None, help="output CSV file path")
    p_export.add_argument(
        "--failures-only", action="store_true", help="include only Fail/Error in CSV report"
    )
    p_export.set_defaults(func=_cmd_export_csv)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(logging.DEBUG if args.verbose else logging.WARNING)
    try:
        return args.func(args)
    except (ConfigError, DemoDataError, ReportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
