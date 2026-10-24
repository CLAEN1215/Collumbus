"""Command-line entry point: `collumbus ...` or `python -m collumbus ...`.

Phase 1 commands:
  validate-config   check config/rules.yaml
  sample-finding    print one SIMULATED finding as JSON (proves the model works)

The demo scan command arrives in Phase 2, together with the scanner.
"""

import argparse
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from collumbus import __version__
from collumbus.config import DEFAULT_CONFIG_PATH, ConfigError, load_config
from collumbus.logging_setup import setup_logging
from collumbus.models import Finding, Severity, Source, Status

SIMULATED_BANNER = "SIMULATED DATA: fictional demo finding, not a real AWS result."


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="collumbus",
        description="Read-only AWS configuration auditor (Phase 1: foundation only).",
    )
    parser.add_argument("--version", action="version", version=f"collumbus {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logs")
    sub = parser.add_subparsers(dest="command", required=True)

    p_config = sub.add_parser("validate-config", help="validate the rules config file")
    p_config.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    p_config.set_defaults(func=_cmd_validate_config)

    p_sample = sub.add_parser("sample-finding", help="print one SIMULATED finding as JSON")
    p_sample.set_defaults(func=_cmd_sample_finding)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(logging.DEBUG if args.verbose else logging.WARNING)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
