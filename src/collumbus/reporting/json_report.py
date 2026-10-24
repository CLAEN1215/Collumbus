"""JSON report generation and loading for Collumbus scans."""

from pathlib import Path

from pydantic import ValidationError

from collumbus.models import Scan
from collumbus.validation import format_validation_error


class ReportError(Exception):
    """Raised when a report cannot be written, read, or validated."""


def export_json(scan: Scan, indent: int = 2) -> str:
    """Serialize a Scan model to a formatted JSON string."""
    return scan.model_dump_json(indent=indent)


def write_json_report(scan: Scan, path: Path, indent: int = 2) -> Path:
    """Write a Scan model to a JSON file. Creates parent directories if needed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = export_json(scan, indent=indent)
        path.write_text(content, encoding="utf-8")
        return path
    except OSError as exc:
        raise ReportError(f"cannot write JSON report to {path}: {exc.strerror}") from exc


def read_json_report(path: Path) -> Scan:
    """Read a JSON file and parse it into a validated Scan object."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"cannot read JSON report from {path}: {exc.strerror}") from exc

    try:
        return Scan.model_validate_json(text)
    except ValidationError as exc:
        problems = format_validation_error(exc)
        raise ReportError(f"JSON report at {path} is invalid: {problems}") from exc
