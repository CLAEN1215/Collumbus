"""Demo collector: loads fictional resources from a local JSON file.

Everything it returns is SIMULATED. No AWS account or network access is used.
"""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from collumbus.collectors.base import CollectionResult, Collector, Resource
from collumbus.models import CoverageGap, Source
from collumbus.validation import format_validation_error

DEFAULT_DEMO_PATH = Path(__file__).resolve().parents[3] / "data" / "demo" / "resources.json"

# The demo file is small; refuse anything unexpectedly large.
MAX_DEMO_FILE_BYTES = 5 * 1024 * 1024


class DemoDataError(Exception):
    """The demo data file is missing, unreadable, or invalid."""


class DemoFile(BaseModel):
    """The structure of data/demo/resources.json."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    description: str = ""
    account_id: str = Field(pattern=r"^\d{12}$")
    regions: list[str] = Field(min_length=1)
    resource_categories: list[str] = Field(min_length=1)
    resources: list[Resource]
    gaps: list[CoverageGap] = Field(default_factory=list)


class DemoCollector(Collector):
    def __init__(self, path: Path = DEFAULT_DEMO_PATH) -> None:
        self.path = path

    def collect(self) -> CollectionResult:
        try:
            size = self.path.stat().st_size
            if size > MAX_DEMO_FILE_BYTES:
                raise DemoDataError(
                    f"demo file {self.path} is {size} bytes; limit is {MAX_DEMO_FILE_BYTES}"
                )
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise DemoDataError(f"cannot read demo file {self.path}: {exc.strerror}") from exc

        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DemoDataError(
                f"demo file {self.path} is not valid JSON (line {exc.lineno}): {exc.msg}"
            ) from exc

        try:
            demo = DemoFile.model_validate(raw)
            # Sorting makes the order independent of how the file happens to be written.
            resources = sorted(
                demo.resources, key=lambda r: (r.category, r.resource_type, r.region, r.resource_id)
            )
            return CollectionResult(
                source=Source.DEMO,
                account_id=demo.account_id,
                regions=demo.regions,
                resource_categories=demo.resource_categories,
                resources=resources,
                gaps=demo.gaps,
            )
        except ValidationError as exc:
            problems = format_validation_error(exc)
            raise DemoDataError(f"demo file {self.path} is invalid: {problems}") from exc
