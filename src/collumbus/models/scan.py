"""The Scan model: metadata, coverage, and findings for one audit run."""

import uuid

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from collumbus.models.finding import Finding, Source, Status


def new_scan_id() -> str:
    return uuid.uuid4().hex


class CoverageGap(BaseModel):
    """Something the scan could not inspect, and why."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: str = Field(min_length=1)  # e.g. "s3", "iam", "cloudtrail"
    region: str = Field(min_length=1)
    resource_id: str | None = None  # None = the whole category/region was skipped
    reason: str = Field(min_length=1)  # e.g. "AccessDenied", "Throttling"
    missing_permission: str | None = None  # e.g. "s3:GetEncryptionConfiguration"


class Coverage(BaseModel):
    """What the scan did and did not inspect."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    inspected_categories: list[str] = Field(default_factory=list)
    resources_inspected: int = Field(default=0, ge=0)
    gaps: list[CoverageGap] = Field(default_factory=list)


class Scan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: str = Field(min_length=1)
    source: Source
    account_id: str = Field(pattern=r"^\d{12}$")
    regions: list[str] = Field(min_length=1)
    resource_categories: list[str] = Field(min_length=1)
    started_at: AwareDatetime
    finished_at: AwareDatetime
    coverage: Coverage = Field(default_factory=Coverage)
    # A scan is complete only if everything requested was inspected.
    is_complete: bool
    findings: list[Finding] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_consistency(self) -> "Scan":
        if self.started_at > self.finished_at:
            raise ValueError("started_at cannot be later than finished_at")
        for f in self.findings:
            if f.scan_id != self.scan_id:
                raise ValueError(f"finding {f.finding_id} belongs to a different scan")
            # Never mix demo and real AWS findings in one scan.
            if f.source != self.source:
                raise ValueError(f"finding {f.finding_id} source does not match scan source")
            if f.account_id != self.account_id:
                raise ValueError(f"finding {f.finding_id} account does not match scan account")
        has_errors = any(f.status == Status.ERROR for f in self.findings)
        if self.is_complete and (self.coverage.gaps or has_errors):
            raise ValueError("a scan with coverage gaps or Error findings cannot be complete")
        return self
