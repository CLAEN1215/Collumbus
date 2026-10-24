"""The Finding model: one rule's verdict about one resource."""

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from collumbus.security.redaction import redact_data


class Severity(StrEnum):
    """How serious a failed check is. Assigned per rule, separately from pass/fail."""

    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Status(StrEnum):
    """The verdict. ERROR means "could not determine"; it is never a pass."""

    PASS = "Pass"  # noqa: S105  # nosec B105
    FAIL = "Fail"
    ERROR = "Error"
    NOT_APPLICABLE = "Not Applicable"


class Source(StrEnum):
    """Where the data came from. Demo results are simulated, never real findings."""

    DEMO = "Demo"
    AWS = "AWS"


def make_finding_id(rule_id: str, account_id: str, region: str, resource_id: str) -> str:
    """Return a stable ID: the same rule + account + region + resource always gives
    the same ID, so a finding can be tracked across scans."""
    # JSON encoding avoids ambiguity, e.g. ("a|b", "c") vs ("a", "b|c").
    key = json.dumps([rule_id, account_id, region, resource_id])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    # extra="forbid": unknown fields are an error, not silently ignored.
    # frozen=True: a finding cannot be edited after it is validated.
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(default="", min_length=16, max_length=16)
    rule_id: str = Field(pattern=r"^[A-Z0-9]+-\d{3}$")
    title: str = Field(min_length=1)
    severity: Severity
    status: Status
    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    region: str = Field(min_length=1)  # "global" for services like IAM
    account_id: str = Field(pattern=r"^\d{12}$")
    summary: str = Field(min_length=1)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    risk: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    first_detected: AwareDatetime
    last_detected: AwareDatetime
    scan_id: str = Field(min_length=1)
    source: Source

    @model_validator(mode="before")
    @classmethod
    def _fill_finding_id(cls, data: Any) -> Any:
        """Compute finding_id when the caller did not supply one."""
        if isinstance(data, dict) and not data.get("finding_id"):
            try:
                data = {
                    **data,
                    "finding_id": make_finding_id(
                        data["rule_id"], data["account_id"], data["region"], data["resource_id"]
                    ),
                }
            except (KeyError, TypeError):
                pass  # Missing fields are reported by normal field validation.
        return data

    @field_validator("evidence")
    @classmethod
    def _redact_evidence(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return redact_data(value)

    @field_validator("references")
    @classmethod
    def _https_only(cls, value: list[str]) -> list[str]:
        for url in value:
            if not url.startswith("https://"):
                raise ValueError(f"reference must be an https:// URL: {url!r}")
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> "Finding":
        expected = make_finding_id(self.rule_id, self.account_id, self.region, self.resource_id)
        if self.finding_id != expected:
            raise ValueError(
                "finding_id does not match rule_id/account_id/region/resource_id "
                "(the data may have been edited or corrupted)"
            )
        if self.first_detected > self.last_detected:
            raise ValueError("first_detected cannot be later than last_detected")
        if self.status == Status.FAIL and not self.remediation:
            raise ValueError("a failed finding must include remediation guidance")
        return self
