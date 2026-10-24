"""The shared rule interface.

A rule reads one normalized Resource and returns a RuleResult (a verdict).
Rules never fetch data, print, or change anything. They also do not assign
severity; the engine does that separately (see engine/severity.py).
"""

from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from collumbus.collectors.base import ACCESS_DENIED_CODES, Resource
from collumbus.config import AppConfig
from collumbus.models import Severity, Status


class RuleResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Status
    summary: str = Field(min_length=1)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    # Optional override of the rule's general remediation text.
    remediation: str | None = None

    @model_validator(mode="after")
    def _summary_required(self) -> "RuleResult":
        if not self.summary.strip():
            raise ValueError("summary must not be blank")
        return self


class Rule(ABC):
    rule_id: ClassVar[str]
    title: ClassVar[str]
    resource_types: ClassVar[frozenset[str]]
    # Used only when config/rules.yaml has no entry for this rule.
    default_severity: ClassVar[Severity]
    risk: ClassVar[str]
    remediation: ClassVar[str]
    references: ClassVar[list[str]]

    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config

    def applies_to(self, resource: Resource) -> bool:
        return resource.resource_type in self.resource_types

    @abstractmethod
    def evaluate(self, resource: Resource) -> RuleResult: ...

    # --- helpers shared by all rules ----------------------------------------

    def unavailable(self, resource: Resource, attribute: str) -> RuleResult | None:
        """Return an Error result if `attribute` could not be read, else None.

        Every rule calls this before using an attribute, so a failed or missing
        read always becomes Error and can never be mistaken for a pass.
        """
        for err in resource.fetch_errors:
            if err.attribute == attribute:
                if err.code in ACCESS_DENIED_CODES:
                    hint = (
                        f"Grant the scanning identity {err.permission}"
                        if err.permission
                        else "Grant the scanning identity read access"
                    )
                    advice = f"{hint}, then scan again."
                else:
                    advice = "This may be temporary. Scan again later."
                return RuleResult(
                    status=Status.ERROR,
                    summary=f"Could not read {attribute} ({err.code}). Result unknown.",
                    evidence={
                        "attribute": attribute,
                        "error_code": err.code,
                        "error_message": err.message,
                        "required_permission": err.permission,
                    },
                    remediation=advice,
                )
        if attribute not in resource.attributes:
            return RuleResult(
                status=Status.ERROR,
                summary=f"No data was collected for {attribute}. Result unknown.",
                evidence={"attribute": attribute, "error_code": "NotCollected"},
                remediation="Check the collector output for this resource, then scan again.",
            )
        return None

    def malformed(self, attribute: str, detail: str) -> RuleResult:
        """Error result for data that exists but has an unexpected shape."""
        return RuleResult(
            status=Status.ERROR,
            summary=f"{attribute} has an unexpected format ({detail}). Result unknown.",
            evidence={"attribute": attribute, "error_code": "MalformedData", "detail": detail},
            remediation="Check the collected data for this resource, then scan again.",
        )
