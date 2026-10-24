"""The common format every collector produces, and the Collector interface.

Demo and AWS collectors both return a CollectionResult, so the same rules
evaluate both kinds of data.
"""

from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from collumbus.models import CoverageGap, Source

# Resource types. AWS types use AWS's CloudFormation names. The region-coverage
# type is Collumbus's own: one record per region, used to detect regions with no trail.
S3_BUCKET = "AWS::S3::Bucket"
IAM_POLICY = "AWS::IAM::Policy"
CLOUDTRAIL_TRAIL = "AWS::CloudTrail::Trail"
CLOUDTRAIL_REGION = "Collumbus::CloudTrail::RegionCoverage"

# Error codes that mean "the scanning identity lacks permission".
ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


class FetchError(BaseModel):
    """One attribute of a resource that could not be read."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attribute: str = Field(min_length=1)  # e.g. "public_access_block"
    code: str = Field(min_length=1)  # e.g. "AccessDenied", "Throttling"
    message: str = ""
    permission: str | None = None  # IAM permission the API call needs


class Resource(BaseModel):
    """One normalized cloud resource.

    An attribute that was read successfully is in `attributes`. Its value may be
    None, meaning "AWS says this is not configured". An attribute that could not
    be read is listed in `fetch_errors` instead. Those are different situations
    and rules must treat them differently.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    region: str = Field(min_length=1)  # "global" for IAM
    category: str = Field(min_length=1)  # "s3", "iam", "cloudtrail"
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    fetch_errors: list[FetchError] = Field(default_factory=list)

    @model_validator(mode="after")
    def _no_value_and_error_for_same_attribute(self) -> "Resource":
        both = {e.attribute for e in self.fetch_errors} & set(self.attributes)
        if both:
            raise ValueError(f"attributes cannot be both collected and failed: {sorted(both)}")
        return self


class CollectionResult(BaseModel):
    """Everything a collector gathered, plus what it could not inspect."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: Source
    account_id: str = Field(pattern=r"^\d{12}$")
    regions: list[str] = Field(min_length=1)
    resource_categories: list[str] = Field(min_length=1)
    resources: list[Resource] = Field(default_factory=list)
    # Whole areas that could not be listed at all (e.g. ListBuckets was denied).
    gaps: list[CoverageGap] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_consistency(self) -> "CollectionResult":
        seen = set()
        for r in self.resources:
            key = (r.resource_type, r.region, r.resource_id)
            if key in seen:
                raise ValueError(f"duplicate resource: {r.resource_type} {r.resource_id}")
            seen.add(key)
            if r.region != "global" and r.region not in self.regions:
                raise ValueError(f"resource {r.resource_id} is in unrequested region {r.region}")
            if r.category not in self.resource_categories:
                raise ValueError(f"resource {r.resource_id} has unrequested category {r.category}")
        return self


class Collector(ABC):
    """Gathers configuration and returns it in the common format. Read-only."""

    @abstractmethod
    def collect(self) -> CollectionResult: ...
