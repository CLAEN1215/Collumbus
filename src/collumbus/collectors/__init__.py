"""Collectors gather configuration (demo file or AWS) into one common format."""

from collumbus.collectors.base import (
    CLOUDTRAIL_REGION,
    CLOUDTRAIL_TRAIL,
    IAM_POLICY,
    S3_BUCKET,
    CollectionResult,
    Collector,
    FetchError,
    Resource,
)
from collumbus.collectors.demo import DemoCollector, DemoDataError

__all__ = [
    "CLOUDTRAIL_REGION",
    "CLOUDTRAIL_TRAIL",
    "IAM_POLICY",
    "S3_BUCKET",
    "CollectionResult",
    "Collector",
    "DemoCollector",
    "DemoDataError",
    "FetchError",
    "Resource",
]
