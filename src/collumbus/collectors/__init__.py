"""Collectors gather configuration (demo file or AWS) into one common format."""

from collumbus.collectors.aws import AwsCollector, AwsCredentialsError
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
from collumbus.collectors.memory import (
    FileParseError,
    MemoryCollector,
    parse_input_to_collection,
)

__all__ = [
    "CLOUDTRAIL_REGION",
    "CLOUDTRAIL_TRAIL",
    "IAM_POLICY",
    "S3_BUCKET",
    "AwsCollector",
    "AwsCredentialsError",
    "CollectionResult",
    "Collector",
    "DemoCollector",
    "DemoDataError",
    "FetchError",
    "FileParseError",
    "MemoryCollector",
    "Resource",
    "parse_input_to_collection",
]
