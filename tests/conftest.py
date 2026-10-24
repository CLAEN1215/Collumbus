from datetime import UTC, datetime

import pytest

T0 = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def finding_data() -> dict:
    """Valid raw data for a Finding. Tests copy and modify it."""
    return {
        "rule_id": "S3-001",
        "title": "S3 bucket Public Access Block is incomplete",
        "severity": "High",
        "status": "Fail",
        "resource_type": "AWS::S3::Bucket",
        "resource_id": "demo-bucket",
        "region": "us-east-1",
        "account_id": "111122223333",
        "summary": "BlockPublicPolicy is disabled.",
        "evidence": {"BlockPublicPolicy": False},
        "risk": "A public bucket policy could be applied.",
        "remediation": "Enable all four Block Public Access settings.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/"],
        "first_detected": T0,
        "last_detected": T0,
        "scan_id": "scan-1",
        "source": "Demo",
    }
