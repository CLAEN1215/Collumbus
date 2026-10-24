import logging

import pytest

from collumbus.logging_setup import RedactingFilter
from collumbus.security import REDACTED, redact_data, redact_text

# AWS's documented example credentials (not real keys).
EXAMPLE_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa: S105 - public AWS doc example


@pytest.mark.parametrize(
    "text, secret",
    [
        (f"key {EXAMPLE_KEY_ID} denied", EXAMPLE_KEY_ID),
        ("temp key ASIAIOSFODNN7EXAMPLE used", "ASIAIOSFODNN7EXAMPLE"),
        (f"aws_secret_access_key={EXAMPLE_SECRET}", EXAMPLE_SECRET),
        ("aws_session_token: FwoGZXIvYXdzEXAMPLE", "FwoGZXIvYXdzEXAMPLE"),
        ("password=hunter2", "hunter2"),
    ],
)
def test_redact_text_removes_secrets(text, secret):
    result = redact_text(text)
    assert secret not in result
    assert REDACTED in result


def test_redact_text_leaves_normal_text_alone():
    text = "Bucket demo-bucket has BlockPublicPolicy=false in us-east-1"
    assert redact_text(text) == text


def test_redact_data_handles_nested_structures():
    data = {
        "aws_access_key_id": EXAMPLE_KEY_ID,
        "SecretAccessKey": EXAMPLE_SECRET,
        "items": [{"Token": "abc"}, {"name": "ok"}],
        "count": 3,
        "flag": True,
    }
    result = redact_data(data)
    assert result == {
        "aws_access_key_id": REDACTED,
        "SecretAccessKey": REDACTED,
        "items": [{"Token": REDACTED}, {"name": "ok"}],
        "count": 3,
        "flag": True,
    }
    # The original is not modified.
    assert data["SecretAccessKey"] == EXAMPLE_SECRET


def test_redact_data_keeps_kms_key_ids():
    # A KMS key ID identifies a key; it is evidence, not a secret.
    data = {"KMSMasterKeyID": "arn:aws:kms:us-east-1:111122223333:key/example"}
    assert redact_data(data) == data


def test_logging_filter_redacts_messages_and_args(caplog):
    logger = logging.getLogger("collumbus.test")
    caplog.handler.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO, logger="collumbus.test"):
        logger.info("calling AWS with %s and secret=%s", EXAMPLE_KEY_ID, EXAMPLE_SECRET)
    assert EXAMPLE_KEY_ID not in caplog.text
    assert EXAMPLE_SECRET not in caplog.text
    assert REDACTED in caplog.text
