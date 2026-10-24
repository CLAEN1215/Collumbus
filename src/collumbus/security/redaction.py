"""Remove secrets from text and data before they reach logs, evidence, or reports.

Redaction is a safety net, not a guarantee. The main protection is that Collumbus
never reads or stores credentials in the first place.
"""

import re
from typing import Any

REDACTED = "[REDACTED]"

# Patterns for secrets that might appear inside free text (error messages, etc.).
_TEXT_PATTERNS = [
    # AWS access key IDs: AKIA (long-term) or ASIA (temporary), 16 more chars.
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    # key=value or key: value pairs whose key names a secret.
    re.compile(
        r"(?i)\b(aws_secret_access_key|aws_session_token|secret|password|token)"
        r"(\s*[=:]\s*)([^\s,;\"']+)"
    ),
]

# Dictionary keys whose values are always secrets. Compared after lowercasing and
# removing "_" and "-", so "SecretAccessKey" and "secret_access_key" both match.
_SENSITIVE_KEYS = {
    "secretaccesskey",
    "awssecretaccesskey",
    "sessiontoken",
    "awssessiontoken",
    "accesskeyid",
    "awsaccesskeyid",
    "password",
    "secret",
    "token",
    "credentials",
    "authorization",
}


def _normalize_key(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "")


def redact_text(text: str) -> str:
    """Return text with recognizable secrets replaced by [REDACTED]."""
    text = _TEXT_PATTERNS[0].sub(REDACTED, text)
    text = _TEXT_PATTERNS[1].sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return text


def redact_data(value: Any) -> Any:
    """Recursively redact secrets in dicts, lists, and strings. Returns a new object."""
    if isinstance(value, dict):
        return {
            k: REDACTED
            if isinstance(k, str) and _normalize_key(k) in _SENSITIVE_KEYS
            else redact_data(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
