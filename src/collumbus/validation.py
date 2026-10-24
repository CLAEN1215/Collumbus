"""Shared helper for turning Pydantic errors into readable one-line messages."""

from pydantic import ValidationError


def format_validation_error(exc: ValidationError) -> str:
    """Example: 'rules.S3-001.severity: Input should be ...; account_id: Field required'"""
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc']) or '(top level)'}: {err['msg']}"
        for err in exc.errors()
    )
