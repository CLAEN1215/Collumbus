"""Logging configuration with automatic secret redaction."""

import logging

from collumbus.security.redaction import redact_text

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


class RedactingFilter(logging.Filter):
    """Redact secrets from every log record before it is written."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Format the message once (applying %-args), redact it, and freeze it.
        record.msg = redact_text(record.getMessage())
        record.args = None
        return True


def setup_logging(level: int = logging.INFO) -> None:
    """Configure the root logger to write redacted messages to stderr."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    # Attached to the handler (not a logger) so it also covers messages
    # propagated from library loggers such as boto3.
    handler.addFilter(RedactingFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
