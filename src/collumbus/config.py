"""Load and validate config/rules.yaml."""

import logging
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from collumbus.models.finding import Severity
from collumbus.validation import format_validation_error

logger = logging.getLogger(__name__)

# Project root is three levels above this file: src/collumbus/config.py
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "rules.yaml"

KNOWN_RULE_IDS = {"S3-001", "S3-002", "IAM-001", "CT-001"}


class ConfigError(Exception):
    """The configuration file is missing, unreadable, or invalid."""


class RuleSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    severity: Severity


class S3EncryptionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved_algorithms: list[str] = Field(min_length=1)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: dict[str, RuleSettings]
    s3_encryption: S3EncryptionSettings

    @field_validator("rules")
    @classmethod
    def _known_rules_only(cls, value: dict[str, RuleSettings]) -> dict[str, RuleSettings]:
        unknown = set(value) - KNOWN_RULE_IDS
        if unknown:
            raise ValueError(
                f"unknown rule IDs: {sorted(unknown)}; known rules are {sorted(KNOWN_RULE_IDS)}"
            )
        return value


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> AppConfig:
    """Read and validate the rules config. Raises ConfigError with a readable message."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror}") from exc

    try:
        # safe_load only builds plain data (dicts, lists, strings, numbers);
        # it cannot run code or create arbitrary Python objects.
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {path} is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must contain a YAML mapping at the top level")

    try:
        config = AppConfig.model_validate(data)
    except ValidationError as exc:
        problems = format_validation_error(exc)
        raise ConfigError(f"config file {path} is invalid: {problems}") from exc

    logger.debug("Loaded config from %s", path)
    return config
