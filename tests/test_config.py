import pytest

from collumbus.config import DEFAULT_CONFIG_PATH, ConfigError, load_config
from collumbus.models import Severity

VALID_YAML = """
rules:
  S3-001: {enabled: true, severity: High}
s3_encryption:
  approved_algorithms: [AES256]
"""


def write(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_project_config_loads():
    config = load_config(DEFAULT_CONFIG_PATH)
    assert set(config.rules) == {"S3-001", "S3-002", "IAM-001", "CT-001"}
    assert config.rules["S3-001"].severity == Severity.HIGH
    assert "aws:kms" in config.s3_encryption.approved_algorithms


def test_minimal_valid_config(tmp_path):
    config = load_config(write(tmp_path, VALID_YAML))
    assert config.rules["S3-001"].enabled is True


def test_missing_file_gives_config_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(tmp_path / "does-not-exist.yaml")


def test_malformed_yaml_gives_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(write(tmp_path, "rules: [unclosed"))


def test_non_mapping_yaml_gives_config_error(tmp_path):
    with pytest.raises(ConfigError, match="mapping"):
        load_config(write(tmp_path, "- just\n- a list\n"))


def test_unknown_rule_id_is_rejected(tmp_path):
    text = VALID_YAML.replace("S3-001", "S3-999")
    with pytest.raises(ConfigError, match="unknown rule IDs"):
        load_config(write(tmp_path, text))


def test_invalid_severity_is_rejected(tmp_path):
    text = VALID_YAML.replace("High", "Scary")
    with pytest.raises(ConfigError, match=r"rules\.S3-001\.severity"):
        load_config(write(tmp_path, text))


def test_empty_approved_algorithms_is_rejected(tmp_path):
    text = VALID_YAML.replace("[AES256]", "[]")
    with pytest.raises(ConfigError, match="approved_algorithms"):
        load_config(write(tmp_path, text))


def test_unknown_top_level_key_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="Extra inputs"):
        load_config(write(tmp_path, VALID_YAML + "auto_remediate: true\n"))


def test_unsafe_yaml_tags_are_refused(tmp_path):
    # yaml.load() with an unsafe loader would try to run this; safe_load refuses.
    text = "rules: !!python/object/apply:os.system ['echo hacked']\n"
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(write(tmp_path, text))
