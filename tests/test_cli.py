import json
import subprocess  # noqa: S404 - test runs our own module with fixed arguments
import sys

import pytest

from collumbus import __version__
from collumbus.cli import SIMULATED_BANNER, build_sample_finding, main
from collumbus.models import Finding, Source


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_validate_config_succeeds(capsys):
    assert main(["validate-config"]) == 0
    out = capsys.readouterr().out
    assert "Config OK" in out
    assert "S3-001" in out


def test_validate_config_reports_bad_file(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: [unclosed", encoding="utf-8")
    assert main(["validate-config", "--config", str(bad)]) == 2
    assert "not valid YAML" in capsys.readouterr().err


def test_sample_finding_prints_valid_simulated_json(capsys):
    assert main(["sample-finding"]) == 0
    captured = capsys.readouterr()
    assert SIMULATED_BANNER in captured.err
    finding = Finding.model_validate(json.loads(captured.out))
    assert finding.source == Source.DEMO


def test_sample_finding_is_deterministic():
    assert build_sample_finding() == build_sample_finding()


def test_python_dash_m_entry_point():
    result = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [sys.executable, "-m", "collumbus", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert __version__ in result.stdout


def test_demo_scan_succeeds(capsys):
    assert main(["demo-scan"]) == 0
    out = capsys.readouterr().out
    assert "SIMULATED DATA" in out
    assert "Scan " in out
    assert "Resources inspected: 10" in out
    assert "Findings: 15" in out
    assert "Coverage gaps" in out


def test_demo_scan_bad_config(tmp_path, capsys):
    bad_cfg = tmp_path / "bad.yaml"
    bad_cfg.write_text("not: valid: yaml", encoding="utf-8")
    assert main(["demo-scan", "--config", str(bad_cfg)]) == 2
    assert "Error:" in capsys.readouterr().err


def test_demo_scan_bad_data(tmp_path, capsys):
    bad_data = tmp_path / "missing.json"
    assert main(["demo-scan", "--data", str(bad_data)]) == 2
    assert "cannot read demo file" in capsys.readouterr().err
