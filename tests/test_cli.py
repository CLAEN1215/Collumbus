import json
import subprocess  # noqa: S404 - test runs our own module with fixed arguments
import sys
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import NoCredentialsError

from collumbus import __version__
from collumbus.cli import SIMULATED_BANNER, build_sample_finding, main
from collumbus.collectors import AwsCollector, CollectionResult
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


def test_demo_scan_writes_json_and_csv(tmp_path, capsys):
    json_path = tmp_path / "scan.json"
    csv_path = tmp_path / "scan.csv"
    assert main(["demo-scan", "--json", str(json_path), "--csv", str(csv_path)]) == 0

    assert json_path.exists()
    assert csv_path.exists()
    out = capsys.readouterr().out
    assert f"Wrote JSON report to {json_path}" in out
    assert f"Wrote CSV report to {csv_path}" in out


def test_export_csv_stdout(tmp_path, capsys):
    json_path = tmp_path / "scan.json"
    assert main(["demo-scan", "--json", str(json_path)]) == 0
    capsys.readouterr()  # clear buffer

    assert main(["export-csv", str(json_path)]) == 0
    out = capsys.readouterr().out
    assert "finding_id,rule_id,title,severity" in out


def test_export_csv_to_file(tmp_path, capsys):
    json_path = tmp_path / "scan.json"
    csv_path = tmp_path / "exported.csv"
    assert main(["demo-scan", "--json", str(json_path)]) == 0
    capsys.readouterr()

    assert main(["export-csv", str(json_path), "-o", str(csv_path), "--failures-only"]) == 0
    assert csv_path.exists()
    out = capsys.readouterr().out
    assert f"Wrote CSV report to {csv_path}" in out


def test_export_csv_missing_file_reports_error(tmp_path, capsys):
    missing_json = tmp_path / "nonexistent.json"
    assert main(["export-csv", str(missing_json)]) == 2
    assert "Error: cannot read JSON report" in capsys.readouterr().err


def test_dashboard_cli_calls_streamlit():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert main(["dashboard", "--port", "9000", "--no-browser"]) == 0
        args, _ = mock_run.call_args
        cmd = args[0]
        assert "streamlit" in cmd
        assert "run" in cmd
        assert "--server.port" in cmd
        assert "9000" in cmd
        assert "--server.headless=true" in cmd


def test_aws_scan_cli_credentials_error(capsys):
    with patch("boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        mock_session.client.return_value = mock_sts
        mock_session_cls.return_value = mock_session

        assert main(["aws-scan"]) == 2
        assert "Error: AWS credentials not found" in capsys.readouterr().err


def test_aws_scan_cli_success(tmp_path, capsys):
    json_path = tmp_path / "aws_scan.json"
    csv_path = tmp_path / "aws_scan.csv"

    mock_collection = CollectionResult(
        source=Source.AWS,
        account_id="111122223333",
        regions=["us-east-1"],
        resource_categories=["s3"],
        resources=[],
        gaps=[],
    )

    with patch.object(AwsCollector, "collect", return_value=mock_collection):
        assert main(["aws-scan", "--json", str(json_path), "--csv", str(csv_path)]) == 0
        out = capsys.readouterr().out
        assert "AWS LIVE (UNVERIFIED)" in out
        assert "account=111122223333" in out
        assert json_path.exists()
        assert csv_path.exists()
