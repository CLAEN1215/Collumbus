from unittest.mock import MagicMock, patch

import pytest
import streamlit as st

from collumbus.collectors import DemoCollector
from collumbus.config import load_config
from collumbus.dashboard import APP_PATH
from collumbus.dashboard.state import (
    get_active_scan,
    get_history,
    run_and_save_demo_scan,
    set_active_scan,
)
from collumbus.dashboard.views import (
    render_coverage,
    render_findings,
    render_history,
    render_overview,
    render_rules,
)
from collumbus.engine import run_scan
from collumbus.models import Scan


@pytest.fixture
def clean_state():
    if "active_scan" in st.session_state:
        del st.session_state["active_scan"]
    yield
    if "active_scan" in st.session_state:
        del st.session_state["active_scan"]


@pytest.fixture
def mock_scan():
    config = load_config()
    return run_scan(DemoCollector(), config)


def test_app_path_exists():
    assert APP_PATH.exists()
    assert APP_PATH.name == "app.py"


def test_dashboard_state_lifecycle(clean_state, tmp_path, mock_scan):
    # Empty history
    assert get_history(tmp_path) == []

    # Run and save scan
    scan = run_and_save_demo_scan(history_dir=tmp_path)
    assert isinstance(scan, Scan)
    assert len(get_history(tmp_path)) == 1

    # get_active_scan returns the cached scan
    active = get_active_scan(history_dir=tmp_path)
    assert active.scan_id == scan.scan_id

    # Switch active scan
    other_scan = mock_scan.model_copy(update={"scan_id": "other123"})
    set_active_scan(other_scan)
    assert get_active_scan(history_dir=tmp_path).scan_id == "other123"


def mock_cols(spec, **kwargs):
    count = spec if isinstance(spec, int) else len(spec)
    return [MagicMock() for _ in range(count)]


def test_render_overview_execution(clean_state, mock_scan):
    set_active_scan(mock_scan)
    with patch("streamlit.columns", side_effect=mock_cols):
        render_overview()

    # Test clean scan (complete with no fails)
    clean_scan = mock_scan.model_copy(update={"is_complete": True, "findings": []})
    set_active_scan(clean_scan)
    with patch("streamlit.columns", side_effect=mock_cols):
        render_overview()


def test_render_findings_execution(clean_state, mock_scan):
    set_active_scan(mock_scan)
    with (
        patch("streamlit.columns", side_effect=mock_cols),
        patch("streamlit.multiselect", return_value=[]),
        patch("streamlit.text_input", return_value=""),
    ):
        render_findings()

    # Test filtering with query and empty result
    with (
        patch("streamlit.columns", side_effect=mock_cols),
        patch("streamlit.multiselect", return_value=["NonExistent"]),
        patch("streamlit.text_input", return_value="nonexistent-query"),
    ):
        render_findings()


def test_render_coverage_execution(clean_state, mock_scan):
    set_active_scan(mock_scan)
    with patch("streamlit.columns", side_effect=mock_cols):
        render_coverage()

    # Test zero gaps
    from collumbus.models import Coverage

    clean_coverage = mock_scan.model_copy(
        update={"coverage": Coverage(inspected_categories=["s3"], resources_inspected=1, gaps=[])}
    )
    set_active_scan(clean_coverage)
    with patch("streamlit.columns", side_effect=mock_cols):
        render_coverage()


def test_render_rules_execution():
    with patch("streamlit.columns", side_effect=mock_cols):
        render_rules()


def test_render_history_execution(clean_state, mock_scan, tmp_path):
    set_active_scan(mock_scan)
    # Test with 1 scan
    with (
        patch("collumbus.dashboard.views.history.get_history", return_value=[mock_scan]),
        patch("streamlit.columns", side_effect=mock_cols),
    ):
        render_history()

    # Test with 2 scans to run diff
    scan2 = mock_scan.model_copy(
        update={
            "scan_id": "scan-diff-2",
            "findings": [mock_scan.findings[0]],
        }
    )
    with (
        patch("collumbus.dashboard.views.history.get_history", return_value=[mock_scan, scan2]),
        patch("streamlit.columns", side_effect=mock_cols),
        patch("streamlit.selectbox", side_effect=[scan2.scan_id, mock_scan.scan_id]),
    ):
        render_history()
