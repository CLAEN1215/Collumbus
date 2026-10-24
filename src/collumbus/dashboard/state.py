"""Session state and data management for the Streamlit dashboard."""

from collections.abc import Sequence
from pathlib import Path

import streamlit as st

from collumbus.collectors import AwsCollector, DemoCollector
from collumbus.config import load_config
from collumbus.engine import run_scan
from collumbus.history import (
    correlate_scan_with_history,
    list_historical_scans,
    save_scan_to_history,
)
from collumbus.models import Scan


def get_history(history_dir: Path | None = None) -> list[Scan]:
    """Retrieve historical scans from disk."""
    if history_dir is not None:
        return list_historical_scans(history_dir)
    return list_historical_scans()


def run_and_save_demo_scan(history_dir: Path | None = None) -> Scan:
    """Run a new demo scan, correlate with past scans, save to history, and update state."""
    config = load_config()
    raw_scan = run_scan(DemoCollector(), config)
    past_scans = get_history(history_dir)
    scan = correlate_scan_with_history(raw_scan, past_scans)
    if history_dir is not None:
        save_scan_to_history(scan, history_dir)
    else:
        save_scan_to_history(scan)
    st.session_state["active_scan"] = scan
    return scan


def run_and_save_aws_scan(
    regions: Sequence[str] | None = None,
    history_dir: Path | None = None,
) -> Scan:
    """Run a live AWS scan, correlate with past scans, save to history, and update state."""
    config = load_config()
    raw_scan = run_scan(AwsCollector(regions=regions), config)
    past_scans = get_history(history_dir)
    scan = correlate_scan_with_history(raw_scan, past_scans)
    if history_dir is not None:
        save_scan_to_history(scan, history_dir)
    else:
        save_scan_to_history(scan)
    st.session_state["active_scan"] = scan
    return scan


def run_and_save_content_scan(
    content: str,
    name: str = "Uploaded Document",
    history_dir: Path | None = None,
) -> Scan:
    """Run an audit on uploaded or pasted JSON content, save to history, and update state."""
    from collumbus.collectors import MemoryCollector, parse_input_to_collection

    collection = parse_input_to_collection(content, target_name=name)
    config = load_config()
    raw_scan = run_scan(MemoryCollector(collection), config)
    past_scans = get_history(history_dir)
    scan = correlate_scan_with_history(raw_scan, past_scans)
    if history_dir is not None:
        save_scan_to_history(scan, history_dir)
    else:
        save_scan_to_history(scan)
    st.session_state["active_scan"] = scan
    return scan


def get_active_scan(history_dir: Path | None = None) -> Scan:
    """Return the active scan from session state, or load the latest historical scan,
    or run a demo scan if no history exists yet."""
    if "active_scan" in st.session_state and isinstance(st.session_state["active_scan"], Scan):
        return st.session_state["active_scan"]

    history = get_history(history_dir)
    if history:
        scan = history[0]
        st.session_state["active_scan"] = scan
        return scan

    return run_and_save_demo_scan(history_dir)


def set_active_scan(scan: Scan) -> None:
    """Switch the dashboard's active scan."""
    st.session_state["active_scan"] = scan
