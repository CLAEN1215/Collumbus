"""History page: browse past audit runs, compare scans, and track issue lifecycles."""

import pandas as pd
import streamlit as st
from pydantic import ValidationError

from collumbus.dashboard.state import (
    get_active_scan,
    get_history,
    run_and_save_demo_scan,
    set_active_scan,
)
from collumbus.dashboard.theme import apply_theme
from collumbus.history import compare_scans
from collumbus.models import Scan, Status
from collumbus.validation import format_validation_error


def render_history() -> None:
    apply_theme()
    active_scan = get_active_scan()
    history = get_history()

    st.title("⏱️ Scan History & Trend Tracking")
    st.caption(
        "Review previous audits, compare posture changes, and track issue resolution over time."
    )

    # Actions row: Run new scan or Upload external scan
    act_col1, act_col2 = st.columns([1, 2])
    with act_col1:
        if st.button("🚀 Run New Demo Scan", type="primary", use_container_width=True):
            new_scan = run_and_save_demo_scan()
            st.success(f"Executed and saved scan `{new_scan.scan_id[:8]}`!")
            st.rerun()

    with act_col2:
        uploaded_file = st.file_uploader(
            "Upload External Scan JSON", type=["json"], label_visibility="collapsed"
        )
        if uploaded_file is not None:
            try:
                content = uploaded_file.read().decode("utf-8")
                loaded_scan = Scan.model_validate_json(content)
                set_active_scan(loaded_scan)
                st.success(f"Loaded external scan `{loaded_scan.scan_id[:8]}` into active view!")
                st.rerun()
            except ValidationError as exc:
                err_msg = format_validation_error(exc)
                st.error(f"Uploaded file is not a valid Scan report: {err_msg}")
            except Exception as exc:
                st.error(f"Failed to read file: {exc}")

    st.divider()

    if not history:
        st.info(
            "No scan history saved yet. Click 'Run New Demo Scan' above to record the first scan."
        )
        return

    # Posture Trend Over Time (if at least 2 scans)
    if len(history) >= 2:
        st.subheader("📈 Security Posture Trend")
        trend_records = []
        for s in reversed(history):
            f_count = sum(1 for f in s.findings if f.status == Status.FAIL)
            e_count = sum(1 for f in s.findings if f.status == Status.ERROR)
            trend_records.append(
                {
                    "Timestamp": s.started_at.strftime("%m/%d %H:%M"),
                    "Failures": f_count,
                    "Errors": e_count,
                    "Total Findings": len(s.findings),
                }
            )
        trend_df = pd.DataFrame(trend_records)
        st.line_chart(trend_df, x="Timestamp", y=["Failures", "Errors", "Total Findings"])

    # Scan History Table
    st.subheader("Historical Audit Records")
    table_data = []
    for s in history:
        fails = sum(1 for f in s.findings if f.status == Status.FAIL)
        errors = sum(1 for f in s.findings if f.status == Status.ERROR)
        is_active = s.scan_id == active_scan.scan_id
        table_data.append(
            {
                "Active": "👉 CURRENT" if is_active else "",
                "Date (UTC)": s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
                "Scan ID": s.scan_id[:8],
                "Source": s.source.value,
                "Account": s.account_id,
                "Resources": s.coverage.resources_inspected,
                "Total Findings": len(s.findings),
                "Fails": fails,
                "Errors": errors,
                "Complete": "Yes" if s.is_complete else "No",
            }
        )
    st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)

    st.divider()

    # Scan Comparison Diff Tool
    st.subheader("Compare Audits (Posture Diff)")
    if len(history) < 2:
        st.info("Record at least two scans to compare changes between audit runs.")
        return

    scan_labels = {
        s.scan_id: f"{s.started_at.strftime('%Y-%m-%d %H:%M')} ({s.scan_id[:8]})" for s in history
    }

    cmp_c1, cmp_c2 = st.columns(2)
    with cmp_c1:
        baseline_id = st.selectbox(
            "Baseline (Older) Scan",
            options=list(scan_labels.keys()),
            index=min(1, len(history) - 1),
            format_func=lambda x: scan_labels[x],
        )
    with cmp_c2:
        current_id = st.selectbox(
            "Current (Newer) Scan",
            options=list(scan_labels.keys()),
            index=0,
            format_func=lambda x: scan_labels[x],
        )

    if baseline_id == current_id:
        st.info("Select two different scans to see posture changes.")
        return

    baseline_scan = next((s for s in history if s.scan_id == baseline_id), None)
    current_scan = next((s for s in history if s.scan_id == current_id), None)

    if not baseline_scan or not current_scan:
        st.error("Could not find the selected scans.")
        return

    try:
        diff = compare_scans(baseline_scan, current_scan)

        # Diff metrics
        d1, d2, d3 = st.columns(3)
        with d1:
            st.metric(
                "New Issues",
                len(diff.new_findings),
                delta=f"+{len(diff.new_findings)}" if diff.new_findings else "0",
                delta_color="inverse",
            )
        with d2:
            st.metric(
                "Resolved Issues",
                len(diff.resolved_findings),
                delta=f"-{len(diff.resolved_findings)}" if diff.resolved_findings else "0",
                delta_color="normal",
            )
        with d3:
            st.metric(
                "Recurring Issues",
                len(diff.recurring_findings),
                delta=f"{len(diff.recurring_findings)} persisting",
                delta_color="off",
            )

        if diff.new_findings:
            with st.expander(f"⚠️ New Findings ({len(diff.new_findings)})", expanded=True):
                for f in diff.new_findings:
                    tag = f"[{f.status.value.upper()}] {f.severity.value}"
                    st.write(f"- **{tag}** `{f.rule_id}` — {f.resource_id}: {f.summary}")

        if diff.resolved_findings:
            with st.expander(f"✅ Resolved Findings ({len(diff.resolved_findings)})"):
                for f in diff.resolved_findings:
                    st.write(f"- `{f.rule_id}` — {f.resource_id}: {f.summary}")

        if diff.recurring_findings:
            with st.expander(f"🔄 Recurring Findings ({len(diff.recurring_findings)})"):
                for f in diff.recurring_findings:
                    age_str = f.first_detected.strftime("%Y-%m-%d")
                    st.write(f"- `{f.rule_id}` — {f.resource_id} (first detected {age_str})")

    except ValueError as exc:
        st.warning(f"Cannot compare selected scans: {exc}")
