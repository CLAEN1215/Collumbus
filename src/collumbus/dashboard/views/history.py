"""History page: browse past audit runs, compare scans, and track issue lifecycles.

Built using the 7 Principles of Design:
1. Contrast - High-visibility metrics for new vs resolved security issues.
2. Hierarchy - Top audit actions, posture trend visualization, history log, then posture diff.
3. Alignment - Symmetrical baseline vs target scan comparison columns.
4. Balance - Balanced delta metrics (New, Resolved, Recurring) with color coding.
5. Proximity - Scan selectors placed directly above the diff analysis they control.
6. Repetition - Consistent date formatting, finding badges, and card styling.
7. White Space - Uncluttered layout with progressive disclosure for deep finding diffs.
"""

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

    st.title("⏱️ Audit History & Posture Trends")
    st.caption(
        "Track cloud security posture over time, evaluate resolved issues, "
        "and compare audit baselines."
    )

    # 1. Action Toolbar: Run New Scan or Upload External Scan (Alignment & Balance)
    with st.container(border=True):
        col_act1, col_act2 = st.columns([1, 2])
        with col_act1:
            st.markdown("#### 🚀 Trigger Audit")
            if st.button("Run Fresh Demo Scan", type="primary", use_container_width=True):
                with st.spinner("Executing simulated cloud audit..."):
                    new_scan = run_and_save_demo_scan()
                st.success(f"Executed and saved scan `{new_scan.scan_id[:8]}`!")
                st.rerun()

        with col_act2:
            st.markdown("#### 📂 Import Scan Report")
            uploaded_file = st.file_uploader(
                "Upload External Scan JSON",
                type=["json"],
                label_visibility="collapsed",
            )
            if uploaded_file is not None:
                try:
                    content = uploaded_file.read().decode("utf-8")
                    loaded_scan = Scan.model_validate_json(content)
                    set_active_scan(loaded_scan)
                    st.success(
                        f"Loaded external scan `{loaded_scan.scan_id[:8]}` into active view!"
                    )
                    st.rerun()
                except ValidationError as exc:
                    err_msg = format_validation_error(exc)
                    st.error(f"Uploaded file is not a valid Scan report: {err_msg}")
                except Exception as exc:
                    st.error(f"Failed to read file: {exc}")

    st.divider()

    if not history:
        st.info(
            "No scan history recorded yet. Click 'Run Fresh Demo Scan' above "
            "to create your first audit record."
        )
        return

    # 2. Posture Trend Over Time (Hierarchy & Visual Flow)
    if len(history) >= 2:
        st.subheader("📈 Security Posture Trend")
        st.caption("Tracking failures, gaps, and passing controls across consecutive audit runs.")

        trend_records = []
        for s in reversed(history):
            f_count = sum(1 for f in s.findings if f.status == Status.FAIL)
            e_count = sum(1 for f in s.findings if f.status == Status.ERROR)
            p_count = sum(1 for f in s.findings if f.status == Status.PASS)
            trend_records.append(
                {
                    "Timestamp": s.started_at.strftime("%m/%d %H:%M"),
                    "Failures": f_count,
                    "Visibility Gaps": e_count,
                    "Passes": p_count,
                }
            )
        trend_df = pd.DataFrame(trend_records)
        st.line_chart(
            trend_df,
            x="Timestamp",
            y=["Failures", "Visibility Gaps", "Passes"],
            color=["#ef4444", "#f59e0b", "#10b981"],
        )

    # 3. Scan History Table (Alignment & Repetition)
    st.subheader(f"📋 Recorded Audits ({len(history)} total)")
    table_data = []
    for s in history:
        fails = sum(1 for f in s.findings if f.status == Status.FAIL)
        errors = sum(1 for f in s.findings if f.status == Status.ERROR)
        passes = sum(1 for f in s.findings if f.status == Status.PASS)
        is_active = s.scan_id == active_scan.scan_id
        table_data.append(
            {
                "Status": "👉 ACTIVE" if is_active else "Archived",
                "Timestamp (UTC)": s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
                "Scan ID": s.scan_id[:8],
                "Source": s.source.value.upper(),
                "Account ID": s.account_id,
                "Inspected": s.coverage.resources_inspected,
                "Failures": fails,
                "Gaps": errors,
                "Passes": passes,
            }
        )
    st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)

    st.divider()

    # 4. Posture Diff Tool (Proximity, Contrast & Progressive Disclosure)
    st.subheader("🔍 Compare Audits (Posture Diff)")
    st.caption("Measure posture changes between any two scans to verify issue remediation.")

    if len(history) < 2:
        st.info("Record at least two scans to compare changes between audit runs.")
        return

    scan_labels = {
        s.scan_id: f"{s.started_at.strftime('%Y-%m-%d %H:%M')} ({s.scan_id[:8]})" for s in history
    }

    with st.container(border=True):
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
        st.error("Could not locate the selected scans.")
        return

    try:
        diff = compare_scans(baseline_scan, current_scan)

        # Delta metrics (Balance & Contrast)
        d1, d2, d3 = st.columns(3)
        with d1:
            st.metric(
                "New Security Issues",
                len(diff.new_findings),
                delta=f"+{len(diff.new_findings)}" if diff.new_findings else "0 new",
                delta_color="inverse",
            )
        with d2:
            st.metric(
                "Resolved Issues",
                len(diff.resolved_findings),
                delta=f"-{len(diff.resolved_findings)}" if diff.resolved_findings else "0 resolved",
                delta_color="normal",
            )
        with d3:
            st.metric(
                "Recurring / Persisting Issues",
                len(diff.recurring_findings),
                delta=f"{len(diff.recurring_findings)} persisting",
                delta_color="off",
            )

        # Detailed change breakdown
        if diff.new_findings:
            with st.expander(
                f"🚨 New Findings Introduced ({len(diff.new_findings)})",
                expanded=True,
            ):
                for f in diff.new_findings:
                    tag = f"[{f.status.value.upper()}] [{f.severity.value}]"
                    st.markdown(
                        f"- <span style='color: #ef4444; font-weight: bold;'>{tag}</span> "
                        f"`{f.rule_id}` — **{f.resource_id}**: {f.summary}",
                        unsafe_allow_html=True,
                    )

        if diff.resolved_findings:
            with st.expander(
                f"🎉 Successfully Resolved Findings ({len(diff.resolved_findings)})",
                expanded=True,
            ):
                for f in diff.resolved_findings:
                    st.markdown(
                        f"- <span style='color: #10b981; font-weight: bold;'>[RESOLVED]</span> "
                        f"`{f.rule_id}` — **{f.resource_id}**: {f.summary}",
                        unsafe_allow_html=True,
                    )

        if diff.recurring_findings:
            with st.expander(
                f"🔄 Recurring Unresolved Findings ({len(diff.recurring_findings)})",
                expanded=False,
            ):
                for f in diff.recurring_findings:
                    age_str = f.first_detected.strftime("%Y-%m-%d")
                    st.markdown(
                        f"- `{f.rule_id}` — **{f.resource_id}** (persisting since `{age_str}`)",
                    )

    except ValueError as exc:
        st.warning(f"Cannot compare selected scans: {exc}")
