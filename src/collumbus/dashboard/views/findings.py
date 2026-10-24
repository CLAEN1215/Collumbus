"""Findings page: interactive exploration, filtering, drill-down, and export."""

from collections import Counter

import streamlit as st

from collumbus.dashboard.state import get_active_scan
from collumbus.dashboard.theme import apply_theme
from collumbus.models import Finding, Severity, Status
from collumbus.reporting import export_csv, export_json

SEVERITY_OPTIONS = [s.value for s in Severity]


def render_findings() -> None:
    apply_theme()
    scan = get_active_scan()

    # 1. Nocturn Page Header
    st.markdown(
        "<h1 style='font-size: 2.3rem; font-weight: 800; color: #ffffff; "
        "margin-bottom: 2px;'>Findings</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color: #8e90a6; font-size: 0.95rem; margin-bottom: 1.5rem;'>"
        "Security evaluations against CIS AWS benchmarks &bull; "
        "Review evidence, analyze attack vectors, and apply fixes.</p>",
        unsafe_allow_html=True,
    )

    # 2. Key Metrics Row
    status_counts = Counter(f.status for f in scan.findings)
    total_f = len(scan.findings)
    fails_f = status_counts.get(Status.FAIL, 0)
    errors_f = status_counts.get(Status.ERROR, 0)
    passes_f = status_counts.get(Status.PASS, 0)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total evaluated", total_f)
    with m2:
        st.metric(
            "Security failures",
            fails_f,
            delta=f"-{fails_f} failing" if fails_f else "0",
            delta_color="inverse",
        )
    with m3:
        st.metric(
            "Visibility gaps",
            errors_f,
            delta=f"{errors_f} uninspected" if errors_f else "0",
            delta_color="off",
        )
    with m4:
        st.metric(
            "Passing controls",
            passes_f,
            delta=f"+{passes_f} verified" if passes_f else "0",
            delta_color="normal",
        )

    st.write("")

    # 3. Fast Filter Segment (Nocturn Pill Tabs)
    filter_tab = st.radio(
        "Filter by Verdict",
        options=[
            f"All ({total_f})",
            f"Failures ({fails_f})",
            f"Gaps ({errors_f})",
            f"Passes ({passes_f})",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

    # Search & Region Controls
    with st.container(border=True):
        col_s1, col_s2, col_s3 = st.columns([2, 1, 1])
        with col_s1:
            query = st.text_input(
                "Search",
                placeholder="Search by resource ID, rule ID (e.g. S3-001), or title...",
                label_visibility="collapsed",
            )
        with col_s2:
            sel_severities = st.multiselect(
                "Severity",
                options=SEVERITY_OPTIONS,
                default=SEVERITY_OPTIONS,
                label_visibility="collapsed",
                placeholder="Filter severity...",
            )
        with col_s3:
            all_regions = sorted({f.region for f in scan.findings})
            sel_regions = st.multiselect(
                "Region",
                options=all_regions,
                default=all_regions,
                label_visibility="collapsed",
                placeholder="Filter region...",
            )

    # Filter logic
    filtered: list[Finding] = []
    for f in scan.findings:
        if "Failures" in filter_tab and f.status != Status.FAIL:
            continue
        if "Gaps" in filter_tab and f.status != Status.ERROR:
            continue
        if "Passes" in filter_tab and f.status != Status.PASS:
            continue

        if sel_severities and f.severity.value not in sel_severities:
            continue
        if sel_regions and f.region not in sel_regions:
            continue

        if query:
            q = query.lower()
            text_match = (
                q in f.resource_id.lower()
                or q in f.rule_id.lower()
                or q in f.title.lower()
                or q in f.summary.lower()
            )
            if not text_match:
                continue

        filtered.append(f)

    # Results Counter & Export Toolbar
    tb_c1, tb_c2, tb_c3 = st.columns([2, 1, 1])
    with tb_c1:
        st.markdown(
            f"<div style='font-size: 0.9rem; color: #8e90a6; padding-top: 6px;'>"
            f"Showing <span style='color: #8b5cf6; font-weight: 700;'>"
            f"{len(filtered)}</span> of {total_f} findings</div>",
            unsafe_allow_html=True,
        )
    with tb_c2:
        csv_data = export_csv(scan, failures_only=False)
        st.download_button(
            "Export CSV",
            data=csv_data,
            file_name=f"columbus_scan_{scan.scan_id[:8]}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with tb_c3:
        json_data = export_json(scan)
        st.download_button(
            "Export JSON",
            data=json_data,
            file_name=f"columbus_scan_{scan.scan_id[:8]}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.write("")

    if not filtered:
        st.info("No findings match the current filter selection.")
        return

    # Finding Cards (Clean Nocturn Dark Style)
    for f in filtered:
        card_title = f"[{f.status.value.upper()}] [{f.severity.value}] {f.rule_id}: {f.resource_id}"

        with st.expander(
            card_title,
            expanded=(f.status == Status.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH)),
        ):
            st.markdown(f"### {f.title}")
            st.markdown(
                f"<div style='color: #d4d4d8; font-size: 0.9rem; margin-bottom: 12px;'>"
                f"<b>Verdict:</b> {f.summary}</div>",
                unsafe_allow_html=True,
            )

            # Metadata grid
            with st.container(border=True):
                meta1, meta2, meta3, meta4 = st.columns(4)
                with meta1:
                    st.caption(f"**Resource:** `{f.resource_id}`")
                    st.caption(f"**Type:** `{f.resource_type}`")
                with meta2:
                    st.caption(f"**Region:** `{f.region}`")
                    st.caption(f"**Account:** `{f.account_id}`")
                with meta3:
                    st.caption(f"**Rule:** `{f.rule_id}`")
                    st.caption(f"**Severity:** `{f.severity.value}`")
                with meta4:
                    detected_str = f.first_detected.strftime("%Y-%m-%d %H:%M UTC")
                    st.caption(f"**First Seen:** `{detected_str}`")
                    st.caption(f"**Finding ID:** `{f.finding_id[:8]}...`")

            # Risk & Threat Model
            if f.risk:
                st.markdown(
                    "<div style='background: #181928; border-left: 3px solid #fb7185; "
                    "border-radius: 0 10px 10px 0; padding: 12px 16px; margin: 12px 0;'>"
                    "<div style='font-size: 0.8rem; font-weight: 700; color: #fb7185; "
                    "text-transform: uppercase; margin-bottom: 4px;'>Threat Scenario</div>"
                    f"<div style='font-size: 0.85rem; color: #d4d4d8;'>{f.risk}</div>"
                    "</div>",
                    unsafe_allow_html=True,
                )

            # Remediation Guidance
            if f.remediation:
                st.markdown(
                    "<span style='font-size: 0.85rem; font-weight: 700; color: #ffffff;'>"
                    "Remediation Command:</span>",
                    unsafe_allow_html=True,
                )
                st.code(f.remediation, language="text")

            # Progressive disclosure: Raw Evidence and References
            if f.evidence:
                with st.expander("Technical Evidence", expanded=False):
                    st.json(f.evidence)

            if f.references:
                with st.expander("Benchmark References", expanded=False):
                    for url in f.references:
                        st.markdown(f"- [{url}]({url})")
