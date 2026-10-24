"""Findings page: interactive exploration, filtering, drill-down, and export.

Built using the 7 Principles of Design:
1. Contrast - Semantic color badges (Fail/Pass/Error/Severity) with high visibility.
2. Hierarchy - Quick-filter tabs, clear problem description, threat model, and fix command.
3. Alignment - Uniform metadata columns, standard card padding, and aligned exports.
4. Balance - Top summary metric cards balanced with detailed drill-down findings.
5. Proximity - Grouped threat and remediation instructions right beside the resource ID.
6. Repetition - Standardized card structure for all security checks.
7. White Space - Uncluttered card spacing with progressive disclosure for raw logs.
"""

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

    st.title("🔍 Security Findings Explorer")
    st.caption(
        "Inspect individual audit findings, analyze threat scenarios, "
        "and get step-by-step remediation."
    )

    # 1. Summary Metric Cards (Balance & Hierarchy)
    status_counts = Counter(f.status for f in scan.findings)
    total_f = len(scan.findings)
    fails_f = status_counts.get(Status.FAIL, 0)
    errors_f = status_counts.get(Status.ERROR, 0)
    passes_f = status_counts.get(Status.PASS, 0)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Evaluated", total_f)
    with m2:
        st.metric(
            "Security Failures",
            fails_f,
            delta=f"-{fails_f}" if fails_f else "0",
            delta_color="inverse",
        )
    with m3:
        st.metric(
            "Visibility Gaps",
            errors_f,
            delta=f"{errors_f} unverified" if errors_f else "0",
            delta_color="off",
        )
    with m4:
        st.metric(
            "Passing Controls",
            passes_f,
            delta=f"+{passes_f}" if passes_f else "0",
            delta_color="normal",
        )

    st.divider()

    # 2. Fast Filter Bar & Secondary Filters (Hierarchy & Alignment)
    filter_tab = st.radio(
        "Filter by Verdict",
        options=[
            f"All Findings ({total_f})",
            f"Failures ({fails_f}) 🔴",
            f"Visibility Gaps ({errors_f}) ⚠️",
            f"Passes ({passes_f}) 🟢",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

    with st.container(border=True):
        col_s1, col_s2, col_s3 = st.columns([2, 1, 1])
        with col_s1:
            query = st.text_input(
                "Search Findings",
                placeholder="Search by resource ID, rule ID (e.g. S3-001), or title...",
                label_visibility="collapsed",
            )
        with col_s2:
            sel_severities = st.multiselect(
                "Severity Filter",
                options=SEVERITY_OPTIONS,
                default=SEVERITY_OPTIONS,
                label_visibility="collapsed",
                placeholder="Filter severity...",
            )
        with col_s3:
            all_regions = sorted({f.region for f in scan.findings})
            sel_regions = st.multiselect(
                "Region Filter",
                options=all_regions,
                default=all_regions,
                label_visibility="collapsed",
                placeholder="Filter region...",
            )

    # 3. Filter Application
    filtered: list[Finding] = []
    for f in scan.findings:
        # Verdict tab filter
        if "Failures" in filter_tab and f.status != Status.FAIL:
            continue
        if "Visibility Gaps" in filter_tab and f.status != Status.ERROR:
            continue
        if "Passes" in filter_tab and f.status != Status.PASS:
            continue

        # Severity filter
        if sel_severities and f.severity.value not in sel_severities:
            continue

        # Region filter
        if sel_regions and f.region not in sel_regions:
            continue

        # Search query
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

    # 4. Result Count & Export Actions (Alignment & Contrast)
    tb_c1, tb_c2, tb_c3 = st.columns([2, 1, 1])
    with tb_c1:
        st.markdown(
            f"**Showing <span style='color: #3b82f6; font-size: 1.15rem; font-weight: bold;'>"
            f"{len(filtered)}</span> of {total_f} findings**",
            unsafe_allow_html=True,
        )
    with tb_c2:
        csv_data = export_csv(scan, failures_only=False)
        st.download_button(
            "📥 Export CSV",
            data=csv_data,
            file_name=f"collumbus_scan_{scan.scan_id[:8]}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with tb_c3:
        json_data = export_json(scan)
        st.download_button(
            "📥 Export JSON",
            data=json_data,
            file_name=f"collumbus_scan_{scan.scan_id[:8]}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.write("")  # Generous whitespace

    if not filtered:
        st.info(
            "No findings match the current filter selection. "
            "Try selecting 'All Findings' or clearing search."
        )
        return

    # 5. Finding Cards (Repetition, Proximity, Contrast & Progressive Disclosure)
    for f in filtered:
        # Determine icon & visual indicator
        if f.status == Status.FAIL:
            icon = "🔴" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "🟡"
            status_color = "#ef4444"
        elif f.status == Status.ERROR:
            icon = "⚠️"
            status_color = "#f59e0b"
        else:
            icon = "🟢"
            status_color = "#10b981"

        card_title = (
            f"{icon} [{f.status.value.upper()}] [{f.severity.value}] {f.rule_id}: {f.resource_id}"
        )

        # Clean card expander
        with st.expander(
            card_title,
            expanded=(f.status == Status.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH)),
        ):
            st.markdown(f"### {f.title}")
            summary_html = (
                f"**Verdict Summary:** <span style='color: {status_color}; "
                f"font-weight: 600;'>{f.summary}</span>"
            )
            st.markdown(summary_html, unsafe_allow_html=True)

            # Metadata grid (Alignment & Balance)
            with st.container(border=True):
                meta1, meta2, meta3, meta4 = st.columns(4)
                with meta1:
                    st.caption(f"**Resource ID:** `{f.resource_id}`")
                    st.caption(f"**Type:** `{f.resource_type}`")
                with meta2:
                    st.caption(f"**Region:** `{f.region}`")
                    st.caption(f"**Account:** `{f.account_id}`")
                with meta3:
                    st.caption(f"**Rule ID:** `{f.rule_id}`")
                    st.caption(f"**Severity:** `{f.severity.value}`")
                with meta4:
                    detected_str = f.first_detected.strftime("%Y-%m-%d %H:%M UTC")
                    st.caption(f"**First Seen:** `{detected_str}`")
                    st.caption(f"**Finding ID:** `{f.finding_id[:8]}...`")

            # Risk & Threat Model (Proximity & Contrast)
            if f.risk:
                st.markdown("#### 🚨 Real-World Threat Scenario")
                st.info(f.risk)

            # Remediation Guidance (Proximity & Hierarchy)
            if f.remediation:
                st.markdown("#### 🛠️ Step-by-Step Remediation Command")
                st.code(f.remediation, language="text")

            # Progressive disclosure: Raw Evidence and References (White Space)
            if f.evidence:
                with st.expander("📋 Technical Evidence & Evaluated Attributes", expanded=False):
                    st.json(f.evidence)

            if f.references:
                with st.expander("🔗 Compliance References & Benchmarks", expanded=False):
                    for url in f.references:
                        st.markdown(f"- [{url}]({url})")
