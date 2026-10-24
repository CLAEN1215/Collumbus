"""Findings page: interactive exploration, filtering, drill-down, and export."""

import streamlit as st

from collumbus.dashboard.state import get_active_scan
from collumbus.models import Finding, Severity, Status
from collumbus.reporting import export_csv, export_json

STATUS_OPTIONS = [s.value for s in Status]
SEVERITY_OPTIONS = [s.value for s in Severity]


def render_findings() -> None:
    scan = get_active_scan()

    st.title("🔍 Findings Explorer")
    st.caption("Inspect individual findings, review evidence, and get remediation instructions.")

    # Filters
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        sel_statuses = st.multiselect(
            "Status",
            options=STATUS_OPTIONS,
            default=[Status.FAIL.value, Status.ERROR.value],
        )
    with col_f2:
        sel_severities = st.multiselect(
            "Severity",
            options=SEVERITY_OPTIONS,
            default=SEVERITY_OPTIONS,
        )
    with col_f3:
        all_regions = sorted({f.region for f in scan.findings})
        sel_regions = st.multiselect(
            "Region",
            options=all_regions,
            default=all_regions,
        )
    with col_f4:
        query = st.text_input("Search", placeholder="Filter by resource ID, rule, or keyword...")

    # Filter findings
    filtered: list[Finding] = []
    for f in scan.findings:
        if sel_statuses and f.status.value not in sel_statuses:
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

    st.markdown(f"**Showing {len(filtered)} of {len(scan.findings)} findings**")

    # Export Buttons
    exp_col1, exp_col2, _ = st.columns([1, 1, 2])
    with exp_col1:
        csv_data = export_csv(scan, failures_only=False)
        st.download_button(
            "📥 Export All as CSV",
            data=csv_data,
            file_name=f"collumbus_scan_{scan.scan_id[:8]}.csv",
            mime="text/csv",
        )
    with exp_col2:
        json_data = export_json(scan)
        st.download_button(
            "📥 Export Scan as JSON",
            data=json_data,
            file_name=f"collumbus_scan_{scan.scan_id[:8]}.json",
            mime="application/json",
        )

    st.divider()

    if not filtered:
        st.info("No findings match the current filter selection.")
        return

    # Render finding cards
    for f in filtered:
        # Determine card icon & color badge
        if f.status == Status.FAIL:
            icon = "🔴" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "🟡"
        elif f.status == Status.ERROR:
            icon = "⚠️"
        else:
            icon = "🟢"

        status_tag = f"[{f.status.value.upper()}] {f.severity.value}"
        header = f"{icon} {status_tag} — {f.rule_id}: {f.resource_id}"
        with st.expander(header):
            st.markdown(f"### {f.title}")
            st.write(f"**Verdict**: {f.summary}")

            meta_c1, meta_c2, meta_c3 = st.columns(3)
            with meta_c1:
                st.caption(f"**Resource Type:** `{f.resource_type}`")
                st.caption(f"**Resource ID:** `{f.resource_id}`")
            with meta_c2:
                st.caption(f"**Region:** `{f.region}`")
                st.caption(f"**Account:** `{f.account_id}`")
            with meta_c3:
                detected_str = f.first_detected.strftime("%Y-%m-%d %H:%M UTC")
                st.caption(f"**First Detected:** `{detected_str}`")
                st.caption(f"**Finding ID:** `{f.finding_id}`")

            if f.risk:
                st.markdown("**🚨 Security Risk**")
                st.write(f.risk)

            if f.remediation:
                st.markdown("**🛠️ Remediation Guidance**")
                st.write(f.remediation)

            if f.evidence:
                st.markdown("**📋 Evidence (Redacted)**")
                st.json(f.evidence)

            if f.references:
                st.markdown("**🔗 Documentation & References**")
                for url in f.references:
                    st.markdown(f"- [{url}]({url})")
