"""Overview page: executive audit summary and posture metrics."""

from collections import Counter

import altair as alt
import pandas as pd
import streamlit as st

from collumbus.dashboard.state import get_active_scan
from collumbus.dashboard.theme import apply_theme
from collumbus.models import Severity, Source, Status

STATUS_ORDER = [Status.FAIL, Status.ERROR, Status.PASS, Status.NOT_APPLICABLE]
SEVERITY_ORDER = list(reversed(Severity))
SEVERITY_ORDER_NAMES = [s.value for s in SEVERITY_ORDER]

STATUS_COLORS = {
    "Fail": "#ef4444",
    "Error": "#f59e0b",
    "Pass": "#10b981",  # nosec B105
    "Not Applicable": "#9ca3af",
}

SEVERITY_COLORS = {
    "Critical": "#991b1b",
    "High": "#ef4444",
    "Medium": "#f59e0b",
    "Low": "#3b82f6",
    "Informational": "#6b7280",
}


def render_overview() -> None:
    apply_theme()
    scan = get_active_scan()

    st.title("🧭 Executive Audit Overview")
    st.caption("High-level security posture, compliance indicators, and priority action items.")

    if scan.source == Source.DEMO:
        st.info(
            "ℹ️ **Simulated Data**: Displaying fictional demo resources, not a live AWS account. "
            "Run `python -m collumbus aws-scan` to audit real cloud infrastructure."
        )

    # Top metadata row
    col_meta1, col_meta2, col_meta3, col_meta4 = st.columns(4)
    with col_meta1:
        st.metric("Account ID", scan.account_id)
    with col_meta2:
        st.metric("Regions", ", ".join(scan.regions))
    with col_meta3:
        st.metric("Scan Time (UTC)", scan.started_at.strftime("%Y-%m-%d %H:%M"))
    with col_meta4:
        st.metric("Scan ID", f"{scan.scan_id[:8]}...")

    # Completion status banner
    if scan.is_complete:
        st.success(
            "✅ **Audit Complete**: All requested categories and regions were fully inspected."
        )
    else:
        gap_count = len(scan.coverage.gaps)
        err_count = sum(1 for f in scan.findings if f.status == Status.ERROR)
        st.warning(
            f"⚠️ **Audit Incomplete**: {gap_count} coverage gap(s) and {err_count} rule error(s) "
            "detected. Unchecked areas are **NOT** passes."
        )

    st.divider()

    # Core Metric Counters
    status_counts = Counter(f.status for f in scan.findings)
    fails = status_counts.get(Status.FAIL, 0)
    errors = status_counts.get(Status.ERROR, 0)
    passes = status_counts.get(Status.PASS, 0)

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("Resources Checked", scan.coverage.resources_inspected)
    with m2:
        st.metric("Total Findings", len(scan.findings))
    with m3:
        st.metric("Failures", fails, delta=f"-{fails}" if fails else "0", delta_color="inverse")
    with m4:
        st.metric(
            "Errors / Gaps",
            errors,
            delta=f"{errors} uninspected" if errors else "0",
            delta_color="off",
        )
    with m5:
        st.metric("Passes", passes)

    st.divider()

    # Visualizations
    st.subheader("Security Posture Visualizations")
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("**Findings by Verdict**")
        status_df = pd.DataFrame(
            [
                {"Status": s.value, "Count": status_counts.get(s, 0)}
                for s in STATUS_ORDER
                if status_counts.get(s, 0) > 0
            ]
        )
        if not status_df.empty:
            status_chart = (
                alt.Chart(status_df)
                .mark_arc(innerRadius=45, cornerRadius=4)
                .encode(
                    theta=alt.Theta(field="Count", type="quantitative"),
                    color=alt.Color(
                        field="Status",
                        type="nominal",
                        scale=alt.Scale(
                            domain=list(STATUS_COLORS.keys()),
                            range=list(STATUS_COLORS.values()),
                        ),
                        legend=alt.Legend(title="Verdict", orient="bottom"),
                    ),
                    tooltip=["Status", "Count"],
                )
                .properties(height=260)
            )
            st.altair_chart(status_chart, use_container_width=True)
        else:
            st.write("No findings to display.")

    with chart_col2:
        st.markdown("**Failing Issues by Severity**")
        fail_findings = [f for f in scan.findings if f.status == Status.FAIL]
        sev_counts = Counter(f.severity for f in fail_findings)
        sev_df = pd.DataFrame(
            [
                {"Severity": s.value, "Count": sev_counts.get(s, 0)}
                for s in SEVERITY_ORDER
                if sev_counts.get(s, 0) > 0
            ]
        )
        if not sev_df.empty:
            sev_chart = (
                alt.Chart(sev_df)
                .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
                .encode(
                    x=alt.X("Severity:N", sort=SEVERITY_ORDER_NAMES, title=None),
                    y=alt.Y("Count:Q", title="Failing Findings", axis=alt.Axis(tickMinStep=1)),
                    color=alt.Color(
                        "Severity:N",
                        scale=alt.Scale(
                            domain=list(SEVERITY_COLORS.keys()),
                            range=list(SEVERITY_COLORS.values()),
                        ),
                        legend=None,
                    ),
                    tooltip=["Severity", "Count"],
                )
                .properties(height=260)
            )
            st.altair_chart(sev_chart, use_container_width=True)
        else:
            st.success("No failing findings in this scan!")

    st.divider()

    # Urgent Action Items Callout
    st.subheader("Priority Action Items")
    urgent = [
        f
        for f in scan.findings
        if f.status == Status.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if urgent:
        for f in urgent[:5]:
            with st.expander(f"🔴 [{f.severity.value}] {f.rule_id} — {f.resource_id} ({f.region})"):
                st.markdown(f"**Issue Description:** {f.summary}")
                if f.risk:
                    st.markdown(f"**🚨 Security Risk:** {f.risk}")
                if f.remediation:
                    st.markdown("**🛠️ Recommended Fix:**")
                    st.code(f.remediation, language="text")
    else:
        st.success("No High or Critical failures detected.")
