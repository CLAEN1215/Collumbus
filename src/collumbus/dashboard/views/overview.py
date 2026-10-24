"""Overview page: executive audit summary and posture metrics."""

from collections import Counter

import pandas as pd
import streamlit as st

from collumbus.dashboard.state import get_active_scan
from collumbus.models import Severity, Source, Status

STATUS_ORDER = [Status.FAIL, Status.ERROR, Status.PASS, Status.NOT_APPLICABLE]
SEVERITY_ORDER = list(reversed(Severity))


def render_overview() -> None:
    scan = get_active_scan()

    st.title("🧭 Audit Overview")

    if scan.source == Source.DEMO:
        st.info(
            "ℹ️ **Simulated Data**: Displaying fictional demo resources, not a live AWS account."
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
        st.metric("Fails", fails, delta=f"-{fails}" if fails else "0", delta_color="inverse")
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
    st.subheader("Posture Distribution")
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
            st.bar_chart(status_df.set_index("Status"), color="#ff4b4b")
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
            st.bar_chart(sev_df.set_index("Severity"), color="#ffa421")
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
                st.write(f"**Issue**: {f.summary}")
                st.write(f"**Risk**: {f.risk}")
                st.write(f"**Fix**: {f.remediation}")
    else:
        st.success("No High or Critical failures detected.")
