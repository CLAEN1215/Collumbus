"""Overview page: executive audit summary and posture metrics.

Built using the 7 Principles of Design:
1. Contrast - High-visibility status chips, clear differentiation between risks and passes.
2. Hierarchy - Prominent health scorecard, distinct typography sizes, natural visual flow.
3. Alignment - Consistent grid, standardized card margins and padding.
4. Balance - Symmetrical metric distribution and harmonious layout.
5. Proximity - Logical grouping of threat descriptions, fixes, and metadata.
6. Repetition - Consistent card templates and iconography across views.
7. White Space - Uncluttered layouts with generous breathing room.
"""

from collections import Counter

import pandas as pd
import streamlit as st

from collumbus.dashboard.state import get_active_scan
from collumbus.dashboard.theme import apply_theme
from collumbus.models import Severity, Source, Status

STATUS_ORDER = [Status.FAIL, Status.ERROR, Status.PASS, Status.NOT_APPLICABLE]
SEVERITY_ORDER = list(reversed(Severity))
SEVERITY_ORDER_NAMES = [s.value for s in SEVERITY_ORDER]


def render_overview() -> None:
    apply_theme()
    scan = get_active_scan()

    st.title("🧭 Cloud Security Posture Overview")
    st.caption("Executive audit summary, compliance health score, and prioritized action items.")

    if scan.source == Source.DEMO:
        st.info(
            "ℹ️ **Simulated Audit Environment**: Displaying demo cloud resources "
            "for safe evaluation. To audit a live AWS account, run `python -m collumbus aws-scan`."
        )

    # 1. Executive Status & Posture Score (Hierarchy & Contrast)
    status_counts = Counter(f.status for f in scan.findings)
    fails = status_counts.get(Status.FAIL, 0)
    errors = status_counts.get(Status.ERROR, 0)
    passes = status_counts.get(Status.PASS, 0)
    total_findings = len(scan.findings) or 1
    compliance_score = int((passes / total_findings) * 100)

    if scan.is_complete and fails == 0:
        st.success(
            f"🛡️ **Security Status: Excellent ({compliance_score}% Compliance)** — "
            "All cloud checks passed with zero policy violations."
        )
    elif fails > 0:
        st.error(
            f"🚨 **Security Status: Attention Required ({compliance_score}% Compliance)** — "
            f"Detected {fails} failing security check(s) and {errors} visibility gap(s)."
        )
    else:
        st.warning(
            f"⚠️ **Security Status: Visibility Incomplete ({compliance_score}% Compliance)** — "
            f"{errors} check(s) could not be verified due to missing IAM permissions."
        )

    # 2. Key Metrics Row (Balance & Alignment)
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("Total Inspected", scan.coverage.resources_inspected)
    with m2:
        st.metric("Total Findings", len(scan.findings))
    with m3:
        st.metric(
            "Security Failures",
            fails,
            delta=f"-{fails}" if fails else "0",
            delta_color="inverse",
        )
    with m4:
        st.metric(
            "Visibility Gaps",
            errors,
            delta=f"{errors} unverified" if errors else "0",
            delta_color="off",
        )
    with m5:
        st.metric(
            "Passing Controls",
            passes,
            delta=f"+{passes}" if passes else "0",
            delta_color="normal",
        )

    # 3. Posture Proportion Meter (Contrast & Visual Flow)
    fail_pct = (fails / total_findings) * 100
    err_pct = (errors / total_findings) * 100
    pass_pct = (passes / total_findings) * 100

    meter_html = (
        f'<div style="display: flex; height: 16px; border-radius: 9999px; '
        f'overflow: hidden; margin: 12px 0 20px 0; background: #e2e8f0;">'
        f'<div style="width: {fail_pct:.1f}%; background-color: #ef4444;" '
        f'title="Failures: {fails}"></div>'
        f'<div style="width: {err_pct:.1f}%; background-color: #f59e0b;" '
        f'title="Gaps: {errors}"></div>'
        f'<div style="width: {pass_pct:.1f}%; background-color: #10b981;" '
        f'title="Passes: {passes}"></div>'
        f"</div>"
    )
    st.markdown(meter_html, unsafe_allow_html=True)

    # 4. Target Environment Metadata (Proximity & White Space)
    with st.container(border=True):
        st.markdown("#### 🎯 Target Audit Scope")
        meta1, meta2, meta3, meta4 = st.columns(4)
        with meta1:
            st.metric("Target Account", scan.account_id)
        with meta2:
            st.metric("Regions Audited", len(scan.regions), help=", ".join(scan.regions))
        with meta3:
            st.metric("Scan Time (UTC)", scan.started_at.strftime("%H:%M:%S"))
        with meta4:
            st.metric("Audit ID", f"{scan.scan_id[:8]}...")

    st.divider()

    # 5. Visual Posture Charts (Balance & Alignment)
    st.subheader("📊 Posture Distribution Breakdown")
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("**Checks by Security Verdict**")
        status_df = pd.DataFrame(
            [
                {"Verdict": s.value, "Count": status_counts.get(s, 0)}
                for s in STATUS_ORDER
                if status_counts.get(s, 0) > 0
            ]
        )
        if not status_df.empty:
            st.bar_chart(status_df, x="Verdict", y="Count", color="#ef4444")
        else:
            st.write("No findings to display.")

    with chart_col2:
        st.markdown("**Failing Checks by Severity**")
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
            st.bar_chart(sev_df, x="Severity", y="Count", color="#f59e0b")
        else:
            st.success("🎉 No policy failures detected in this audit!")

    st.divider()

    # 6. Priority Action Items (Proximity, Contrast & Progressive Disclosure)
    st.subheader("⚡ Top Priority Action Items")
    st.caption(
        "Address these high-severity findings first to immediately improve your cloud posture."
    )

    urgent = [
        f
        for f in scan.findings
        if f.status == Status.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if urgent:
        for f in urgent[:5]:
            with st.container(border=True):
                col_h1, col_h2 = st.columns([3, 1])
                with col_h1:
                    st.markdown(f"### 🔴 {f.title}")
                    st.caption(
                        f"**Resource:** `{f.resource_id}` &nbsp; | &nbsp; **Region:** `{f.region}`"
                    )
                with col_h2:
                    st.caption(f"**Rule:** `{f.rule_id}`")
                    st.caption(f"**Severity:** `{f.severity.value}`")

                st.markdown(f"**Issue Description:** {f.summary}")
                if f.risk:
                    st.info(f"**🚨 Real-World Threat:** {f.risk}")
                if f.remediation:
                    st.markdown("**🛠️ Recommended Fix Command:**")
                    st.code(f.remediation, language="text")
    else:
        st.success("🎉 Zero High or Critical failures detected.")
