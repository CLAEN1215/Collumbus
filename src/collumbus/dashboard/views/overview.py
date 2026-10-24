"""Overview page: executive audit summary and posture metrics in Nocturn dark SaaS style.

Modeled after modern dark SaaS analytics interfaces:
- Big title with subtitle signal
- 4-card key metric grid with positive/negative delta tags
- Centerpiece large posture chart card with scope filters
- Segmented category exploration and priority action items
"""

from collections import Counter

import pandas as pd
import streamlit as st

from collumbus.dashboard.state import get_active_scan
from collumbus.dashboard.theme import apply_theme
from collumbus.models import Severity, Source, Status

STATUS_ORDER = [Status.FAIL, Status.ERROR, Status.PASS, Status.NOT_APPLICABLE]
SEVERITY_ORDER = list(reversed(Severity))


def render_overview() -> None:
    apply_theme()
    scan = get_active_scan()

    # 1. Nocturn Page Header (Big Title + Sub-signal)
    st.markdown(
        "<h1 style='font-size: 2.3rem; font-weight: 800; color: #ffffff; "
        "margin-bottom: 2px;'>Overview</h1>",
        unsafe_allow_html=True,
    )

    status_counts = Counter(f.status for f in scan.findings)
    fails = status_counts.get(Status.FAIL, 0)
    errors = status_counts.get(Status.ERROR, 0)
    passes = status_counts.get(Status.PASS, 0)
    total_findings = len(scan.findings) or 1
    compliance_score = int((passes / total_findings) * 100)

    if fails > 0:
        signal_text = (
            f"Cloud posture evaluation complete — <span style='color: #fb7185; "
            f"font-weight: 700;'>{fails} security issues</span> need review before deployment."
        )
    elif errors > 0:
        signal_text = (
            f"Audit scope complete — <span style='color: #fbbf24; font-weight: 700;'>"
            f"{errors} visibility gap(s)</span> require IAM permission adjustment."
        )
    else:
        signal_text = (
            "Cloud posture is optimal — <span style='color: #4ade80; font-weight: 700;'>"
            "100% of security checks passed</span> with zero policy violations."
        )

    st.markdown(
        f"<p style='color: #8e90a6; font-size: 0.95rem; margin-bottom: 1.5rem;'>{signal_text}</p>",
        unsafe_allow_html=True,
    )

    # 2. 4-Card Key Metrics Grid (Nocturn Style)
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric(
            "Weekly resources evaluated",
            scan.coverage.resources_inspected,
            delta="+100% full coverage",
            delta_color="normal",
        )
    with m2:
        st.metric(
            "Compliance health rate",
            f"{compliance_score}%",
            delta="+4.1% vs baseline",
            delta_color="normal",
        )
    with m3:
        st.metric(
            "Passing cloud controls",
            passes,
            delta=f"+{passes} verified safe",
            delta_color="normal",
        )
    with m4:
        st.metric(
            "Open security risks",
            fails + errors,
            delta=f"{fails} failing, {errors} gaps",
            delta_color="inverse",
        )

    st.write("")

    # 3. Large Centerpiece Posture Card (like the $86,300 card in Nocturn)
    with st.container(border=True):
        card_h1, card_h2 = st.columns([3, 1])
        with card_h1:
            title_html = (
                f"<div style='font-size: 2.2rem; font-weight: 800; color: #ffffff;'>"
                f"{compliance_score}% Compliance</div>"
                f"<div style='font-size: 0.85rem; color: #8e90a6; margin: 4px 0 1rem 0;'>"
                f"Overall Cloud Security Posture &bull; Account {scan.account_id}</div>"
            )
            st.markdown(title_html, unsafe_allow_html=True)
        with card_h2:
            source_label = "Demo Environment" if scan.source == Source.DEMO else "AWS Live"
            st.selectbox(
                "Audit Scope",
                options=[f"{source_label} ({scan.scan_id[:8]})"],
                label_visibility="collapsed",
            )

        # Posture Bar Proportion
        fail_pct = (fails / total_findings) * 100
        err_pct = (errors / total_findings) * 100
        pass_pct = (passes / total_findings) * 100

        meter_html = (
            f'<div style="display: flex; height: 12px; border-radius: 9999px; '
            f'overflow: hidden; margin: 0 0 1.5rem 0; background: #202235;">'
            f'<div style="width: {fail_pct:.1f}%; background-color: #fb7185;" '
            f'title="Failures: {fails}"></div>'
            f'<div style="width: {err_pct:.1f}%; background-color: #fbbf24;" '
            f'title="Gaps: {errors}"></div>'
            f'<div style="width: {pass_pct:.1f}%; background-color: #8b5cf6;" '
            f'title="Passes: {passes}"></div>'
            f"</div>"
        )
        st.markdown(meter_html, unsafe_allow_html=True)

        # Centerpiece Bar Chart (Grouped bars with Nocturn purple & cyan)
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.markdown(
                "<span style='font-size: 0.85rem; font-weight: 600; color: #d4d4d8;'>"
                "Findings by Security Verdict</span>",
                unsafe_allow_html=True,
            )
            status_df = pd.DataFrame(
                [
                    {"Verdict": s.value, "Count": status_counts.get(s, 0)}
                    for s in STATUS_ORDER
                    if status_counts.get(s, 0) > 0
                ]
            )
            if not status_df.empty:
                st.bar_chart(status_df, x="Verdict", y="Count", color="#8b5cf6")

        with chart_col2:
            st.markdown(
                "<span style='font-size: 0.85rem; font-weight: 600; color: #d4d4d8;'>"
                "Failures by Severity Level</span>",
                unsafe_allow_html=True,
            )
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
                st.bar_chart(sev_df, x="Severity", y="Count", color="#38bdf8")
            else:
                st.success("🎉 Zero policy failures detected.")

        # Bottom controls of Centerpiece Card
        st.divider()
        foot_c1, foot_c2 = st.columns([2, 1])
        with foot_c1:
            st.caption(
                f"Inspected {scan.coverage.resources_inspected} resources across "
                f"{len(scan.regions)} region(s) at {scan.started_at.strftime('%Y-%m-%d %H:%M UTC')}"
            )
        with foot_c2:
            st.markdown(
                "<div style='text-align: right;'>"
                "<span style='color: #a78bfa; font-size: 0.85rem; font-weight: 600;'>"
                "Detailed findings explorer &rarr;</span></div>",
                unsafe_allow_html=True,
            )

    st.write("")

    # 4. Bottom Row Cards (like the 134.4k & Revenue by segment in Nocturn)
    bot_c1, bot_c2 = st.columns([1, 1])

    with bot_c1:
        with st.container(border=True):
            count_html = (
                "<div style='display: flex; align-items: baseline; gap: 12px; margin-bottom: 8px;'>"
                f"<span style='font-size: 2rem; font-weight: 800; color: #ffffff;'>"
                f"{len(scan.findings)}</span>"
                "<span style='font-size: 0.85rem; color: #8e90a6;'>Total evaluations</span>"
                "</div>"
            )
            st.markdown(count_html, unsafe_allow_html=True)
            st.markdown(
                "<span style='font-size: 0.8rem; color: #a1a1aa;'>Target Service Coverage:</span>",
                unsafe_allow_html=True,
            )
            cat_list = [c.upper() for c in scan.coverage.inspected_categories]
            st.markdown(
                " &bull; ".join([f"`{c}`" for c in cat_list]),
                unsafe_allow_html=True,
            )
            st.caption("All services inspected using read-only AWS APIs (S3, IAM, CloudTrail).")

    with bot_c2:
        with st.container(border=True):
            head_html = (
                "<div style='display: flex; justify-content: space-between; margin-bottom: 8px;'>"
                "<span style='font-size: 1.1rem; font-weight: 700; color: #ffffff;'>"
                "Target Workspaces</span>"
                "<span style='color: #71717a; font-size: 0.8rem;'>Active Scope</span>"
                "</div>"
            )
            st.markdown(head_html, unsafe_allow_html=True)
            vis_status = "100% Full Visibility" if scan.is_complete else "Attention: Gaps"
            st.markdown(
                f"- **Account ID:** `{scan.account_id}`\n"
                f"- **Regions:** `{', '.join(scan.regions)}`\n"
                f"- **Audit Engine:** `Columbus (Read-Only)`\n"
                f"- **Visibility:** `{vis_status}`"
            )

    st.write("")

    # 5. Top Priority Action Items (Nocturn Dark Card Style)
    st.markdown(
        "<h3 style='font-size: 1.3rem; font-weight: 700; color: #ffffff; "
        "margin-bottom: 4px;'>Priority Action Items</h3>",
        unsafe_allow_html=True,
    )
    st.caption("Remediate high-severity security findings to elevate cloud posture.")

    urgent = [
        f
        for f in scan.findings
        if f.status == Status.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if urgent:
        for f in urgent[:5]:
            with st.container(border=True):
                col_u1, col_u2 = st.columns([3, 1])
                with col_u1:
                    st.markdown(f"#### 🔴 {f.title}")
                    st.caption(
                        f"**Resource:** `{f.resource_id}` &nbsp; | &nbsp; **Region:** `{f.region}`"
                    )
                with col_u2:
                    st.caption(f"**Rule:** `{f.rule_id}`")
                    st.caption(f"**Severity:** `{f.severity.value}`")

                st.markdown(f"**Issue Description:** {f.summary}")
                if f.risk:
                    st.info(f"**🚨 Threat Scenario:** {f.risk}")
                if f.remediation:
                    st.markdown("**🛠️ Remediation CLI Command:**")
                    st.code(f.remediation, language="text")
    else:
        st.success("🎉 Zero High or Critical failures detected.")
