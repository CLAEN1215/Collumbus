"""Coverage page: transparent breakdown of inspected areas and coverage gaps."""

import json

import pandas as pd
import streamlit as st

from collumbus.dashboard.state import get_active_scan
from collumbus.dashboard.theme import apply_theme


def render_coverage() -> None:
    apply_theme()
    scan = get_active_scan()
    gaps_count = len(scan.coverage.gaps)
    inspected_count = len(scan.coverage.inspected_categories)

    # 1. Nocturn Page Header
    st.markdown(
        "<h1 style='font-size: 2.3rem; font-weight: 800; color: #ffffff; "
        "margin-bottom: 2px;'>Coverage</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color: #8e90a6; font-size: 0.95rem; margin-bottom: 1.5rem;'>"
        "Audit visibility and blind spot verification &bull; "
        "Uninspected resources are never treated as clean passes.</p>",
        unsafe_allow_html=True,
    )

    # 2. Key Coverage Metrics
    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Inspected services", inspected_count)
    with m2:
        st.metric("Total resources evaluated", scan.coverage.resources_inspected)
    with m3:
        st.metric(
            "Identified coverage gaps",
            gaps_count,
            delta=f"{gaps_count} blind spots" if gaps_count else "Zero gaps",
            delta_color="inverse" if gaps_count else "normal",
        )

    st.write("")

    # 3. Posture Principle Card
    with st.container(border=True):
        col_banner1, col_banner2 = st.columns([3, 1])
        with col_banner1:
            banner_html = (
                "<div style='font-size: 1.1rem; font-weight: 700; color: #ffffff; "
                "margin-bottom: 4px;'>The Transparency Principle</div>"
                "<div style='font-size: 0.85rem; color: #8e90a6; line-height: 1.5;'>"
                "Traditional audit tools often treat API permission errors as silent "
                "passes, creating dangerous blind spots. Columbus guarantees that any "
                "inaccessible resource is flagged as an <b>Error</b> and tracked as a "
                "<b>Coverage Gap</b> until verified.</div>"
            )
            st.markdown(banner_html, unsafe_allow_html=True)
        with col_banner2:
            if gaps_count == 0:
                badge_html = (
                    "<div style='background: rgba(74, 222, 128, 0.1); "
                    "border: 1px solid rgba(74, 222, 128, 0.3); border-radius: 10px; "
                    "padding: 12px; text-align: center;'>"
                    "<div style='color: #4ade80; font-weight: 800; "
                    "font-size: 0.85rem;'>FULL VISIBILITY</div>"
                    "<div style='color: #a1a1aa; font-size: 0.75rem; "
                    "margin-top: 2px;'>100% accessible</div></div>"
                )
                st.markdown(badge_html, unsafe_allow_html=True)
            else:
                badge_html = (
                    "<div style='background: rgba(251, 191, 36, 0.1); "
                    "border: 1px solid rgba(251, 191, 36, 0.3); border-radius: 10px; "
                    "padding: 12px; text-align: center;'>"
                    "<div style='color: #fbbf24; font-weight: 800; "
                    "font-size: 0.85rem;'>GAPS DETECTED</div>"
                    f"<div style='color: #a1a1aa; font-size: 0.75rem; "
                    f"margin-top: 2px;'>{gaps_count} skipped</div></div>"
                )
                st.markdown(badge_html, unsafe_allow_html=True)

    st.write("")

    # 4. Gaps Breakdown Section
    if gaps_count > 0:
        st.markdown(
            "<h3 style='font-size: 1.25rem; font-weight: 700; color: #ffffff; margin-bottom: 4px;'>"
            "Coverage Gaps & Blind Spots</h3>",
            unsafe_allow_html=True,
        )
        st.caption("Resources skipped due to API permission denials or service throttling.")

        gaps_data = [
            {
                "Service": g.category.upper(),
                "Region": g.region,
                "Target": g.resource_id or "(all in region)",
                "Error Code": g.reason,
                "Missing Action": g.missing_permission or "N/A",
                "Impact": g.detail or "Not inspected",
            }
            for g in scan.coverage.gaps
        ]
        st.dataframe(pd.DataFrame(gaps_data), use_container_width=True, hide_index=True)

        # Minimal IAM Policy Remediation Card
        missing_perms = sorted(
            {g.missing_permission for g in scan.coverage.gaps if g.missing_permission}
        )
        if missing_perms:
            with st.container(border=True):
                head_html = (
                    "<div style='font-size: 1rem; font-weight: 700; color: #ffffff; "
                    "margin-bottom: 4px;'>Recommended Read-Only IAM Remediation Policy</div>"
                    "<div style='font-size: 0.82rem; color: #8e90a6; margin-bottom: 10px;'>"
                    "Attach this minimal policy statement to achieve 100% audit coverage:</div>"
                )
                st.markdown(head_html, unsafe_allow_html=True)

                remediation_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "ColumbusAuditCoveragePermissions",
                            "Effect": "Allow",
                            "Action": missing_perms,
                            "Resource": "*",
                        }
                    ],
                }
                st.code(json.dumps(remediation_policy, indent=2), language="json")
                st.caption(
                    "Note: Columbus strictly requires read-only actions. "
                    "No write or delete permissions are requested."
                )
    else:
        clean_html = (
            "<div style='background: #151624; "
            "border: 1px solid rgba(74, 222, 128, 0.25); "
            "border-left: 3px solid #4ade80; border-radius: 12px; "
            "padding: 14px 18px; margin: 12px 0;'>"
            "<div style='color: #4ade80; font-weight: 700; "
            "font-size: 0.9rem;'>Zero Coverage Gaps</div>"
            "<div style='color: #a1a1aa; font-size: 0.82rem; margin-top: 2px;'>"
            "Full read visibility achieved across all target services. "
            "Zero access denials encountered.</div></div>"
        )
        st.markdown(clean_html, unsafe_allow_html=True)

    st.write("")

    # 5. Inspected Services Table
    st.markdown(
        "<h3 style='font-size: 1.25rem; font-weight: 700; color: #ffffff; margin-bottom: 4px;'>"
        "Evaluated Cloud Services</h3>",
        unsafe_allow_html=True,
    )
    cat_rows = []
    for cat in scan.coverage.inspected_categories:
        cat_upper = cat.upper()
        cat_gaps = [g for g in scan.coverage.gaps if g.category.upper() == cat_upper]
        health_status = f"{len(cat_gaps)} Gaps Detected" if cat_gaps else "Verified Full Visibility"
        cat_rows.append(
            {
                "Service Category": cat_upper,
                "Inspection Status": "Evaluated",
                "Coverage Status": health_status,
            }
        )

    st.dataframe(pd.DataFrame(cat_rows), use_container_width=True, hide_index=True)
