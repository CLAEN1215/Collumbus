"""Coverage page: transparent breakdown of inspected areas and coverage gaps.

Built using the 7 Principles of Design:
1. Contrast - High-visibility alert banners for blind spots vs verified coverage.
2. Hierarchy - Core audit principle up front, key coverage metrics, then IAM remediation.
3. Alignment - Symmetrical metrics grid, aligned gap tables, and clean policy cards.
4. Balance - Equal weight given to verified coverage and uninspected areas.
5. Proximity - Missing IAM permissions paired directly with the affected cloud service.
6. Repetition - Standardized badges and card borders across all views.
7. White Space - Spacious layout with progressive disclosure for deep technical details.
"""

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

    st.title("🛡️ Audit Visibility & Coverage Gaps")
    st.caption("A core Collumbus design principle: uninspected areas are never treated as passes.")

    # 1. Posture Principle & Hero Banner (Contrast & Hierarchy)
    with st.container(border=True):
        col_banner1, col_banner2 = st.columns([3, 1])
        with col_banner1:
            st.markdown("### 💡 The Collumbus Transparency Principle")
            st.markdown(
                "Traditional cloud security tools often treat API permission errors "
                "as silent passes, creating dangerous blind spots. Collumbus guarantees "
                "that any inaccessible resource is flagged as an **Error** and logged "
                "as a **Coverage Gap** until verified."
            )
        with col_banner2:
            if gaps_count == 0:
                st.success("🟢 **Full Visibility**\n\n100% of target resources were accessible.")
            else:
                st.warning(
                    f"⚠️ **Attention Needed**\n\n{gaps_count} area(s) skipped due to missing access."
                )

    # 2. Key Coverage Metrics (Balance & Alignment)
    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Inspected Services", inspected_count)
    with m2:
        st.metric("Total Resources Evaluated", scan.coverage.resources_inspected)
    with m3:
        st.metric(
            "Identified Blind Spots",
            gaps_count,
            delta=f"{gaps_count} gaps" if gaps_count else "0 gaps",
            delta_color="inverse" if gaps_count else "off",
        )

    st.divider()

    # 3. Gaps & Blind Spots Section (Contrast, Proximity & Actionability)
    if gaps_count > 0:
        st.subheader("⚠️ Uninspected Areas (Coverage Gaps)")
        st.caption(
            "The following cloud resources could not be evaluated due to API permission "
            "denials or AWS service throttling."
        )

        gaps_data = [
            {
                "Category": g.category.upper(),
                "Region": g.region,
                "Resource Target": g.resource_id or "(all resources in region)",
                "AWS Error Code": g.reason,
                "Missing Action": g.missing_permission or "N/A",
                "Audit Impact": g.detail or "Not inspected",
            }
            for g in scan.coverage.gaps
        ]
        st.dataframe(pd.DataFrame(gaps_data), use_container_width=True, hide_index=True)

        # 4. Minimal IAM Policy Remediation Card (Hierarchy, Proximity & Contrast)
        missing_perms = sorted(
            {g.missing_permission for g in scan.coverage.gaps if g.missing_permission}
        )
        if missing_perms:
            st.write("")
            with st.container(border=True):
                st.markdown("#### 🛠️ Recommended Read-Only IAM Remediation Policy")
                st.markdown(
                    "To achieve 100% audit coverage, attach the following minimal read-only "
                    "IAM policy statement to the scanning role or user:"
                )

                remediation_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "CollumbusAuditCoveragePermissions",
                            "Effect": "Allow",
                            "Action": missing_perms,
                            "Resource": "*",
                        }
                    ],
                }
                st.code(json.dumps(remediation_policy, indent=2), language="json")
                st.caption(
                    "📌 **Security Note:** Collumbus strictly requires read-only actions "
                    "(e.g. `s3:Get*`, `iam:Get*`, `cloudtrail:Describe*`). "
                    "No write or delete permissions are ever requested."
                )

    else:
        st.success(
            "🎉 **Zero Coverage Gaps**: Full read visibility was achieved across all "
            "requested resources. No permission errors or API rate limit issues "
            "were encountered."
        )

    st.divider()

    # 5. Inspected Service Breakdown (Alignment & Repetition)
    st.subheader("📋 Verified Service Scope")
    st.caption("AWS services evaluated during this audit run:")

    cat_rows = []
    for cat in scan.coverage.inspected_categories:
        cat_upper = cat.upper()
        # Find if this category had any gaps
        cat_gaps = [g for g in scan.coverage.gaps if g.category.upper() == cat_upper]
        health_status = f"⚠️ {len(cat_gaps)} Gap(s)" if cat_gaps else "🟢 Verified Full Visibility"
        cat_rows.append(
            {
                "Cloud Service Category": cat_upper,
                "Audit Status": "Inspected",
                "Visibility Health": health_status,
            }
        )

    st.dataframe(pd.DataFrame(cat_rows), use_container_width=True, hide_index=True)
