"""Coverage page: transparent breakdown of inspected areas and coverage gaps."""

import json

import pandas as pd
import streamlit as st

from collumbus.dashboard.state import get_active_scan
from collumbus.dashboard.theme import apply_theme


def render_coverage() -> None:
    apply_theme()
    scan = get_active_scan()

    st.title("🛡️ Audit Coverage & Gaps")
    st.caption("A core Collumbus principle: uninspected areas are never passes.")

    st.info(
        "💡 **Why Coverage Matters**: Traditional audit tools often hide API errors or treat them "
        "as clean passes. Collumbus marks uninspected areas as coverage gaps and produces Error "
        "findings so misconfigurations are never concealed by lack of permissions."
    )

    # Metrics
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Inspected Categories", len(scan.coverage.inspected_categories))
    with c2:
        st.metric("Resources Evaluated", scan.coverage.resources_inspected)
    with c3:
        st.metric(
            "Coverage Gaps",
            len(scan.coverage.gaps),
            delta=f"{len(scan.coverage.gaps)} gaps" if scan.coverage.gaps else "0 gaps",
            delta_color="inverse" if scan.coverage.gaps else "off",
        )

    st.divider()

    # Coverage Gaps Breakdown
    st.subheader("Coverage Gaps & Blind Spots")
    if not scan.coverage.gaps:
        st.success(
            "🎉 **Zero Coverage Gaps**: Full read visibility was achieved "
            "across all requested resources."
        )
    else:
        st.warning(
            f"⚠️ **{len(scan.coverage.gaps)} area(s) could not be inspected**. "
            "Resources in these categories/regions were skipped due to access denials or "
            "rate limits."
        )

        gaps_data = [
            {
                "Category": g.category.upper(),
                "Region": g.region,
                "Resource": g.resource_id or "(all in region)",
                "Error Code": g.reason,
                "Missing Permission": g.missing_permission or "N/A",
                "Description": g.detail or "Not inspected",
            }
            for g in scan.coverage.gaps
        ]
        st.dataframe(pd.DataFrame(gaps_data), use_container_width=True, hide_index=True)

        # IAM Remediation Generator
        missing_perms = sorted(
            {g.missing_permission for g in scan.coverage.gaps if g.missing_permission}
        )
        if missing_perms:
            st.subheader("🛠️ Recommended Remediation Policy")
            st.markdown(
                "Attach this minimal read-only IAM policy to the scanning identity to resolve "
                "the permissions gaps above:"
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

    st.divider()

    # Inspected Categories
    st.subheader("Inspected Service Categories")
    cat_df = pd.DataFrame(
        [
            {"Service Category": c.upper(), "Status": "Inspected", "Coverage": "Verified"}
            for c in scan.coverage.inspected_categories
        ]
    )
    st.dataframe(cat_df, use_container_width=True, hide_index=True)
