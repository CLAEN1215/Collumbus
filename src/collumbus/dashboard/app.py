"""Main entry point for the Collumbus Streamlit web dashboard."""

import streamlit as st

from collumbus.dashboard.state import get_active_scan, run_and_save_demo_scan
from collumbus.dashboard.views import (
    render_coverage,
    render_findings,
    render_history,
    render_overview,
    render_rules,
)
from collumbus.models import Source

st.set_page_config(
    page_title="Collumbus — Cloud Configuration Auditor",
    page_icon="🧭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Sidebar Branding and Quick Actions
with st.sidebar:
    st.markdown("## 🧭 **Collumbus**")
    st.caption("Read-only AWS Configuration Auditor")

    scan = get_active_scan()
    st.divider()

    st.markdown("### Active Audit")
    source_label = "Demo (Simulated)" if scan.source == Source.DEMO else "AWS (Live)"
    st.write(f"**Target Account:** `{scan.account_id}`")
    st.write(f"**Data Source:** `{source_label}`")
    st.write(f"**Scan ID:** `{scan.scan_id[:8]}...`")

    if scan.is_complete:
        st.success("Complete (100% Inspected)")
    else:
        st.warning("Incomplete (Gaps / Errors)")

    if st.button("🔄 Refresh Demo Scan", use_container_width=True):
        new_scan = run_and_save_demo_scan()
        st.success(f"Executed fresh scan `{new_scan.scan_id[:8]}`!")
        st.rerun()

    st.divider()
    st.caption("Collumbus Portfolio Project — Lance (BSIT)")

# Define the 5 Pages
pages = [
    st.Page(render_overview, title="Executive Overview", icon="📊", default=True),
    st.Page(render_findings, title="Findings Explorer", icon="🔍"),
    st.Page(render_coverage, title="Coverage & Gaps", icon="🛡️"),
    st.Page(render_history, title="Scan History & Trends", icon="⏱️"),
    st.Page(render_rules, title="Security Rules Catalog", icon="📋"),
]

nav = st.navigation(pages)
nav.run()
