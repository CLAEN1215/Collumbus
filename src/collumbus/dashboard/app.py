"""Main entry point for the Collumbus Streamlit web dashboard."""

import streamlit as st

from collumbus.dashboard.state import (
    get_active_scan,
    get_history,
    run_and_save_demo_scan,
    set_active_scan,
)
from collumbus.dashboard.theme import apply_theme
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

# Apply global responsive stylesheet and component theme
apply_theme()

# Sidebar Branding and Quick Actions
with st.sidebar:
    st.markdown("## 🧭 **Collumbus**")
    st.caption("Read-only AWS Configuration Auditor")

    scan = get_active_scan()
    history = get_history()

    st.divider()

    st.markdown("### 🎯 Active Audit")

    if len(history) > 1:
        scan_options = [s.scan_id for s in history]
        scan_labels = {
            s.scan_id: (
                f"{s.started_at.strftime('%m/%d %H:%M')} — {s.source.value} ({s.scan_id[:8]})"
            )
            for s in history
        }

        if (
            "sidebar_scan_select" not in st.session_state
            or st.session_state["sidebar_scan_select"] not in scan_labels
        ):
            st.session_state["sidebar_scan_select"] = scan.scan_id

        def _handle_scan_switch() -> None:
            chosen_id = st.session_state.get("sidebar_scan_select")
            if chosen_id:
                chosen = next((s for s in history if s.scan_id == chosen_id), None)
                if chosen:
                    set_active_scan(chosen)

        st.selectbox(
            "Select Scan",
            options=scan_options,
            key="sidebar_scan_select",
            format_func=lambda x: scan_labels.get(x, x),
            on_change=_handle_scan_switch,
            label_visibility="collapsed",
        )

    source_label = "Demo (Simulated)" if scan.source == Source.DEMO else "AWS (Live)"
    st.write(f"**Target Account:** `{scan.account_id}`")
    st.write(f"**Data Source:** `{source_label}`")
    st.write(f"**Scan ID:** `{scan.scan_id[:8]}...`")

    if scan.is_complete:
        st.success("✅ Complete (100% Inspected)")
    else:
        st.warning("⚠️ Incomplete (Gaps / Errors)")

    if st.button("🔄 Run New Demo Scan", use_container_width=True, type="primary"):
        with st.spinner("Executing simulated audit..."):
            new_scan = run_and_save_demo_scan()
            st.session_state["sidebar_scan_select"] = new_scan.scan_id
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
