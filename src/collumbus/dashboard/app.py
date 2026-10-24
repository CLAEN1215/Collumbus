"""Main entry point for the Columbus Streamlit web dashboard in Nocturn SaaS style."""

from pathlib import Path

import streamlit as st
from PIL import Image

from collumbus.dashboard.state import get_active_scan, run_and_save_demo_scan
from collumbus.dashboard.theme import apply_theme, render_header
from collumbus.dashboard.views import (
    render_coverage,
    render_findings,
    render_history,
    render_overview,
    render_rules,
)
from collumbus.models import Source

BRAND_DIR = Path(__file__).parent / "assets" / "brand"
FAVICON_PATH = BRAND_DIR / "favicon.png"
LOGO_HORIZONTAL_PATH = BRAND_DIR / "logo_horizontal.png"
LOGO_COMPACT_PATH = BRAND_DIR / "logo_compact.png"


def main() -> None:
    # 1. Official Browser Tab Favicon
    page_icon_obj = Image.open(FAVICON_PATH) if FAVICON_PATH.exists() else "🧭"

    st.set_page_config(
        page_title="Columbus — Cloud Security Auditor",
        page_icon=page_icon_obj,
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # 2. Official Sidebar Logo (renders at top of sidebar above navigation)
    if LOGO_HORIZONTAL_PATH.exists():
        st.logo(str(LOGO_HORIZONTAL_PATH), icon_image=str(FAVICON_PATH))

    # 3. Apply Nocturn SaaS styling
    apply_theme()

    # 4. Sidebar Content (Scope, Mode & Actions — Zero mock user)
    with st.sidebar:
        scan = get_active_scan()

        st.markdown(
            "<div style='font-size: 0.75rem; font-weight: 700; color: #71717a; "
            "letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 6px;'>"
            "Workspaces</div>",
            unsafe_allow_html=True,
        )
        source_label = "Demo Environment" if scan.source == Source.DEMO else "AWS Live Account"
        st.markdown(
            f"<div style='font-size: 0.82rem; color: #d4d4d8; line-height: 1.6;'>"
            f"&bull; <b>Target:</b> {source_label}<br/>"
            f"&bull; <b>Account:</b> {scan.account_id}<br/>"
            f"&bull; <b>Regions:</b> {', '.join(scan.regions)}<br/>"
            f"</div>",
            unsafe_allow_html=True,
        )

        st.write("")

        # Cloud Mode Promo Card
        promo_html = """
        <div class="sidebar-promo-card">
            <div class="sidebar-promo-title">⚡ AWS Cloud Mode</div>
            <div class="sidebar-promo-desc">
                Zero-credential scanning via IMDSv2. Read-only least-privilege security audit.
            </div>
        </div>
        """
        st.markdown(promo_html, unsafe_allow_html=True)

        if st.button("🚀 Run New Scan", use_container_width=True, type="primary"):
            with st.spinner("Executing simulated audit..."):
                new_scan = run_and_save_demo_scan()
            st.success(f"Executed fresh scan `{new_scan.scan_id[:8]}`!")
            st.rerun()

        st.divider()
        st.caption("Columbus v0.1.0 &bull; Read-Only Cloud Security Auditor")

    # Define the 5 Pages
    pages = [
        st.Page(render_overview, title="Overview", icon="📊", default=True),
        st.Page(render_findings, title="Findings", icon="🔍"),
        st.Page(render_coverage, title="Coverage", icon="🛡️"),
        st.Page(render_history, title="History", icon="⏱️"),
        st.Page(render_rules, title="Rules", icon="📋"),
    ]

    # Branded Nocturn top SaaS navbar
    render_header()

    nav = st.navigation(pages)
    nav.run()


if __name__ == "__main__":
    main()
