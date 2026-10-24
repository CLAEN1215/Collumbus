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
LOGO_STACKED_PATH = BRAND_DIR / "logo_stacked.png"
LOGO_HORIZONTAL_PATH = BRAND_DIR / "logo_horizontal.png"
LOGO_PATH = Path(__file__).parent / "assets" / "logo.png"


def main() -> None:
    page_icon_obj = Image.open(FAVICON_PATH) if FAVICON_PATH.exists() else "🧭"

    st.set_page_config(
        page_title="Columbus — Cloud Security Auditor",
        page_icon=page_icon_obj,
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Apply Nocturn SaaS styling
    apply_theme()

    # Sidebar Branding (Nocturn Style)
    with st.sidebar:
        # 1. Official Vertical / Primary Block Logo (Stacked)
        if LOGO_STACKED_PATH.exists():
            st.image(str(LOGO_STACKED_PATH), use_container_width=True)
        elif LOGO_PATH.exists():
            st.image(str(LOGO_PATH), use_container_width=True)

        st.write("")

        # 2. Auditor Profile Card
        profile_html = """
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 1.25rem;">
            <div style="width: 36px; height: 36px; border-radius: 50%;
                 background: linear-gradient(135deg, #7c3aed 0%, #38bdf8 100%);
                 display: flex; align-items: center; justify-content: center;
                 font-weight: 800; font-size: 0.85rem; color: #ffffff;">LM</div>
            <div>
                <div style="font-weight: 700; font-size: 0.92rem; color: #ffffff;">
                    Lance (BSIT)
                </div>
                <div style="font-size: 0.72rem; color: #8e90a6;">auditor@columbus.sec</div>
            </div>
        </div>
        """
        st.markdown(profile_html, unsafe_allow_html=True)

        scan = get_active_scan()

        # Workspaces section (like in Nocturn)
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

        # Cloud Mode Promo Card (like "Upgrade to Growth" in Nocturn)
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
        st.caption("Columbus Portfolio Project &bull; BSIT Cloud Security")

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
