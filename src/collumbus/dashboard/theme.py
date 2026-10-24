"""Nocturn-style modern SaaS dark theme, responsive CSS, and component helpers.

Harmonized with the Nocturn dark SaaS analytics design system:
- Base Canvas: #0d0e15 (Obsidian Slate)
- Sidebar Canvas: #11121d
- Card Surface: #161726
- Card Border: 1px solid rgba(255, 255, 255, 0.07)
- Primary Accent: #8b5cf6 (Electric Violet)
- Secondary Accent: #38bdf8 (Sky Cyan)
- Positive Delta: #4ade80 (Mint Green)
- Negative Delta: #fb7185 (Rose Pink)
- Monospace Typography: 'JetBrains Mono', 'Fira Code', monospace
"""

import base64
from pathlib import Path

import streamlit as st

from collumbus.models import Severity, Status

ASSETS_DIR = Path(__file__).parent / "assets"
LOGO_FILE = ASSETS_DIR / "logo.png"


def apply_theme() -> None:
    """Inject Nocturn-style dark SaaS theme and responsive CSS."""
    st.markdown(
        """
        <style>
        /* Import Google JetBrains Mono */
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&display=swap');

        /* Universal Monospace Typography */
        html, body, [class*="css"], .stMarkdown, p, span, label, div,
        input, select, textarea, button, code, pre, table, th, td {
            font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
            font-feature-settings: "zero" 1, "liga" 1;
        }

        /* Canvas constraints */
        .main .block-container {
            padding-top: 1rem;
            padding-bottom: 3.5rem;
            max-width: 1240px;
        }

        /* Top SaaS Navigation Bar (Nocturn Style) */
        .nocturn-top-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #11121d;
            border: 1px solid rgba(255, 255, 255, 0.07);
            border-radius: 14px;
            padding: 8px 16px;
            margin-bottom: 1.25rem;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
        }
        .nocturn-brand-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .nocturn-brand-name {
            font-weight: 700;
            font-size: 0.95rem;
            color: #ffffff;
            letter-spacing: 0.02em;
        }
        .nocturn-search-pill {
            background: #161726;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 9999px;
            padding: 5px 14px;
            font-size: 0.78rem;
            color: #71717a;
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 240px;
        }
        .nocturn-actions-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .nocturn-user-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            background: #161726;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 9999px;
            padding: 4px 12px 4px 4px;
            font-size: 0.76rem;
            color: #e4e4e7;
            font-weight: 600;
        }
        .nocturn-user-avatar {
            width: 22px;
            height: 22px;
            border-radius: 50%;
            background: #3f3f46;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.65rem;
            font-weight: 800;
            color: #ffffff;
        }

        /* Metric Cards (Nocturn Rounded Dark Card) */
        div[data-testid="stMetric"] {
            background: #161726 !important;
            border: 1px solid rgba(255, 255, 255, 0.07) !important;
            border-radius: 16px !important;
            padding: 18px 20px !important;
            box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25) !important;
            transition: all 0.2s ease !important;
        }
        div[data-testid="stMetric"]:hover {
            border-color: rgba(139, 92, 246, 0.35) !important;
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.45) !important;
        }
        div[data-testid="stMetricLabel"] {
            font-size: 0.78rem !important;
            font-weight: 500 !important;
            text-transform: none !important;
            letter-spacing: 0.02em !important;
            color: #8e90a6 !important;
        }
        div[data-testid="stMetricValue"] {
            font-size: 2rem !important;
            font-weight: 800 !important;
            color: #ffffff !important;
            margin: 4px 0 !important;
        }

        /* Card Containers */
        div[data-testid="stVerticalBlock"] > div[data-testid="stContainer"] {
            border: 1px solid rgba(255, 255, 255, 0.07) !important;
            background: #161726 !important;
            border-radius: 16px !important;
            padding: 18px 20px !important;
        }

        /* Expander Styling */
        div[data-testid="stExpander"] {
            background: #161726 !important;
            border: 1px solid rgba(255, 255, 255, 0.07) !important;
            border-radius: 14px !important;
            margin-bottom: 0.75rem !important;
            transition: border-color 0.2s ease !important;
        }
        div[data-testid="stExpander"]:hover {
            border-color: rgba(139, 92, 246, 0.3) !important;
        }
        div[data-testid="stExpander"] summary {
            font-weight: 600 !important;
            font-size: 0.9rem !important;
        }

        /* Alert Styling Overhaul (No bright blue or yellow banners) */
        div[data-testid="stAlert"] {
            background: #151624 !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            border-radius: 12px !important;
            padding: 14px 18px !important;
        }
        div[data-testid="stAlert"] * {
            color: #e4e4e7 !important;
        }
        /* Color-accented left borders */
        div[data-testid="stAlert"]:has(svg[data-testid="stIconInfo"]) {
            border-left: 3px solid #8b5cf6 !important;
        }
        div[data-testid="stAlert"]:has(svg[data-testid="stIconSuccess"]) {
            border-left: 3px solid #4ade80 !important;
        }
        div[data-testid="stAlert"]:has(svg[data-testid="stIconWarning"]) {
            border-left: 3px solid #fbbf24 !important;
        }
        div[data-testid="stAlert"]:has(svg[data-testid="stIconError"]) {
            border-left: 3px solid #fb7185 !important;
        }

        /* Pill Badges (Modern SaaS Minimalist) */
        .badge {
            display: inline-block;
            padding: 2px 9px;
            font-size: 0.7rem;
            font-weight: 700;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            vertical-align: middle;
            margin-right: 6px;
            line-height: 1.4;
            font-family: 'JetBrains Mono', monospace !important;
        }
        .badge-fail {
            background-color: rgba(244, 63, 94, 0.16);
            color: #fb7185;
            border: 1px solid rgba(244, 63, 94, 0.35);
        }
        .badge-pass {
            background-color: rgba(74, 222, 128, 0.14);
            color: #4ade80;
            border: 1px solid rgba(74, 222, 128, 0.35);
        }
        .badge-error {
            background-color: rgba(245, 158, 11, 0.16);
            color: #fcd34d;
            border: 1px solid rgba(245, 158, 11, 0.35);
        }
        .badge-na {
            background-color: rgba(113, 113, 122, 0.2);
            color: #a1a1aa;
            border: 1px solid rgba(113, 113, 122, 0.35);
        }

        .badge-critical {
            background-color: rgba(225, 29, 72, 0.22);
            color: #fda4af;
            border: 1px solid #e11d48;
        }
        .badge-high {
            background-color: rgba(244, 63, 94, 0.18);
            color: #fb7185;
            border: 1px solid #f43f5e;
        }
        .badge-medium {
            background-color: rgba(245, 158, 11, 0.18);
            color: #fde047;
            border: 1px solid #eab308;
        }
        .badge-low {
            background-color: rgba(139, 92, 246, 0.18);
            color: #c084fc;
            border: 1px solid #8b5cf6;
        }
        .badge-info {
            background-color: rgba(14, 165, 233, 0.18);
            color: #38bdf8;
            border: 1px solid #0ea5e9;
        }

        /* Segmented Radio Buttons (Nocturn Pill Tabs) */
        div[data-testid="stRadio"] > div {
            background: #11121d !important;
            padding: 4px !important;
            border-radius: 12px !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            gap: 4px !important;
        }
        div[data-testid="stRadio"] label {
            border-radius: 8px !important;
            padding: 6px 14px !important;
            font-size: 0.8rem !important;
            font-weight: 600 !important;
            color: #8e90a6 !important;
            margin: 0 !important;
            transition: all 0.15s ease !important;
        }
        div[data-testid="stRadio"] label:hover {
            color: #ffffff !important;
            background: rgba(255, 255, 255, 0.04) !important;
        }
        div[data-testid="stRadio"] label[data-checked="true"] {
            background: #202235 !important;
            color: #ffffff !important;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.3) !important;
        }

        /* Buttons (Nocturn Pill & Solid) */
        button[kind="primary"] {
            background: linear-gradient(135deg, #7c3aed 0%, #6366f1 100%) !important;
            border: none !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            border-radius: 10px !important;
            box-shadow: 0 4px 12px rgba(124, 58, 237, 0.3) !important;
        }
        button[kind="primary"]:hover {
            box-shadow: 0 6px 18px rgba(124, 58, 237, 0.45) !important;
            transform: translateY(-1px);
        }
        button[kind="secondary"] {
            background: #161726 !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            color: #e4e4e7 !important;
            border-radius: 10px !important;
        }
        button[kind="secondary"]:hover {
            border-color: rgba(139, 92, 246, 0.4) !important;
            color: #ffffff !important;
        }

        /* Inputs & Selectboxes */
        div[data-testid="stTextInput"] input,
        div[data-testid="stSelectbox"] div[data-baseweb="select"] {
            background: #131422 !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            border-radius: 10px !important;
            color: #ffffff !important;
            font-size: 0.85rem !important;
        }

        /* Code Blocks */
        code, pre {
            background: #0f1019 !important;
            border-radius: 10px !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            font-size: 0.82rem !important;
        }

        /* Sidebar Promo Card */
        .sidebar-promo-card {
            background: linear-gradient(180deg, #181928 0%, #131422 100%);
            border: 1px solid rgba(139, 92, 246, 0.25);
            border-radius: 14px;
            padding: 14px;
            margin: 1rem 0;
        }
        .sidebar-promo-title {
            font-weight: 700;
            font-size: 0.85rem;
            color: #ffffff;
            margin-bottom: 4px;
        }
        .sidebar-promo-desc {
            font-size: 0.72rem;
            color: #9496a8;
            line-height: 1.4;
            margin-bottom: 10px;
        }

        @media (max-width: 768px) {
            .nocturn-top-bar {
                flex-direction: column;
                gap: 10px;
                padding: 12px;
            }
            .nocturn-search-pill {
                min-width: 100%;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header() -> None:
    """Render the Nocturn-style top SaaS navigation bar."""
    if LOGO_FILE.exists():
        encoded = base64.b64encode(LOGO_FILE.read_bytes()).decode("utf-8")
        logo_tag = (
            f'<img src="data:image/png;base64,{encoded}" height="30" '
            'style="border-radius: 6px;" alt="Columbus" />'
        )
    else:
        logo_tag = '<div class="nocturn-brand-badge">C</div>'

    navbar_html = f"""
    <div class="nocturn-top-bar">
        <div class="nocturn-brand-group">
            {logo_tag}
            <span class="nocturn-brand-name">Columbus</span>
        </div>
        <div class="nocturn-search-pill">
            <span>🔍</span>
            <span>Search findings, rules, resources...</span>
        </div>
        <div class="nocturn-actions-group">
            <div class="nocturn-user-pill">
                <div class="nocturn-user-avatar">LM</div>
                <span>Lance (Auditor)</span>
            </div>
        </div>
    </div>
    """
    st.markdown(navbar_html, unsafe_allow_html=True)


def format_status_badge(status: Status) -> str:
    """Return an HTML pill badge for a finding status."""
    css_class = {
        Status.FAIL: "badge-fail",
        Status.PASS: "badge-pass",
        Status.ERROR: "badge-error",
        Status.NOT_APPLICABLE: "badge-na",
    }.get(status, "badge-na")
    return f'<span class="badge {css_class}">{status.value}</span>'


def format_severity_badge(severity: Severity) -> str:
    """Return an HTML pill badge for a severity level."""
    css_class = {
        Severity.CRITICAL: "badge-critical",
        Severity.HIGH: "badge-high",
        Severity.MEDIUM: "badge-medium",
        Severity.LOW: "badge-low",
        Severity.INFORMATIONAL: "badge-info",
    }.get(severity, "badge-info")
    return f'<span class="badge {css_class}">{severity.value}</span>'
