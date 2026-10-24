"""Nocturn-style modern SaaS dark theme, responsive CSS, and component helpers.

Modeled after modern dark-mode SaaS analytics dashboards:
- Base Canvas: #0d0e15 (Obsidian Slate)
- Sidebar: #11121d
- Card Surface: #161726
- Subtle Borders: 1px solid rgba(255, 255, 255, 0.07)
- Primary Accent: #8b5cf6 (Electric Violet / Purple)
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
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&family=Inter:wght@400;500;600;700&display=swap');

        /* Typography & Canvas Constraints */
        html, body, [class*="css"], .stMarkdown, p, span, label, div,
        input, select, textarea, button, code, pre, table, th, td {
            font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
            font-feature-settings: "zero" 1, "liga" 1;
        }

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
            padding: 10px 18px;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
        }
        .nocturn-brand-group {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .nocturn-brand-badge {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: linear-gradient(135deg, #7c3aed 0%, #38bdf8 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            font-weight: 800;
            font-size: 1rem;
        }
        .nocturn-brand-name {
            font-weight: 700;
            font-size: 1rem;
            color: #ffffff;
            letter-spacing: 0.02em;
        }
        .nocturn-search-pill {
            background: #161726;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 9999px;
            padding: 6px 16px;
            font-size: 0.8rem;
            color: #71717a;
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 260px;
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
            font-size: 0.78rem;
            color: #e4e4e7;
            font-weight: 600;
        }
        .nocturn-user-avatar {
            width: 24px;
            height: 24px;
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
            padding: 20px 22px !important;
            box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35) !important;
            transition: all 0.2s ease !important;
        }
        div[data-testid="stMetric"]:hover {
            border-color: rgba(139, 92, 246, 0.35) !important;
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5) !important;
        }
        div[data-testid="stMetricLabel"] {
            font-size: 0.8rem !important;
            font-weight: 500 !important;
            text-transform: none !important;
            letter-spacing: 0.02em !important;
            color: #8e90a6 !important;
        }
        div[data-testid="stMetricValue"] {
            font-size: 2.1rem !important;
            font-weight: 800 !important;
            color: #ffffff !important;
            margin: 6px 0 !important;
        }
        div[data-testid="stMetricDelta"] {
            font-size: 0.75rem !important;
            font-weight: 600 !important;
        }

        /* Card Containers */
        div[data-testid="stVerticalBlock"] > div[data-testid="stContainer"] {
            border: 1px solid rgba(255, 255, 255, 0.07) !important;
            background: #161726 !important;
            border-radius: 16px !important;
            padding: 20px !important;
        }

        /* Expander Styling */
        div[data-testid="stExpander"] {
            background: #161726 !important;
            border: 1px solid rgba(255, 255, 255, 0.07) !important;
            border-radius: 14px !important;
            margin-bottom: 0.85rem !important;
            transition: border-color 0.2s ease !important;
        }
        div[data-testid="stExpander"]:hover {
            border-color: rgba(139, 92, 246, 0.3) !important;
        }

        /* Pill Badges (Modern SaaS Minimalist) */
        .badge {
            display: inline-block;
            padding: 3px 10px;
            font-size: 0.72rem;
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
            background-color: rgba(225, 29, 72, 0.25);
            color: #fda4af;
            border: 1px solid #e11d48;
        }
        .badge-high {
            background-color: rgba(244, 63, 94, 0.2);
            color: #fb7185;
            border: 1px solid #f43f5e;
        }
        .badge-medium {
            background-color: rgba(245, 158, 11, 0.2);
            color: #fde047;
            border: 1px solid #eab308;
        }
        .badge-low {
            background-color: rgba(139, 92, 246, 0.2);
            color: #c084fc;
            border: 1px solid #8b5cf6;
        }
        .badge-info {
            background-color: rgba(14, 165, 233, 0.2);
            color: #38bdf8;
            border: 1px solid #0ea5e9;
        }

        /* Buttons (Nocturn Pill & Solid) */
        button[kind="primary"] {
            background: linear-gradient(135deg, #7c3aed 0%, #6366f1 100%) !important;
            border: none !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            border-radius: 10px !important;
            box-shadow: 0 4px 14px rgba(124, 58, 237, 0.3) !important;
        }
        button[kind="primary"]:hover {
            box-shadow: 0 6px 20px rgba(124, 58, 237, 0.5) !important;
            transform: translateY(-1px);
        }

        /* Code Blocks */
        code, pre {
            background: #10111a !important;
            border-radius: 10px !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
        }

        /* Sidebar Custom Card */
        .sidebar-promo-card {
            background: linear-gradient(180deg, #181928 0%, #131422 100%);
            border: 1px solid rgba(139, 92, 246, 0.25);
            border-radius: 14px;
            padding: 16px;
            margin-top: 1rem;
        }
        .sidebar-promo-title {
            font-weight: 700;
            font-size: 0.88rem;
            color: #ffffff;
            margin-bottom: 6px;
        }
        .sidebar-promo-desc {
            font-size: 0.74rem;
            color: #9496a8;
            line-height: 1.4;
            margin-bottom: 12px;
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
            f'<img src="data:image/png;base64,{encoded}" height="32" '
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
