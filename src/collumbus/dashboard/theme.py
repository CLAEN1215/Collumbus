"""Cybersecurity theme, responsive CSS, and visual badge helpers for Columbus dashboard.

Harmonized with the Columbus Cloud Security Auditor brand palette:
- Primary Navy Base: #060b17
- Card / Panel Elevation: #0c162d
- Accent Cyan / Neon Teal: #00d2ff & #38bdf8
- Shield Emerald: #10b981
- Alert Crimson: #ef4444
- Warning Amber: #f59e0b
- Monospace Typography: 'JetBrains Mono', 'Fira Code', monospace
"""

import base64
from pathlib import Path

import streamlit as st

from collumbus.models import Severity, Status

ASSETS_DIR = Path(__file__).parent / "assets"
LOGO_FILE = ASSETS_DIR / "logo.png"


def apply_theme() -> None:
    """Inject professional cybersecurity dark palette and monospace typography."""
    st.markdown(
        """
        <style>
        /* Import Google JetBrains Mono */
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&display=swap');

        /* Universal Monospace Font Application */
        html, body, [class*="css"], .stMarkdown, p, span, label, div,
        input, select, textarea, button, code, pre, table, th, td {
            font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace !important;
            font-feature-settings: "zero" 1, "liga" 1;
        }

        /* Container constraints & padding */
        .main .block-container {
            padding-top: 1rem;
            padding-bottom: 3.5rem;
            max-width: 1240px;
        }

        /* Top Branded Header Container */
        .columbus-header-bar {
            background: linear-gradient(90deg, #060b17 0%, #0d1830 50%, #060b17 100%);
            border: 1px solid rgba(0, 210, 255, 0.22);
            border-radius: 14px;
            padding: 14px 24px;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(0, 210, 255, 0.15);
        }
        .columbus-header-logo {
            max-height: 48px;
            object-fit: contain;
            display: block;
        }
        .columbus-status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(0, 210, 255, 0.08);
            border: 1px solid rgba(0, 210, 255, 0.3);
            color: #38bdf8;
            font-size: 0.72rem;
            font-weight: 700;
            padding: 5px 12px;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        .pulse-indicator {
            width: 8px;
            height: 8px;
            background-color: #00d2ff;
            border-radius: 50%;
            box-shadow: 0 0 8px #00d2ff;
            animation: pulse-glow 2s infinite ease-in-out;
        }
        @keyframes pulse-glow {
            0% { transform: scale(0.9); opacity: 0.7; box-shadow: 0 0 4px #00d2ff; }
            50% { transform: scale(1.15); opacity: 1; box-shadow: 0 0 12px #00d2ff; }
            100% { transform: scale(0.9); opacity: 0.7; box-shadow: 0 0 4px #00d2ff; }
        }

        /* Metric Cards (Balance, Alignment & Cyan Glow) */
        div[data-testid="stMetric"] {
            background: #0c162d !important;
            border: 1px solid rgba(0, 210, 255, 0.18) !important;
            border-radius: 12px !important;
            padding: 16px 20px !important;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3) !important;
            transition: all 0.2s ease !important;
        }
        div[data-testid="stMetric"]:hover {
            border-color: rgba(0, 210, 255, 0.45) !important;
            transform: translateY(-2px);
            box-shadow: 0 6px 18px rgba(0, 210, 255, 0.12) !important;
        }
        div[data-testid="stMetricLabel"] {
            font-size: 0.8rem !important;
            font-weight: 700 !important;
            text-transform: uppercase !important;
            letter-spacing: 0.08em !important;
            color: #94a3b8 !important;
        }
        div[data-testid="stMetricValue"] {
            font-size: 1.9rem !important;
            font-weight: 800 !important;
            color: #f8fafc !important;
        }

        /* Container & Card Styling */
        div[data-testid="stVerticalBlock"] > div[data-testid="stContainer"] {
            border-color: rgba(0, 210, 255, 0.18) !important;
            background: #091122 !important;
            border-radius: 12px !important;
        }

        /* Expander Styling */
        div[data-testid="stExpander"] {
            background: #0a1326 !important;
            border: 1px solid rgba(0, 210, 255, 0.18) !important;
            border-radius: 12px !important;
            margin-bottom: 0.85rem !important;
            transition: border-color 0.2s ease !important;
        }
        div[data-testid="stExpander"]:hover {
            border-color: rgba(0, 210, 255, 0.35) !important;
        }

        /* Pill Badges (Monospace & High Contrast) */
        .badge {
            display: inline-block;
            padding: 3px 10px;
            font-size: 0.72rem;
            font-weight: 700;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            vertical-align: middle;
            margin-right: 6px;
            line-height: 1.4;
            font-family: 'JetBrains Mono', monospace !important;
        }
        .badge-fail {
            background-color: rgba(239, 68, 68, 0.18);
            color: #f87171;
            border: 1px solid #ef4444;
        }
        .badge-pass {
            background-color: rgba(16, 185, 129, 0.18);
            color: #34d399;
            border: 1px solid #10b981;
        }
        .badge-error {
            background-color: rgba(245, 158, 11, 0.18);
            color: #fbbf24;
            border: 1px solid #f59e0b;
        }
        .badge-na {
            background-color: rgba(100, 116, 139, 0.2);
            color: #94a3b8;
            border: 1px solid #64748b;
        }

        .badge-critical {
            background-color: rgba(220, 38, 38, 0.25);
            color: #fca5a5;
            border: 1px solid #dc2626;
        }
        .badge-high {
            background-color: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid #ef4444;
        }
        .badge-medium {
            background-color: rgba(245, 158, 11, 0.2);
            color: #fcd34d;
            border: 1px solid #f59e0b;
        }
        .badge-low {
            background-color: rgba(14, 165, 233, 0.2);
            color: #38bdf8;
            border: 1px solid #0ea5e9;
        }
        .badge-info {
            background-color: rgba(100, 116, 139, 0.2);
            color: #cbd5e1;
            border: 1px solid #64748b;
        }

        /* Buttons & Inputs */
        button[kind="primary"] {
            background: linear-gradient(135deg, #0284c7 0%, #00d2ff 100%) !important;
            border: none !important;
            color: #060b17 !important;
            font-weight: 700 !important;
            letter-spacing: 0.05em !important;
            box-shadow: 0 2px 10px rgba(0, 210, 255, 0.25) !important;
        }
        button[kind="primary"]:hover {
            box-shadow: 0 4px 16px rgba(0, 210, 255, 0.45) !important;
            transform: translateY(-1px);
        }

        /* Code Blocks */
        code, pre {
            border-radius: 8px !important;
            border: 1px solid rgba(0, 210, 255, 0.15) !important;
        }

        /* Mobile responsiveness */
        @media (max-width: 768px) {
            .columbus-header-bar {
                flex-direction: column;
                gap: 12px;
                text-align: center;
                padding: 12px 16px;
            }
            .columbus-header-logo {
                max-height: 38px;
            }
            .main .block-container {
                padding-left: 0.75rem;
                padding-right: 0.75rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header() -> None:
    """Render the branded Columbus logo header with live audit status badge."""
    if LOGO_FILE.exists():
        encoded = base64.b64encode(LOGO_FILE.read_bytes()).decode("utf-8")
        img_tag = (
            f'<img src="data:image/png;base64,{encoded}" '
            f'alt="Columbus" class="columbus-header-logo" />'
        )
        header_html = f"""
        <div class="columbus-header-bar">
            {img_tag}
            <div class="columbus-status-pill">
                <span class="pulse-indicator"></span>
                <span>AUDIT ENGINE // READ-ONLY MODE</span>
            </div>
        </div>
        """
        st.markdown(header_html, unsafe_allow_html=True)


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
