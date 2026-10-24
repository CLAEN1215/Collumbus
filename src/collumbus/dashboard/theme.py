"""Modern styling, responsive CSS, and visual badge helpers for Collumbus dashboard."""

import streamlit as st

from collumbus.models import Severity, Status


def apply_theme() -> None:
    """Inject modern, responsive cybersecurity-themed CSS into the Streamlit app."""
    st.markdown(
        """
        <style>
        /* Container width & padding */
        .main .block-container {
            padding-top: 1.75rem;
            padding-bottom: 3rem;
            max-width: 1280px;
        }

        /* Metric cards */
        div[data-testid="stMetric"] {
            background-color: var(--secondary-background-color);
            border: 1px solid rgba(128, 128, 128, 0.2);
            border-radius: 12px;
            padding: 12px 16px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        div[data-testid="stMetric"]:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
        }
        div[data-testid="stMetricLabel"] {
            font-size: 0.85rem !important;
            font-weight: 600 !important;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-color);
            opacity: 0.85;
        }
        div[data-testid="stMetricValue"] {
            font-size: 1.8rem !important;
            font-weight: 700 !important;
        }

        /* Status & Severity Pill Badges */
        .badge {
            display: inline-block;
            padding: 2px 10px;
            font-size: 0.72rem;
            font-weight: 700;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            vertical-align: middle;
            margin-right: 6px;
            line-height: 1.4;
        }
        .badge-fail {
            background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444;
        }
        .badge-pass {
            background-color: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #10b981;
        }
        .badge-error {
            background-color: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid #f59e0b;
        }
        .badge-na {
            background-color: rgba(156, 163, 175, 0.15); color: #9ca3af; border: 1px solid #9ca3af;
        }

        .badge-critical {
            background-color: rgba(153, 27, 27, 0.2); color: #f87171; border: 1px solid #dc2626;
        }
        .badge-high {
            background-color: rgba(220, 38, 38, 0.15); color: #ef4444; border: 1px solid #f87171;
        }
        .badge-medium {
            background-color: rgba(217, 119, 6, 0.15); color: #f59e0b; border: 1px solid #fbbf24;
        }
        .badge-low {
            background-color: rgba(37, 99, 235, 0.15); color: #3b82f6; border: 1px solid #60a5fa;
        }
        .badge-info {
            background-color: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid #cbd5e1;
        }

        /* Card and container styling */
        .collumbus-card {
            background-color: var(--secondary-background-color);
            border: 1px solid rgba(128, 128, 128, 0.2);
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 1rem;
        }

        /* Expander card borders */
        div[data-testid="stExpander"] {
            border: 1px solid rgba(128, 128, 128, 0.22) !important;
            border-radius: 10px !important;
            margin-bottom: 0.65rem;
            background: var(--background-color);
        }

        /* Responsive Mobile Layout Fixes */
        @media (max-width: 768px) {
            .main .block-container {
                padding-left: 0.8rem;
                padding-right: 0.8rem;
                padding-top: 1rem;
            }
            div[data-testid="stMetric"] {
                padding: 10px 12px;
                margin-bottom: 0.5rem;
            }
            div[data-testid="stMetricValue"] {
                font-size: 1.4rem !important;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


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
