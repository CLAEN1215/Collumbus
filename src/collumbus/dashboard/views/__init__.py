"""Views package for the Streamlit dashboard."""

from collumbus.dashboard.views.coverage import render_coverage
from collumbus.dashboard.views.findings import render_findings
from collumbus.dashboard.views.history import render_history
from collumbus.dashboard.views.overview import render_overview
from collumbus.dashboard.views.rules import render_rules

__all__ = [
    "render_coverage",
    "render_findings",
    "render_history",
    "render_overview",
    "render_rules",
]
