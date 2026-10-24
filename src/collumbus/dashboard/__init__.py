"""Streamlit dashboard package for Collumbus."""

from pathlib import Path

APP_PATH = Path(__file__).resolve().parent / "app.py"

__all__ = ["APP_PATH"]
