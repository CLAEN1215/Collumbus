"""Streamlit Cloud entrypoint for Collumbus."""

import sys
from pathlib import Path

# Add src to sys.path so collumbus package is found
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Import and execute the dashboard application
import collumbus.dashboard.app  # noqa: F401, E402
