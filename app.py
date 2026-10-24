"""Streamlit Cloud entrypoint for Collumbus."""

import sys
from pathlib import Path

# Add src to sys.path so collumbus package is found
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from collumbus.dashboard.app import main  # noqa: E402

main()
