"""Desktop-Launcher und PyInstaller-Einstiegspunkt."""

import multiprocessing
import sys
from pathlib import Path

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if not getattr(sys, "frozen", False):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from osint_tool.desktop.app import main
    main()
