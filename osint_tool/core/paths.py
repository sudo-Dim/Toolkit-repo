"""Dateipfade für Quellcode-Start und portable PyInstaller-Builds."""

import os
import sys
from pathlib import Path


def resource_directory() -> Path:
    # PyInstaller setzt __file__ auf die entsprechende Datei im Bundle.
    return Path(__file__).resolve().parent.parent


def application_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return resource_directory()


def desktop_data_directory() -> Path:
    """Portable Daten neben der EXE; bei Schreibschutz im Benutzerprofil."""
    portable = application_directory() / "user-data"
    if getattr(sys, "frozen", False):
        try:
            portable.mkdir(parents=True, exist_ok=True)
            # os.access ist auf Windows/ACLs kein verlässlicher Schreibtest.
            from tempfile import TemporaryFile
            with TemporaryFile(dir=portable):
                pass
            return portable
        except OSError:
            pass
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    target = base / "OSINTReconTool"
    target.mkdir(parents=True, exist_ok=True)
    return target
