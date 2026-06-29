"""
Build-Script für die Erstellung einer eigenständigen Windows-EXE.

Voraussetzungen:
    pip install pyinstaller

Ausführen:
    python build.py

Ergebnis:
    dist/OSINTReconTool.exe  (Standalone, kein Python nötig)
"""

import subprocess
import sys
import os


def build():
    # Prüfe ob PyInstaller installiert ist
    try:
        import PyInstaller
    except ImportError:
        print("PyInstaller nicht gefunden. Installiere...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # Build-Befehl
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                          # Eine einzelne EXE
        "--console",                          # Konsolen-Anwendung
        "--name", "OSINTReconTool",           # Name der EXE
        "--add-data", "config.json;.",         # config.json einbinden
        "--hidden-import", "dns.resolver",     # Versteckte Imports
        "--hidden-import", "dns.rdatatype",
        "--hidden-import", "dns.name",
        "--clean",                            # Sauberer Build
        "main.py",                            # Einstiegspunkt
    ]

    print("=" * 50)
    print("  OSINT Recon Tool - Build")
    print("=" * 50)
    print(f"\n  Befehl: {' '.join(cmd)}\n")

    try:
        subprocess.check_call(cmd)
        print("\n" + "=" * 50)
        print("  ✅ Build erfolgreich!")
        print(f"  📁 Datei: dist/OSINTReconTool.exe")
        print("=" * 50)
    except subprocess.CalledProcessError as e:
        print(f"\n  ❌ Build fehlgeschlagen: {e}")
        sys.exit(1)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    build()
