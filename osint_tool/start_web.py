"""
OSINT Recon Tool - Web-GUI Launcher
Startet den Webserver und öffnet den Browser automatisch.

Nutzung:
    python start_web.py
    python start_web.py --port 8080
"""

import sys
import os
import time
import threading
import webbrowser

# Pfad-Setup: Elternordner hinzufuegen, damit "osint_tool" als Package gefunden wird
# Wenn dieses Script unter C:\Users\...\osint_tool\start_web.py liegt,
# muss C:\Users\...\ im PATH sein (nicht osint_tool selbst)
_this_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_this_dir)
sys.path.insert(0, _parent_dir)


def open_browser(port):
    """Öffnet den Browser nach kurzem Delay."""
    time.sleep(1.2)
    webbrowser.open(f"http://127.0.0.1:{port}")


def main():
    port = 5000

    # Optionaler Port-Parameter
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            try:
                port = int(sys.argv[i + 1])
            except ValueError:
                pass

    # Browser-Thread starten
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    # Server starten
    from osint_tool.web.app import start_server
    start_server(port=port)


if __name__ == "__main__":
    main()
