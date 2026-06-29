"""
OSINT Recon Tool - Web-Interface (Flask)
Minimalistisches Apple-Style Web-GUI.

Starten:
    python -m osint_tool.web.app
    oder: python web/app.py
"""

import sys
import os
import json
import time
import uuid
import threading
from datetime import datetime

# Pfad-Setup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask import Flask, render_template, request, jsonify, send_file
from osint_tool.core.config import AppConfig
from osint_tool.core.engine import OSINTEngine
from osint_tool.core.reporter import Reporter

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)

# ── Globale Instanzen ─────────────────────────
config = AppConfig()
config.load_api_keys()
engine = OSINTEngine(config)
reporter = Reporter(config.output_dir)

# ── Scan-Status (für Live-Updates) ────────────
scan_states = {}  # scan_id -> {status, progress, results, ...}
scan_lock = threading.Lock()


def progress_callback_factory(scan_id):
    """Erstellt einen Progress-Callback für einen bestimmten Scan."""
    def callback(module_name, current, total, message):
        with scan_lock:
            if scan_id in scan_states:
                pct = int((current / total) * 100) if total > 0 else 0
                scan_states[scan_id]["progress"] = pct
                scan_states[scan_id]["current_module"] = module_name
                scan_states[scan_id]["message"] = message
    return callback


# ── Routen ─────────────────────────────────────

@app.route("/")
def index():
    """Hauptseite."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Startet einen neuen Scan im Hintergrund."""
    data = request.get_json(silent=True) or {}
    input_value = data.get("input", "").strip()
    input_type = data.get("type", "").strip() or None

    if not input_value:
        return jsonify({"error": "Keine Eingabe"}), 400

    # Typ erkennen falls nicht angegeben
    detected_type = input_type or engine.detect_input_type(input_value)

    # Eindeutige ID (kollisionssicher, auch bei parallelen Scans im selben ms)
    scan_id = uuid.uuid4().hex

    with scan_lock:
        scan_states[scan_id] = {
            "status": "running",
            "progress": 0,
            "current_module": "",
            "message": "Initialisiere...",
            "input": input_value,
            "type": detected_type,
            "results": None,
            "files": None,
            "start_time": datetime.now().isoformat(),
        }

    def run_scan():
        try:
            # Eigene Engine-Instanz mit Callback
            scan_engine = OSINTEngine(config)
            scan_engine.set_progress_callback(progress_callback_factory(scan_id))

            result = scan_engine.scan(input_value, detected_type)

            # Export
            files = reporter.export_all(result)

            with scan_lock:
                scan_states[scan_id]["status"] = "done"
                scan_states[scan_id]["progress"] = 100
                scan_states[scan_id]["message"] = "Abgeschlossen"
                scan_states[scan_id]["results"] = result.to_dict()
                scan_states[scan_id]["files"] = files
                scan_states[scan_id]["duration"] = result.duration_seconds

        except Exception as e:
            with scan_lock:
                scan_states[scan_id]["status"] = "error"
                scan_states[scan_id]["message"] = str(e)

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "type": detected_type,
        "input": input_value,
    })


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    """Liefert den aktuellen Status eines Scans."""
    with scan_lock:
        state = scan_states.get(scan_id)
    if not state:
        return jsonify({"error": "Scan nicht gefunden"}), 404
    return jsonify(state)


@app.route("/api/scan/<scan_id>/results")
def scan_results(scan_id):
    """Liefert die vollständigen Ergebnisse eines Scans."""
    with scan_lock:
        state = scan_states.get(scan_id)
    if not state:
        return jsonify({"error": "Scan nicht gefunden"}), 404
    if state["status"] != "done":
        return jsonify({"error": "Scan noch nicht abgeschlossen"}), 202
    return jsonify(state["results"])


@app.route("/api/scan/<scan_id>/export/<fmt>")
def scan_export(scan_id, fmt):
    """Liefert eine Export-Datei zum Download."""
    with scan_lock:
        state = scan_states.get(scan_id)
    if not state or not state.get("files"):
        return jsonify({"error": "Keine Dateien verfügbar"}), 404

    filepath = state["files"].get(fmt)
    if not filepath or not os.path.exists(filepath):
        return jsonify({"error": f"Format '{fmt}' nicht verfügbar"}), 404

    return send_file(filepath, as_attachment=True)


@app.route("/api/detect-type", methods=["POST"])
def detect_type():
    """Erkennt den Eingabetyp."""
    data = request.get_json(silent=True) or {}
    value = data.get("input", "").strip()
    if not value:
        return jsonify({"type": None})
    detected = engine.detect_input_type(value)
    return jsonify({"type": detected})


@app.route("/api/modules")
def list_modules():
    """Listet alle verfügbaren Module."""
    modules = []
    for name, mod in engine.available_modules.items():
        modules.append({
            "name": name,
            "description": mod.description,
            "input_types": mod.input_types,
        })
    return jsonify(modules)


# ── App starten ────────────────────────────────

def start_server(host="127.0.0.1", port=5000, debug=False):
    """Startet den Web-Server."""
    print(f"\n  🔍 OSINT Recon Tool - Web Interface")
    print(f"  ───────────────────────────────────")
    print(f"  Öffne im Browser: http://{host}:{port}")
    print(f"  Beenden: Ctrl+C\n")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    # Debugger niemals standardmaessig aktivieren (Werkzeug-Debugger = potenzielle RCE).
    # Bei Bedarf bewusst per Umgebungsvariable einschalten: OSINT_DEBUG=1
    start_server(debug=os.environ.get("OSINT_DEBUG") == "1")
