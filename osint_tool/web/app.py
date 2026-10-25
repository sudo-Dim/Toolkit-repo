"""
OSINT Recon Tool - Web-Interface (Flask)
Minimalistisches Apple-Style Web-GUI.

Starten:
    python -m osint_tool.web.app
    oder: python web/app.py
"""

import sys
import os
import uuid
import threading
import secrets
import ipaddress
from urllib.parse import urlsplit
from datetime import datetime

# Pfad-Setup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask import Flask, render_template, request, jsonify, send_file
from osint_tool.core.config import AppConfig
from osint_tool.core.engine import OSINTEngine
from osint_tool.core.inputs import clean_input
from osint_tool.core.reporter import Reporter

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)

app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
app.config["LOCAL_TOKEN"] = secrets.token_urlsafe(32)
app.config["MAX_ACTIVE_SCANS"] = 2
app.config["MAX_SAVED_SCANS"] = 32


@app.before_request
def protect_local_app():
    """Reject remote access, DNS rebinding and requests from unrelated websites."""
    try:
        host = urlsplit(request.host_url).hostname
        local_peer = ipaddress.ip_address(request.remote_addr or "").is_loopback
    except ValueError:
        return jsonify(error="Ungültige lokale Anfrage"), 403
    if not local_peer or host not in {"127.0.0.1", "localhost", "::1"}:
        return jsonify(error="Nur lokale Zugriffe sind erlaubt"), 403
    origin = request.headers.get("Origin")
    if (origin and origin != request.host_url.rstrip("/")) or request.headers.get("Sec-Fetch-Site") == "cross-site":
        return jsonify(error="Fremde Webseiten dürfen nicht auf das Tool zugreifen"), 403
    if request.path.startswith("/api/"):
        token = app.config["LOCAL_TOKEN"]
        if not secrets.compare_digest(request.cookies.get("osint_local", ""), token):
            return jsonify(error="Bitte die lokale Startseite öffnen"), 403
        if request.method == "POST" and not secrets.compare_digest(request.headers.get("X-OSINT-Token", ""), token):
            return jsonify(error="Ungültiger Anfrageschlüssel"), 403


@app.after_request
def private_response(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response

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
                pct = max(0, min(100, int((current / total) * 100))) if total > 0 else 0
                scan_states[scan_id]["progress"] = pct
                scan_states[scan_id]["current_module"] = module_name
                scan_states[scan_id]["message"] = message
    return callback


# ── Routen ─────────────────────────────────────

def read_input(*, allow_empty=False):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("Ein JSON-Objekt mit dem Feld 'input' wird erwartet")
    return data, clean_input(data.get("input", ""), allow_empty=allow_empty)


@app.errorhandler(413)
def request_too_large(error):
    return jsonify({"error": "Anfrage zu groß (maximal 64 KiB)"}), 413


@app.route("/")
def index():
    """Hauptseite."""
    response = app.make_response(render_template("index.html", local_token=app.config["LOCAL_TOKEN"]))
    response.set_cookie("osint_local", app.config["LOCAL_TOKEN"], httponly=True, samesite="Strict")
    return response


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Startet einen neuen Scan im Hintergrund."""
    try:
        data, input_value = read_input()
        input_type = data.get("type")
        if input_type is not None and not isinstance(input_type, str):
            raise ValueError("Der Eingabetyp muss ein Text sein")
        input_type = (input_type or "").strip()
        detected_type = (engine.detect_input_type(input_value)
                         if input_type in ("", "auto") else input_type)
        if detected_type not in engine.supported_input_types:
            raise ValueError(f"Unbekannter Eingabetyp: {detected_type}")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # Eindeutige ID (kollisionssicher, auch bei parallelen Scans im selben ms)
    scan_id = uuid.uuid4().hex

    with scan_lock:
        if sum(s["status"] == "running" for s in scan_states.values()) >= app.config["MAX_ACTIVE_SCANS"]:
            return jsonify(error="Es laufen bereits zwei Scans. Bitte deren Abschluss abwarten."), 429
        while len(scan_states) >= app.config["MAX_SAVED_SCANS"]:
            expired = next((key for key, state in scan_states.items() if state["status"] != "running"), None)
            if expired is None:
                return jsonify(error="Scan-Speicher voll"), 429
            del scan_states[expired]
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
        state = dict(scan_states.get(scan_id, {}))
    if not state:
        return jsonify({"error": "Scan nicht gefunden"}), 404
    return jsonify(state)


@app.route("/api/scan/<scan_id>/results")
def scan_results(scan_id):
    """Liefert die vollständigen Ergebnisse eines Scans."""
    with scan_lock:
        state = dict(scan_states.get(scan_id, {}))
    if not state:
        return jsonify({"error": "Scan nicht gefunden"}), 404
    if state["status"] == "error":
        return jsonify({"error": state["message"]}), 500
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

    return send_file(os.path.abspath(filepath), as_attachment=True)


@app.route("/api/detect-type", methods=["POST"])
def detect_type():
    """Erkennt den Eingabetyp."""
    try:
        _, value = read_input(allow_empty=True)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
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
    if host not in {"127.0.0.1", "localhost", "::1"} or debug:
        raise ValueError("Nur Loopback-Betrieb ohne interaktiven Debugger ist erlaubt")
    print(f"\n  🔍 OSINT Recon Tool - Web Interface")
    print(f"  ───────────────────────────────────")
    print(f"  Öffne im Browser: http://{host}:{port}")
    print(f"  Beenden: Ctrl+C\n")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    start_server()
