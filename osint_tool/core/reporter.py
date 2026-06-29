"""
OSINT Tool - Reporter
Exportiert Scan-Ergebnisse in verschiedene Formate:
JSON, TXT (plain text), HTML (interaktiver Report).
"""

import json
import os
from datetime import datetime
from typing import Optional

from .engine import ScanResult
from ..modules.base import ResultSeverity
from .config import SEVERITY_COLORS


class Reporter:
    """Exportiert ScanResults in verschiedene Formate."""

    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def _generate_filename(self, scan_result: ScanResult, extension: str) -> str:
        """Generiert einen eindeutigen Dateinamen."""
        safe_input = "".join(
            c if c.isalnum() or c in "-_." else "_"
            for c in scan_result.job.input_value
        )[:50]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(
            self.output_dir,
            f"osint_{safe_input}_{timestamp}.{extension}"
        )

    # ── JSON ────────────────────────────────────

    def export_json(self, scan_result: ScanResult,
                    filepath: Optional[str] = None) -> str:
        """Exportiert als JSON."""
        filepath = filepath or self._generate_filename(scan_result, "json")
        data = scan_result.to_dict()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath

    # ── TXT ─────────────────────────────────────

    def export_txt(self, scan_result: ScanResult,
                   filepath: Optional[str] = None) -> str:
        """Exportiert als lesbarer Plaintext-Report."""
        filepath = filepath or self._generate_filename(scan_result, "txt")
        lines = []

        lines.append("=" * 70)
        lines.append("  OSINT RECON TOOL - SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"  Eingabe:    {scan_result.job.input_value}")
        lines.append(f"  Typ:        {scan_result.job.input_type}")
        lines.append(f"  Zeitpunkt:  {scan_result.job.timestamp}")
        lines.append(f"  Dauer:      {scan_result.duration_seconds:.1f} Sekunden")
        lines.append("=" * 70)

        summary = scan_result.to_dict()["summary"]
        lines.append(f"\n  ZUSAMMENFASSUNG:")
        lines.append(f"  Module:     {summary['total_modules']}")
        lines.append(f"  Ergebnisse: {summary['total_results']}")
        lines.append(f"  Treffer:    {summary['total_found']}")
        lines.append(f"  Fehler:     {summary['total_errors']}")
        lines.append("")

        for report in scan_result.reports:
            lines.append("-" * 70)
            lines.append(f"  MODUL: {report.module_name.upper()}")
            lines.append(f"  Dauer: {report.duration_seconds:.1f}s | "
                        f"Ergebnisse: {report.total_count} | "
                        f"Treffer: {report.found_count}")
            lines.append("-" * 70)

            for result in report.results:
                icon = {
                    ResultSeverity.FOUND: "[+]",
                    ResultSeverity.NOT_FOUND: "[-]",
                    ResultSeverity.WARNING: "[!]",
                    ResultSeverity.CRITICAL: "[!!!]",
                    ResultSeverity.INFO: "[i]",
                }.get(result.severity, "[?]")

                lines.append(f"\n  {icon} {result.title}")
                lines.append(f"      Quelle:   {result.source}")
                lines.append(f"      Kategorie: {result.category}")
                if result.url:
                    lines.append(f"      URL:      {result.url}")

                # Daten kompakt darstellen
                for key, value in result.data.items():
                    if isinstance(value, (list, dict)):
                        if isinstance(value, list) and len(value) > 0:
                            lines.append(f"      {key}:")
                            for item in value[:10]:
                                if isinstance(item, dict):
                                    brief = ", ".join(
                                        f"{k}: {v}" for k, v in item.items()
                                        if v and str(v) != "None"
                                    )
                                    lines.append(f"        - {brief}")
                                else:
                                    lines.append(f"        - {item}")
                            if len(value) > 10:
                                lines.append(f"        ... und {len(value)-10} weitere")
                    elif value is not None and str(value) != "":
                        lines.append(f"      {key}: {value}")

            if report.errors:
                lines.append(f"\n  Fehler in {report.module_name}:")
                for err in report.errors:
                    lines.append(f"    [ERR] {err}")

            lines.append("")

        lines.append("=" * 70)
        lines.append("  Ende des Reports")
        lines.append("=" * 70)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return filepath

    # ── HTML ────────────────────────────────────

    def export_html(self, scan_result: ScanResult,
                    filepath: Optional[str] = None) -> str:
        """Exportiert als interaktiven HTML-Report."""
        filepath = filepath or self._generate_filename(scan_result, "html")
        data = scan_result.to_dict()
        summary = data["summary"]

        html = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report - {self._escape_html(scan_result.job.input_value)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #0a0e17;
    color: #c8d6e5;
    line-height: 1.6;
    padding: 2rem;
}}
.container {{ max-width: 1100px; margin: 0 auto; }}
h1 {{
    font-size: 1.8rem;
    color: #00d4ff;
    margin-bottom: 0.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}}
h1::before {{ content: "🔍"; }}
.meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
}}
.meta-card {{
    background: #141b2d;
    border: 1px solid #1e2a42;
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
}}
.meta-card .value {{
    font-size: 1.8rem;
    font-weight: 700;
    color: #00d4ff;
}}
.meta-card .label {{ font-size: 0.85rem; color: #8899aa; margin-top: 0.25rem; }}
.module {{
    background: #141b2d;
    border: 1px solid #1e2a42;
    border-radius: 8px;
    margin: 1.5rem 0;
    overflow: hidden;
}}
.module-header {{
    background: #1a2332;
    padding: 1rem 1.5rem;
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    user-select: none;
}}
.module-header:hover {{ background: #1e2a3a; }}
.module-header h2 {{ font-size: 1.1rem; color: #e0e8f0; }}
.module-header .badge {{
    background: #00d4ff22;
    color: #00d4ff;
    padding: 0.2rem 0.7rem;
    border-radius: 12px;
    font-size: 0.8rem;
}}
.module-body {{ padding: 1rem 1.5rem; }}
.module-body.collapsed {{ display: none; }}
.result {{
    border-left: 3px solid #2a3a4a;
    padding: 0.75rem 1rem;
    margin: 0.5rem 0;
    background: #0d1320;
    border-radius: 0 6px 6px 0;
}}
.result.found {{ border-left-color: {SEVERITY_COLORS["found"]}; }}
.result.not_found {{ border-left-color: {SEVERITY_COLORS["not_found"]}; }}
.result.warning {{ border-left-color: {SEVERITY_COLORS["warning"]}; }}
.result.critical {{ border-left-color: {SEVERITY_COLORS["critical"]}; }}
.result.info {{ border-left-color: {SEVERITY_COLORS["info"]}; }}
.result-title {{
    font-weight: 600;
    color: #e0e8f0;
    margin-bottom: 0.25rem;
}}
.result-meta {{ font-size: 0.8rem; color: #667788; }}
.result-meta a {{ color: #00d4ff; text-decoration: none; }}
.result-meta a:hover {{ text-decoration: underline; }}
.data-grid {{
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.2rem 1rem;
    font-size: 0.85rem;
    margin-top: 0.5rem;
}}
.data-key {{ color: #667788; font-weight: 500; }}
.data-value {{ color: #a0b0c0; word-break: break-all; }}
.tag {{
    display: inline-block;
    background: #1a2535;
    border: 1px solid #2a3a4a;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    margin: 0.1rem;
}}
.footer {{
    text-align: center;
    color: #445566;
    font-size: 0.8rem;
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid #1e2a42;
}}
.filter-bar {{
    display: flex;
    gap: 0.5rem;
    margin: 1rem 0;
    flex-wrap: wrap;
}}
.filter-btn {{
    background: #1a2332;
    border: 1px solid #2a3a4a;
    color: #8899aa;
    padding: 0.4rem 0.8rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.8rem;
    transition: all 0.2s;
}}
.filter-btn:hover, .filter-btn.active {{
    background: #00d4ff22;
    border-color: #00d4ff;
    color: #00d4ff;
}}
</style>
</head>
<body>
<div class="container">
    <h1>OSINT Recon Report</h1>
    <p style="color:#667788; margin-bottom: 0.5rem;">
        Ziel: <strong style="color:#e0e8f0">{self._escape_html(scan_result.job.input_value)}</strong>
        &nbsp;|&nbsp; Typ: <strong style="color:#e0e8f0">{scan_result.job.input_type}</strong>
        &nbsp;|&nbsp; {scan_result.job.timestamp}
    </p>

    <div class="meta">
        <div class="meta-card">
            <div class="value">{summary['total_modules']}</div>
            <div class="label">Module</div>
        </div>
        <div class="meta-card">
            <div class="value">{summary['total_results']}</div>
            <div class="label">Ergebnisse</div>
        </div>
        <div class="meta-card">
            <div class="value" style="color: #2ecc71">{summary['total_found']}</div>
            <div class="label">Treffer</div>
        </div>
        <div class="meta-card">
            <div class="value" style="color: {'#e74c3c' if summary['total_errors'] > 0 else '#2ecc71'}">{summary['total_errors']}</div>
            <div class="label">Fehler</div>
        </div>
    </div>

    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterResults('all')">Alle</button>
        <button class="filter-btn" onclick="filterResults('found')">Treffer</button>
        <button class="filter-btn" onclick="filterResults('warning')">Warnungen</button>
        <button class="filter-btn" onclick="filterResults('critical')">Kritisch</button>
        <button class="filter-btn" onclick="filterResults('info')">Info</button>
    </div>
"""

        for report in scan_result.reports:
            html += f"""
    <div class="module">
        <div class="module-header" onclick="toggleModule(this)">
            <h2>📦 {self._escape_html(report.module_name.upper())}</h2>
            <span class="badge">{report.found_count}/{report.total_count} Treffer</span>
        </div>
        <div class="module-body">
"""
            for result in report.results:
                severity_class = result.severity.value
                html += f"""
            <div class="result {severity_class}" data-severity="{severity_class}">
                <div class="result-title">{self._escape_html(result.title)}</div>
                <div class="result-meta">
                    {self._escape_html(result.source)} | {self._escape_html(result.category)}
                    {f' | <a href="{self._escape_html(result.url)}" target="_blank">Link öffnen ↗</a>' if result.url else ''}
                </div>
                <div class="data-grid">
"""
                for key, value in result.data.items():
                    if key.startswith("_"):
                        continue
                    display_value = self._format_value(value)
                    if display_value:
                        html += f"""
                    <span class="data-key">{self._escape_html(key)}</span>
                    <span class="data-value">{display_value}</span>
"""
                html += """
                </div>
            </div>
"""

            html += """
        </div>
    </div>
"""

        html += f"""
    <div class="footer">
        OSINT Recon Tool v1.0 | Report generiert am {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
    </div>
</div>

<script>
function toggleModule(header) {{
    const body = header.nextElementSibling;
    body.classList.toggle('collapsed');
}}
function filterResults(severity) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.result').forEach(r => {{
        if (severity === 'all') {{
            r.style.display = '';
        }} else {{
            r.style.display = r.dataset.severity === severity ? '' : 'none';
        }}
    }});
}}
</script>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return filepath

    # ── Alle Formate ────────────────────────────

    def export_all(self, scan_result: ScanResult) -> dict:
        """Exportiert in alle Formate und gibt Dateipfade zurück."""
        return {
            "json": self.export_json(scan_result),
            "txt": self.export_txt(scan_result),
            "html": self.export_html(scan_result),
        }

    # ── Hilfsfunktionen ────────────────────────

    @staticmethod
    def _escape_html(text: str) -> str:
        if not text:
            return ""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _format_value(self, value) -> str:
        """Formatiert einen Wert für HTML-Anzeige."""
        if value is None:
            return ""
        if isinstance(value, bool):
            return "✅ Ja" if value else "❌ Nein"
        if isinstance(value, list):
            if not value:
                return ""
            items = []
            for item in value[:15]:
                if isinstance(item, dict):
                    parts = [f"{k}: {v}" for k, v in item.items()
                             if v and str(v) != "None"]
                    items.append(
                        f'<span class="tag">{self._escape_html(", ".join(parts))}</span>'
                    )
                else:
                    items.append(
                        f'<span class="tag">{self._escape_html(str(item))}</span>'
                    )
            result = " ".join(items)
            if len(value) > 15:
                result += f' <em>+{len(value)-15} weitere</em>'
            return result
        if isinstance(value, dict):
            if not value:
                return ""
            parts = [f"{k}: {v}" for k, v in value.items()
                     if v and str(v) != "None" and not str(k).startswith("_")]
            return self._escape_html(", ".join(parts[:5]))
        return self._escape_html(str(value))
