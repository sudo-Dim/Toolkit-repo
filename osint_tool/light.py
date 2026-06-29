"""
OSINT Recon Tool - Light (Terminal-Only)
========================================
Schlanke Variante ohne Web-UI / ohne Flask. Nutzt dieselbe Engine, aber mit
einem animierten Terminal-Interface: Braille-Spinner, sanft easender
Gradient-Fortschrittsbalken, Live-Modulstatus und farbcodierte Ergebnisse.

Start:
    python -m osint_tool.light                  # interaktiv
    python -m osint_tool.light user@example.com # einmaliger Scan
    python -m osint_tool.light --type domain example.com --export
"""

import os
import sys
import time
import shutil
import argparse
import threading

# Als Script ausführbar machen (python osint_tool/light.py)
if __name__ == "__main__" and __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from osint_tool.core.config import AppConfig
from osint_tool.core.engine import OSINTEngine
from osint_tool.core.reporter import Reporter


# ══════════════════════════════════════════════════════════════
# Farb-Palette (Truecolor -> 16-Farben -> keine Farbe)
# ══════════════════════════════════════════════════════════════
class Palette:
    def __init__(self, enabled=True, truecolor=True):
        self.enabled = enabled
        self.truecolor = truecolor and enabled
        if not enabled:
            for n in ("RESET", "BOLD", "DIM", "CYAN", "GREEN", "RED",
                      "ORANGE", "GRAY", "WHITE", "INDIGO", "TEAL", "MAGENTA"):
                setattr(self, n, "")
            return
        self.RESET = "\x1b[0m"; self.BOLD = "\x1b[1m"; self.DIM = "\x1b[2m"
        if self.truecolor:
            self.CYAN = self._t(0, 180, 255); self.GREEN = self._t(48, 209, 88)
            self.RED = self._t(255, 69, 58); self.ORANGE = self._t(255, 159, 10)
            self.GRAY = self._t(142, 142, 147); self.WHITE = self._t(245, 245, 247)
            self.INDIGO = self._t(94, 92, 230); self.TEAL = self._t(90, 200, 250)
            self.MAGENTA = self._t(255, 55, 95)
        else:
            self.CYAN = "\x1b[96m"; self.GREEN = "\x1b[92m"; self.RED = "\x1b[91m"
            self.ORANGE = "\x1b[93m"; self.GRAY = "\x1b[90m"; self.WHITE = "\x1b[97m"
            self.INDIGO = "\x1b[94m"; self.TEAL = "\x1b[96m"; self.MAGENTA = "\x1b[95m"

    @staticmethod
    def _t(r, g, b):
        return f"\x1b[38;2;{r};{g};{b}m"

    def grad(self, r, g, b):
        """Truecolor-Vordergrund (für Gradient); fällt sonst auf CYAN zurück."""
        return self._t(r, g, b) if self.truecolor else self.CYAN


def _enable_windows_ansi():
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SEV = {  # severity -> (icon, color-attr-name)
    "found": ("✓", "GREEN"), "critical": ("‼", "RED"), "warning": ("!", "ORANGE"),
    "info": ("•", "TEAL"), "not_found": ("·", "GRAY"),
}
TYPE_ICON = {"username": "👤", "email": "✉️", "phone": "📞", "domain": "🌐",
             "ip": "🌐", "name": "🔎", "image": "🖼️"}


def _term_width(default=80):
    try:
        return max(50, shutil.get_terminal_size().columns)
    except Exception:
        return default


# ══════════════════════════════════════════════════════════════
# Animierter Live-Fortschritt (eigener Render-Thread)
# ══════════════════════════════════════════════════════════════
class LiveProgress:
    def __init__(self, pal: Palette, modules, animate=True):
        self.pal = pal
        self.animate = animate
        self.modules = modules                 # geordnete Modulnamen
        self.n = max(1, len(modules))
        self._lock = threading.Lock()
        self._target = 0.0                      # Ziel-Prozent (0..100)
        self._shown = 0.0                       # angezeigt (easend)
        self._module = ""
        self._message = "Initialisiere…"
        self._frame = 0
        self._stop = threading.Event()
        self._thread = None
        self._start = time.time()
        self._lines = 0

    # vom Engine-Callback aufgerufen
    def callback(self, module_name, current, total, message):
        try:
            idx = self.modules.index(module_name)
        except ValueError:
            idx = 0
        frac = (current / total) if total else 0.0
        overall = (idx + min(frac, 1.0)) / self.n * 100.0
        with self._lock:
            self._target = max(self._target, overall)   # monoton steigend
            self._module = module_name
            self._message = message or self._message

    def start(self):
        if not self.animate:
            print(f"  {self.pal.CYAN}⏳{self.pal.RESET} Scanne …")
            return
        sys.stdout.write("\x1b[?25l")            # Cursor aus
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self, final_message="Fertig"):
        if not self.animate:
            return
        with self._lock:
            self._target = 100.0
            self._message = final_message
        time.sleep(0.18)                         # kurz auf 100% animieren
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        self._render(done=True)
        sys.stdout.write("\x1b[?25h\n")          # Cursor an
        sys.stdout.flush()

    def _loop(self):
        while not self._stop.is_set():
            with self._lock:
                # sanftes Easing Richtung Ziel
                self._shown += (self._target - self._shown) * 0.18
                if self._target - self._shown < 0.05:
                    self._shown = self._target
            self._frame = (self._frame + 1) % len(SPINNER)
            self._render()
            time.sleep(0.07)

    def _bar(self, pct, width):
        pal = self.pal
        filled = pct / 100.0 * width
        full = int(filled)
        frac = filled - full
        parts = ""
        # voll gefüllte Zellen mit Gradient
        for i in range(full):
            if pal.truecolor:
                t = i / max(1, width - 1)
                r = int(0 + (94 - 0) * t)
                g = int(180 + (92 - 180) * t)
                b = int(255 + (230 - 255) * t)
                parts += pal.grad(r, g, b) + "█"
            else:
                parts += pal.CYAN + "█"
        # Teilzelle
        if full < width and frac > 0:
            sub = " ▏▎▍▌▋▊▉"[int(frac * 8)]
            parts += (pal.grad(94, 92, 230) if pal.truecolor else pal.CYAN) + sub
            rest = width - full - 1
        else:
            rest = width - full
        parts += pal.RESET + pal.DIM + "·" * max(0, rest) + pal.RESET
        return parts

    def _render(self, done=False):
        pal = self.pal
        with self._lock:
            shown = 100.0 if done else self._shown
            module = self._module
            message = self._message
        width = _term_width()
        bar_w = max(20, min(46, width - 26))
        spin = "✓" if done else SPINNER[self._frame]
        spin_col = pal.GREEN if done else pal.CYAN
        elapsed = time.time() - self._start
        label = TYPE_ICON.get(module, "📦") + " " + (module or "scan")

        line1 = f"  {spin_col}{spin}{pal.RESET} {pal.BOLD}{pal.WHITE}{label}{pal.RESET}"
        line2 = f"  {self._bar(shown, bar_w)} {pal.BOLD}{shown:3.0f}%{pal.RESET}"
        msg = message if len(message) < width - 14 else message[:width - 17] + "…"
        line3 = f"  {pal.GRAY}{msg}{pal.RESET}  {pal.DIM}{elapsed:4.1f}s{pal.RESET}"

        out = []
        if self._lines:
            out.append(f"\x1b[{self._lines}A")   # Cursor hoch
        for ln in (line1, line2, line3):
            out.append("\x1b[2K" + ln + "\n")     # Zeile löschen + schreiben
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self._lines = 3


# ══════════════════════════════════════════════════════════════
# Ausgabe
# ══════════════════════════════════════════════════════════════
def banner(pal: Palette):
    p = pal
    print(f"""{p.CYAN}{p.BOLD}
   ╔═══════════════════════════════════════════════╗
   ║   ◈  O S I N T   R E C O N   ·   L I G H T     ║
   ║      Terminal Intelligence  ·  no web UI       ║
   ╚═══════════════════════════════════════════════╝{p.RESET}""")


def render_results(pal: Palette, result):
    p = pal
    data = result.to_dict()
    s = data["summary"]
    width = _term_width()
    rule = p.GRAY + "─" * min(width - 2, 60) + p.RESET

    print(f"\n  {p.BOLD}{p.WHITE}Ergebnis{p.RESET}  "
          f"{p.GRAY}{result.job.input_value}  ·  {result.job.input_type}  ·  "
          f"{result.duration_seconds:.1f}s{p.RESET}")
    print("  " + rule)
    print(f"  {p.GREEN}{p.BOLD}{s['total_found']}{p.RESET} Treffer   "
          f"{p.WHITE}{s['total_results']}{p.RESET} Ergebnisse   "
          f"{p.GRAY}{s['total_modules']} Modul(e)   "
          f"{(p.RED if s['total_errors'] else p.GRAY)}{s['total_errors']} Fehler{p.RESET}")
    print("  " + rule)

    for report in data["modules"]:
        results = report.get("results", [])
        if not results:
            continue
        icon = TYPE_ICON.get(report["module"], "📦")
        print(f"\n  {icon} {p.BOLD}{p.WHITE}{report['module'].upper()}{p.RESET}"
              f"  {p.GRAY}({report['summary']['found']} Treffer){p.RESET}")

        buckets = {"found": [], "critical": [], "warning": [], "info": [], "not_found": []}
        for r in results:
            buckets.setdefault(r["severity"], []).append(r)

        # Wichtiges zuerst, voll dargestellt
        for sev in ("critical", "warning", "found"):
            for r in buckets.get(sev, []):
                icon_c, col = SEV.get(sev, ("•", "WHITE"))
                color = getattr(p, col)
                url = f"  {p.CYAN}{r['url']}{p.RESET}" if r.get("url") else ""
                print(f"    {color}{icon_c}{p.RESET} {p.WHITE}{r['title']}{p.RESET}"
                      f"  {p.DIM}{r['source']}{p.RESET}{url}")

        # Info/Links kompakt (mit URL)
        infos = buckets.get("info", [])
        link_infos = [r for r in infos if r.get("url")]
        plain_infos = [r for r in infos if not r.get("url")]
        for r in plain_infos:
            print(f"    {p.TEAL}•{p.RESET} {r['title']} {p.DIM}{r['source']}{p.RESET}")
        if link_infos:
            print(f"    {p.DIM}Links:{p.RESET}")
            for r in link_infos[:25]:
                print(f"      {p.GRAY}↗{p.RESET} {r['title']}  {p.CYAN}{r['url']}{p.RESET}")
            if len(link_infos) > 25:
                print(f"      {p.DIM}… +{len(link_infos) - 25} weitere{p.RESET}")

        # Nicht gefunden nur als Zähler
        nf = buckets.get("not_found", [])
        if nf:
            print(f"    {p.GRAY}·{p.RESET} {p.DIM}{len(nf)} ohne Treffer "
                  f"({', '.join(r['source'] for r in nf[:6])}"
                  f"{' …' if len(nf) > 6 else ''}){p.RESET}")


# ══════════════════════════════════════════════════════════════
# Scan-Ablauf
# ══════════════════════════════════════════════════════════════
def run_once(engine, reporter, pal, value, input_type=None, do_export=False):
    detected = input_type or engine.detect_input_type(value)
    modules = [m.name for m in engine.get_modules_for_type(detected)] or [detected]

    print(f"\n  {pal.DIM}Erkannt als{pal.RESET} "
          f"{TYPE_ICON.get(detected, '📦')} {pal.BOLD}{detected}{pal.RESET}\n")

    live = LiveProgress(pal, modules, animate=pal.enabled)
    engine.set_progress_callback(live.callback)

    result_box = {}

    def worker():
        try:
            result_box["result"] = engine.scan(value, detected)
        except Exception as exc:  # pragma: no cover
            result_box["error"] = exc

    live.start()
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    while t.is_alive():
        time.sleep(0.05)
    t.join()
    live.stop("Analyse abgeschlossen")
    engine.set_progress_callback(None)

    if "error" in result_box:
        print(f"\n  {pal.RED}Fehler: {result_box['error']}{pal.RESET}")
        return None

    result = result_box["result"]
    render_results(pal, result)

    if do_export:
        files = reporter.export_all(result)
        print(f"\n  {pal.GREEN}Exportiert:{pal.RESET}")
        for fmt, path in files.items():
            print(f"    {pal.DIM}{fmt.upper()}{pal.RESET} {path}")
    return result


def main():
    parser = argparse.ArgumentParser(
        prog="osint-light", description="OSINT Recon Tool – Light (Terminal-Only)")
    parser.add_argument("input", nargs="?", help="Ziel (E-Mail, Username, Telefon, Domain, Name, Bild-URL)")
    parser.add_argument("--type", dest="itype", default=None,
                        help="Eingabetyp erzwingen (username/email/phone/domain/ip/name/image)")
    parser.add_argument("--export", action="store_true", help="Ergebnisse als JSON/TXT/HTML exportieren")
    parser.add_argument("--no-color", action="store_true", help="Farben/Animation deaktivieren")
    args = parser.parse_args()

    _enable_windows_ansi()
    color = (not args.no_color) and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    truecolor = os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
    pal = Palette(enabled=color, truecolor=truecolor)

    config = AppConfig()
    config.load_api_keys()
    engine = OSINTEngine(config)
    reporter = Reporter(config.output_dir)

    banner(pal)

    # Einmaliger Lauf (nicht-interaktiv)
    if args.input:
        run_once(engine, reporter, pal, args.input.strip(), args.itype, args.export)
        return

    # Interaktive Schleife
    print(f"  {pal.DIM}Tippe ein Ziel ein – Typ wird automatisch erkannt. "
          f"'q' zum Beenden.{pal.RESET}")
    while True:
        try:
            value = input(f"\n  {pal.CYAN}❯{pal.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {pal.CYAN}Tschüss!{pal.RESET}\n")
            break
        if not value:
            continue
        if value.lower() in ("q", "quit", "exit", ":q"):
            print(f"  {pal.CYAN}Tschüss!{pal.RESET}\n")
            break
        try:
            run_once(engine, reporter, pal, value, args.itype, args.export)
        except KeyboardInterrupt:
            print(f"\n  {pal.ORANGE}Abgebrochen.{pal.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\x1b[?25h\n")
        sys.exit(0)
