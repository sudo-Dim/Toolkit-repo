"""
OSINT Recon Tool - CLI-Hauptprogramm
Interaktives Kommandozeilen-Interface.

Starten: python -m osint_tool
         python main.py
"""

import sys
import os
import logging
from typing import Optional

# Ermöglicht den Aufruf als Modul und als Script
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from osint_tool.core.config import AppConfig
from osint_tool.core.engine import OSINTEngine
from osint_tool.core.reporter import Reporter


# ── Farben für Windows-Terminal ────────────────

class Colors:
    """ANSI-Farbcodes (funktioniert ab Windows 10)."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    @staticmethod
    def enable_windows():
        """Aktiviert ANSI-Escape-Codes unter Windows."""
        if os.name == "nt":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(
                    kernel32.GetStdHandle(-11), 7
                )
            except Exception:
                pass


def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   ██████╗ ███████╗██╗███╗   ██╗████████╗            ║
    ║  ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝            ║
    ║  ██║   ██║███████╗██║██╔██╗ ██║   ██║               ║
    ║  ██║   ██║╚════██║██║██║╚██╗██║   ██║               ║
    ║  ╚██████╔╝███████║██║██║ ╚████║   ██║               ║
    ║   ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝               ║
    ║                                                      ║
    ║        R E C O N   T O O L   v1.0                    ║
    ║        OSINT Intelligence Gathering                  ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def print_separator():
    print(f"{Colors.GRAY}{'─' * 60}{Colors.RESET}")


def print_menu():
    print(f"""
{Colors.BOLD}{Colors.WHITE}  HAUPTMENÜ{Colors.RESET}
{Colors.GRAY}{'─' * 40}{Colors.RESET}
  {Colors.CYAN}[1]{Colors.RESET} 🔍  Automatischer Scan  {Colors.DIM}(Typ wird erkannt){Colors.RESET}
  {Colors.CYAN}[2]{Colors.RESET} 👤  Username-Suche
  {Colors.CYAN}[3]{Colors.RESET} 📧  E-Mail-Analyse
  {Colors.CYAN}[4]{Colors.RESET} 📞  Telefonnummer-Analyse
  {Colors.CYAN}[5]{Colors.RESET} 🌐  Domain/IP-Analyse
  {Colors.CYAN}[6]{Colors.RESET} 🔎  Namenssuche
  {Colors.CYAN}[7]{Colors.RESET} 📋  Multi-Scan  {Colors.DIM}(mehrere Eingaben){Colors.RESET}
  {Colors.CYAN}[8]{Colors.RESET} ⚙️   Einstellungen
  {Colors.CYAN}[0]{Colors.RESET} 🚪  Beenden
{Colors.GRAY}{'─' * 40}{Colors.RESET}""")


def print_progress(module_name: str, current: int, total: int, message: str):
    """Progress-Callback für die CLI."""
    if total > 0:
        pct = int((current / total) * 100)
        bar_len = 30
        filled = int(bar_len * current / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(
            f"\r  {Colors.CYAN}[{bar}]{Colors.RESET} "
            f"{pct:3d}% | {Colors.DIM}{message}{Colors.RESET}",
            end="", flush=True,
        )
        if current >= total:
            print()


def print_results_summary(scan_result):
    """Gibt eine kompakte Zusammenfassung der Ergebnisse aus."""
    data = scan_result.to_dict()
    summary = data["summary"]

    print(f"\n{Colors.BOLD}{Colors.GREEN}  ✅ SCAN ABGESCHLOSSEN{Colors.RESET}")
    print_separator()
    print(f"  Eingabe:     {Colors.WHITE}{scan_result.job.input_value}{Colors.RESET}")
    print(f"  Typ:         {scan_result.job.input_type}")
    print(f"  Dauer:       {scan_result.duration_seconds:.1f}s")
    print(f"  Module:      {summary['total_modules']}")
    print(f"  Ergebnisse:  {summary['total_results']}")
    print(f"  Treffer:     {Colors.GREEN}{summary['total_found']}{Colors.RESET}")
    if summary['total_errors'] > 0:
        print(f"  Fehler:      {Colors.RED}{summary['total_errors']}{Colors.RESET}")
    print_separator()

    # Treffer anzeigen
    for report in scan_result.reports:
        found_results = [r for r in report.results
                        if r.severity.value == "found"]
        if found_results:
            print(f"\n  {Colors.BOLD}{Colors.MAGENTA}📦 {report.module_name.upper()}{Colors.RESET}")
            for r in found_results:
                url_str = f" → {Colors.BLUE}{r.url}{Colors.RESET}" if r.url else ""
                print(f"    {Colors.GREEN}[+]{Colors.RESET} {r.title}{url_str}")

        # Warnungen/Kritisch
        warn_results = [r for r in report.results
                       if r.severity.value in ("warning", "critical")]
        for r in warn_results:
            color = Colors.RED if r.severity.value == "critical" else Colors.YELLOW
            print(f"    {color}[!]{Colors.RESET} {r.title}")


def run_scan(engine: OSINTEngine, reporter: Reporter,
             input_value: str, input_type: Optional[str] = None):
    """Führt einen Scan durch und exportiert die Ergebnisse."""
    print(f"\n  {Colors.CYAN}⏳ Starte Scan...{Colors.RESET}\n")

    if input_type:
        result = engine.scan(input_value, input_type)
    else:
        detected = engine.detect_input_type(input_value)
        print(f"  {Colors.DIM}Erkannter Typ: {detected}{Colors.RESET}\n")
        result = engine.scan(input_value, detected)

    print_results_summary(result)

    # Export
    print(f"\n  {Colors.CYAN}💾 Exportiere Ergebnisse...{Colors.RESET}")
    files = reporter.export_all(result)
    for fmt, path in files.items():
        print(f"    {Colors.GREEN}✓{Colors.RESET} {fmt.upper()}: {path}")

    return result


def settings_menu(config: AppConfig):
    """Einstellungsmenü."""
    while True:
        print(f"""
{Colors.BOLD}{Colors.WHITE}  EINSTELLUNGEN{Colors.RESET}
{Colors.GRAY}{'─' * 40}{Colors.RESET}
  {Colors.CYAN}[1]{Colors.RESET} Request-Timeout:    {config.request_timeout}s
  {Colors.CYAN}[2]{Colors.RESET} Max. Threads:       {config.max_concurrent_requests}
  {Colors.CYAN}[3]{Colors.RESET} Verzögerung:        {config.delay_between_requests}s
  {Colors.CYAN}[4]{Colors.RESET} Ausgabe-Ordner:     {config.output_dir}
  {Colors.CYAN}[5]{Colors.RESET} API-Keys verwalten
  {Colors.CYAN}[0]{Colors.RESET} Zurück
{Colors.GRAY}{'─' * 40}{Colors.RESET}""")

        choice = input(f"  {Colors.CYAN}>{Colors.RESET} ").strip()

        if choice == "0":
            break
        elif choice == "1":
            try:
                val = int(input("  Timeout (Sekunden): "))
                config.request_timeout = max(1, min(60, val))
                print(f"  {Colors.GREEN}✓{Colors.RESET} Timeout: {config.request_timeout}s")
            except ValueError:
                print(f"  {Colors.RED}Ungültige Eingabe{Colors.RESET}")
        elif choice == "2":
            try:
                val = int(input("  Max. parallele Requests: "))
                config.max_concurrent_requests = max(1, min(50, val))
                print(f"  {Colors.GREEN}✓{Colors.RESET} Threads: {config.max_concurrent_requests}")
            except ValueError:
                print(f"  {Colors.RED}Ungültige Eingabe{Colors.RESET}")
        elif choice == "3":
            try:
                val = float(input("  Verzögerung (Sekunden): "))
                config.delay_between_requests = max(0, min(10, val))
                print(f"  {Colors.GREEN}✓{Colors.RESET} Delay: {config.delay_between_requests}s")
            except ValueError:
                print(f"  {Colors.RED}Ungültige Eingabe{Colors.RESET}")
        elif choice == "4":
            val = input("  Ausgabe-Ordner: ").strip()
            if val:
                config.output_dir = val
                os.makedirs(val, exist_ok=True)
                print(f"  {Colors.GREEN}✓{Colors.RESET} Ordner: {config.output_dir}")
        elif choice == "5":
            print(f"\n  {Colors.BOLD}API-Keys:{Colors.RESET}")
            keys = {
                "hibp": "Have I Been Pwned",
                "hunter": "Hunter.io",
                "shodan": "Shodan",
                "numverify": "NumVerify",
            }
            for key, label in keys.items():
                status = (f"{Colors.GREEN}✓ gesetzt{Colors.RESET}"
                         if config.get_api_key(key)
                         else f"{Colors.GRAY}nicht gesetzt{Colors.RESET}")
                print(f"    {label}: {status}")

            print(f"\n  {Colors.DIM}API-Keys werden aus config.json oder "
                  f"Umgebungsvariablen geladen.{Colors.RESET}")
            print(f"  {Colors.DIM}Erstelle eine config.json im Programmordner:{Colors.RESET}")
            print(f'  {Colors.DIM}{{"api_keys": {{"hibp": "dein-key", ...}}}}{Colors.RESET}')


def main():
    """Hauptprogramm."""
    Colors.enable_windows()

    # Logging konfigurieren
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Initialisierung
    config = AppConfig()
    config.load_api_keys()
    engine = OSINTEngine(config)
    engine.set_progress_callback(print_progress)
    reporter = Reporter(config.output_dir)

    print_banner()

    while True:
        print_menu()
        choice = input(f"  {Colors.CYAN}Auswahl >{Colors.RESET} ").strip()

        if choice == "0":
            print(f"\n  {Colors.CYAN}Auf Wiedersehen!{Colors.RESET}\n")
            break

        try:
            if choice == "1":
                # Auto-Scan
                value = input(f"\n  {Colors.WHITE}Eingabe (beliebig):{Colors.RESET} ").strip()
                if value:
                    run_scan(engine, reporter, value)

            elif choice == "2":
                # Username
                value = input(f"\n  {Colors.WHITE}Username:{Colors.RESET} ").strip()
                if value:
                    run_scan(engine, reporter, value, "username")

            elif choice == "3":
                # E-Mail
                value = input(f"\n  {Colors.WHITE}E-Mail-Adresse:{Colors.RESET} ").strip()
                if value:
                    run_scan(engine, reporter, value, "email")

            elif choice == "4":
                # Telefon
                value = input(f"\n  {Colors.WHITE}Telefonnummer (mit Vorwahl):{Colors.RESET} ").strip()
                if value:
                    run_scan(engine, reporter, value, "phone")

            elif choice == "5":
                # Domain/IP
                value = input(f"\n  {Colors.WHITE}Domain oder IP:{Colors.RESET} ").strip()
                if value:
                    run_scan(engine, reporter, value, "domain")

            elif choice == "6":
                # Name
                value = input(f"\n  {Colors.WHITE}Vor- und Nachname:{Colors.RESET} ").strip()
                if value:
                    run_scan(engine, reporter, value, "name")

            elif choice == "7":
                # Multi-Scan
                print(f"\n  {Colors.DIM}Gib mehrere Werte ein (leer = fertig):{Colors.RESET}")
                inputs = []
                while True:
                    val = input(f"  {Colors.CYAN}+{Colors.RESET} ").strip()
                    if not val:
                        break
                    inputs.append({"value": val})

                if inputs:
                    print(f"\n  {Colors.CYAN}⏳ Starte Multi-Scan ({len(inputs)} Ziele)...{Colors.RESET}")
                    results = engine.multi_scan(inputs)
                    for result in results:
                        print_results_summary(result)
                        files = reporter.export_all(result)
                        for fmt, path in files.items():
                            print(f"    {Colors.GREEN}✓{Colors.RESET} {fmt.upper()}: {path}")
                        print()

            elif choice == "8":
                settings_menu(config)

            else:
                print(f"  {Colors.RED}Ungültige Auswahl{Colors.RESET}")
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"\n  {Colors.RED}Fehler bei der Ausführung: {e}{Colors.RESET}")

        input(f"\n  {Colors.DIM}[Enter] für Hauptmenü...{Colors.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.CYAN}Abgebrochen.{Colors.RESET}\n")
        sys.exit(0)
