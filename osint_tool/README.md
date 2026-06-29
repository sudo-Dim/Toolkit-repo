# 🔍 OSINT Recon Tool v1.0

Ein modulares Open Source Intelligence (OSINT) Tool für Cybersecurity-Bildung.

---

## 📦 Features

### Module

| Modul | Eingabe | Was es tut |
|-------|---------|------------|
| **Username** | `@john_doe` | Prüft 30+ Plattformen (GitHub, Twitter, Instagram, Reddit, Steam...) |
| **E-Mail** | `test@example.com` | Format-Validierung, Provider-Erkennung, MX-Check, Gravatar, HIBP Breaches, Reputation |
| **Telefon** | `+43 660 1234567` | Ländererkennung, Carrier-Lookup (NumVerify), Telefonbuch-Links |
| **Domain/IP** | `example.com` / `1.2.3.4` | DNS-Records, WHOIS/RDAP, HTTP-Header, SSL-Zertifikat, Subdomains (crt.sh), robots.txt |
| **Name** | `Max Mustermann` | Google Dorks, Plattform-Suchlinks, Username-Varianten, People-Search-Engines |

### Allgemein
- ✅ **Auto-Erkennung** des Eingabetyps
- ✅ **Multi-Scan** (mehrere Ziele auf einmal)
- ✅ **3 Export-Formate**: JSON, TXT, interaktiver HTML-Report
- ✅ **Modulare Architektur** (eigene Module einfach hinzufügbar)
- ✅ **Progress-Callbacks** (GUI-ready)
- ✅ **Parallele Requests** (ThreadPool)
- ✅ **Optionale API-Keys** für erweiterte Funktionen
- ✅ **Kompilierbar als Windows-EXE** (PyInstaller)

---

## 🚀 Schnellstart

### Variante A: Mit Python (Entwicklung)

```bash
# 1. Abhängigkeiten installieren
pip install -r requirements.txt

# 2. Starten
python main.py
# oder
python -m osint_tool
```

### Variante B: Standalone Windows-EXE

```bash
# 1. Einmalig: Build erstellen
pip install pyinstaller
python build.py

# 2. EXE starten (kein Python nötig!)
dist\OSINTReconTool.exe
```

---

## ⚙️ Konfiguration

### API-Keys (optional, erweitert die Funktionalität)

Erstelle eine `config.json` im Programmordner:

```json
{
    "api_keys": {
        "hibp": "dein-haveibeenpwned-key",
        "shodan": "dein-shodan-key",
        "numverify": "dein-numverify-key",
        "hunter": "dein-hunter-key"
    }
}
```

Oder setze Umgebungsvariablen:
```
HIBP_API_KEY=...
SHODAN_API_KEY=...
NUMVERIFY_API_KEY=...
HUNTER_API_KEY=...
```

| API | Kosten | Nutzen |
|-----|--------|--------|
| [HIBP](https://haveibeenpwned.com/API/Key) | ~$3.50/Monat | E-Mail-Breach-Checks |
| [Shodan](https://account.shodan.io/) | Kostenlos (Basis) | IP-Port-Scans, Schwachstellen |
| [NumVerify](https://numverify.com/) | Kostenlos (250/Monat) | Telefon-Carrier-Erkennung |
| [Hunter.io](https://hunter.io/) | Kostenlos (25/Monat) | E-Mail-Verifikation |

---

## 🏗️ Architektur

```
osint_tool/
├── __init__.py          # Package-Definition
├── __main__.py          # python -m Einstieg
├── main.py              # CLI-Interface
├── build.py             # Windows-EXE-Builder
├── config.json          # API-Key-Konfiguration
├── requirements.txt     # Python-Abhängigkeiten
├── core/
│   ├── __init__.py
│   ├── config.py        # Konfiguration, Plattform-Listen
│   ├── engine.py        # Zentrale Engine (Orchestrierung)
│   └── reporter.py      # Export (JSON, TXT, HTML)
└── modules/
    ├── __init__.py      # Modul-Registry
    ├── base.py          # Abstrakte Basisklasse
    ├── username.py      # Username-Enumeration
    ├── email_osint.py   # E-Mail-Analyse
    ├── phone.py         # Telefonnummer-Analyse
    ├── domain.py        # Domain/IP-Recon
    └── name_search.py   # Namenssuche
```

### Eigenes Modul hinzufügen

```python
# modules/mein_modul.py
from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity

class MeinModul(BaseModule):
    @property
    def name(self): return "mein_modul"

    @property
    def description(self): return "Mein eigenes Modul"

    @property
    def input_types(self): return ["username", "email"]

    def run(self, input_value, input_type):
        start = time.time()
        # ... Logik hier ...
        self.add_result(OSINTResult(
            source="MeineDatenquelle",
            module=self.name,
            category="Custom",
            severity=ResultSeverity.FOUND,
            title="Etwas gefunden!",
            data={"key": "value"},
        ))
        return self.create_report(input_value, input_type, start, time.time())
```

Dann in `modules/__init__.py` registrieren:
```python
from .mein_modul import MeinModul
ALL_MODULES.append(MeinModul)
```

### GUI-Integration (vorbereitet)

Die Engine ist komplett GUI-ready:

```python
from osint_tool.core import OSINTEngine, Reporter

# Engine erstellen
engine = OSINTEngine()

# Progress-Callback für GUI (z.B. Progressbar)
def on_progress(module, current, total, message):
    progress_bar.setValue(int(current / total * 100))
    status_label.setText(message)

engine.set_progress_callback(on_progress)

# Scan starten (z.B. in einem Thread)
result = engine.auto_scan("test@example.com")

# Ergebnis als dict (für GUI-Anzeige)
data = result.to_dict()

# Export
reporter = Reporter("./results")
reporter.export_html(result)
```

---

## 📋 Abhängigkeiten

| Paket | Version | Pflicht | Zweck |
|-------|---------|---------|-------|
| `requests` | ≥2.28 | ✅ | HTTP-Requests |
| `dnspython` | ≥2.3 | ❌ | Erweiterte DNS-Auflösung |
| `pyinstaller` | ≥6.0 | ❌ | Nur zum Erstellen der EXE |

---

## ⚠️ Rechtlicher Hinweis

Dieses Tool dient ausschließlich zu **Bildungszwecken** im Bereich Cybersecurity.
Nutze es nur für autorisierte Analysen und beachte die geltenden Gesetze.
Die Nutzung gegen Dritte ohne deren Einverständnis kann rechtswidrig sein.

---

## 🔮 Geplante Erweiterungen

- [ ] GUI (Tkinter / PyQt / Web-Interface)
- [ ] Weitere Module (Social Media Scraping, EXIF-Analyse, etc.)
- [ ] Datenbank-Backend für Ergebnis-Historisierung
- [ ] Plugin-System für Community-Module
- [ ] Netzwerk-Graph-Visualisierung
