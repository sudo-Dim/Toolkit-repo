# 🔍 OSINT Recon Tool v1.2

Ein modulares Open Source Intelligence (OSINT) Tool für Cybersecurity-Bildung.

---

## 📦 Features

### Module

| Modul | Eingabe | Was es tut |
|-------|---------|------------|
| **Username** | `@john_doe` | Prüft **~60 Plattformen** mit präziser Sherlock-Detektion (echter 404 / Not-Found-Text / Redirect) statt naivem „HTTP 200". Seiten, die anonym nicht zuverlässig prüfbar sind (Instagram, X, TikTok, LinkedIn, StackOverflow …), werden als manueller Link markiert – **keine False Positives**. Mit hinterlegtem Login (`site_auth`) werden auch diese geprüft. |
| **E-Mail** | `test@example.com` | Format & Normalisierung (Gmail-Kanonisierung), Provider (Domain + MX), **MX/SPF/DMARC**, Wegwerf-/Rollen-Konto-Erkennung, **Gravatar** (Name/Ort/verknüpfte Accounts), **GitHub** (Commit-/User-Suche per E-Mail), **Account-Existenz im Holehe-Stil** über viele Seiten inkl. Microsoft/Office 365, Spotify, Strava, eBay, Amazon, Tumblr u.a., **keyfreie Breach-Checks** (XposedOrNot, LeakCheck, ProxyNova) sowie optional HIBP/Hunter/DeHashed, plus generierte **Such-/Dork-Links** |
| **Telefon** | `+43 660 1234567` | **libphonenumber**: Land/Region, Geocoding, **Carrier**, Nummerntyp (Mobil/Festnetz/VoIP), Zeitzonen, alle Formate; Messaging-Links (WhatsApp/Telegram/Viber); Reverse-Lookup/Spam/Telefonbuch (Truecaller, tellows, Das Örtliche, Herold …); NumVerify optional |
| **Domain/IP** | `example.com` / `1.2.3.4` | DNS (A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA, DoH-Fallback), **SPF/DMARC/DKIM**, RDAP/WHOIS, TLS-Zertifikat, HTTP-Security-Header-Grade, Subdomains (crt.sh), robots/sitemap/**security.txt**, **IP-Geo/ASN** (ipwho.is/ip-api), **offene Ports & CVEs via Shodan InternetDB (keyfrei!)**, Wayback; Shodan optional |
| **Name** | `Max Mustermann` | Einzeln klickbare Such-/Dork-Links (Suchmaschinen, Social via Google-Dorks, **People-Search US**, **DE/AT/EU-Verzeichnisse & Register** – Das Telefonbuch, Herold, North Data, Handelsregister, OpenCorporates), Username-Varianten, **live ORCID- & GitHub-Suche** |
| **Bild/Gesicht** 🆕 | `bild.jpg` / Bild-URL | **Grundstein** für PimEyes-artige Gesichtssuche: Direktlinks zu Reverse-Face-/Image-Engines (Google Lens, Yandex, Bing, TinEye, PimEyes, FaceCheck.ID, Search4Faces, Lenso.ai), optionale lokale Gesichts-Detektion, dokumentierte ML-Roadmap (Detection→Embedding→Index→Matching) |

### Allgemein
- ✅ **Auto-Erkennung** des Eingabetyps
- ✅ **Multi-Scan** (mehrere Ziele auf einmal)
- ✅ **3 Export-Formate**: JSON, TXT, interaktiver HTML-Report
- ✅ **Modulare Architektur** (eigene Module einfach hinzufügbar)
- ✅ **Progress-Callbacks** (GUI-ready)
- ✅ **Parallele Requests** (ThreadPool)
- ✅ **Optionale API-Keys** für erweiterte Funktionen
- ✅ **Präzise Detektion** – eindeutige Signale statt Rateversuch, dadurch **keine False Positives**
- ✅ **Login-Hinterlegung** (`site_auth`) für sonst nicht prüfbare Seiten
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

> **Wichtig:** Das E-Mail-Modul liefert auch **ganz ohne API-Keys** viele echte
> Treffer (Gravatar, GitHub, Microsoft/Office 365, Spotify u.a. Account-Checks,
> keyfreie Breach-Quellen, DNS/SPF/DMARC, Such-Links). Keys erweitern nur die
> Abdeckung.

### API-Keys (optional, erweitert die Funktionalität)

Echte Keys gehören in **`config.local.json`** (per `.gitignore` ausgeschlossen,
wird automatisch geladen und überschreibt `config.json`). Vorlage:
`config.local.example.json` kopieren → `config.local.json`.

```json
{
    "api_keys": {
        "hibp": "dein-haveibeenpwned-key",
        "hunter": "dein-hunter-key",
        "dehashed_email": "deine-dehashed-mail",
        "dehashed": "dein-dehashed-key",
        "leakcheck": "dein-leakcheck-pro-key",
        "github": "ghp_dein_token"
    }
}
```

Oder per Umgebungsvariablen: `HIBP_API_KEY`, `HUNTER_API_KEY`, `EMAILREP_API_KEY`,
`DEHASHED_EMAIL`, `DEHASHED_API_KEY`, `INTELX_API_KEY`, `LEAKCHECK_API_KEY`,
`GITHUB_TOKEN`, `SHODAN_API_KEY`, `NUMVERIFY_API_KEY`.

| API | Kosten | Nutzen |
|-----|--------|--------|
| [HIBP](https://haveibeenpwned.com/API/Key) | ~$3.50/Monat | E-Mail-Breach-Checks |
| [Hunter.io](https://hunter.io/) | Kostenlos (25/Monat) | E-Mail-Verifikation |
| [DeHashed](https://dehashed.com/) | kostenpflichtig | Tiefe Breach-Suche |
| [LeakCheck](https://leakcheck.io/) | kostenpflichtig | Breach-Suche (PRO) |
| GitHub Token | Kostenlos | Höheres Rate-Limit der GitHub-Suche |
| [Shodan](https://account.shodan.io/) | Kostenlos (Basis) | IP-Port-Scans |
| [NumVerify](https://numverify.com/) | Kostenlos (250/Monat) | Telefon-Carrier |

### 🔓 Nicht-anonym prüfbare Seiten freischalten (`site_auth`)

Seiten wie **Instagram, X/Twitter, LinkedIn, Reddit, TikTok** blockieren anonyme
Abfragen und werden daher nur als *manueller Link* ausgegeben. Hinterlegst du in
`config.local.json` ein eigenes Login (Session-Cookie / Bearer-Token), prüft das
Username-Modul auch diese Seiten:

```json
{
  "site_auth": {
    "Instagram": { "cookie": "sessionid=...; csrftoken=..." },
    "Twitter/X": { "headers": { "Cookie": "auth_token=...; ct0=..." } },
    "Reddit":    { "bearer": "DEIN_OAUTH_TOKEN" },
    "LinkedIn":  { "cookie": "li_at=..." }
  }
}
```

Die Cookies findest du im eingeloggten Browser über die DevTools
(Application → Cookies bzw. Network → Request Headers). Der Plattformname muss
exakt (case-insensitive) dem Tool-Namen entsprechen. Vollständiges Beispiel:
`config.local.example.json`.
**⚠️ Diese Cookies sind so sensibel wie dein Passwort – niemals committen/teilen.**

---

## 🏗️ Architektur

```
osint_tool/
├── __init__.py          # Package-Definition
├── __main__.py          # python -m Einstieg
├── main.py              # CLI-Interface
├── build.py             # Windows-EXE-Builder
├── config.json          # API-Key-Vorlage (leer)
├── config.local.example.json  # Vorlage für echte Keys/Logins (-> config.local.json)
├── requirements.txt     # Python-Abhängigkeiten
├── data/                # Datentabellen (JSON)
│   ├── username_platforms.json   # ~60 Plattformen + Detektionsregeln
│   ├── email_sources.json        # Account-Checks + Dork-Links
│   ├── disposable_domains.json   # Wegwerf-Mail-Domains
│   ├── name_sources.json         # Namens-Such-/Register-Links
│   └── face_search_engines.json  # Reverse-Face-/Image-Engines
├── core/
│   ├── __init__.py
│   ├── config.py        # Konfiguration, Daten-Loader, site_auth
│   ├── http.py          # Geteilte requests-Session (Pool, Retries)
│   ├── engine.py        # Zentrale Engine (Orchestrierung)
│   └── reporter.py      # Export (JSON, TXT, HTML)
└── modules/
    ├── __init__.py      # Modul-Registry
    ├── base.py          # Abstrakte Basisklasse
    ├── username.py      # Username-Enumeration
    ├── email_osint.py   # E-Mail-Analyse
    ├── phone.py         # Telefonnummer-Analyse
    ├── domain.py        # Domain/IP-Recon
    ├── name_search.py   # Namenssuche
    └── face_recognition.py  # Gesichts-/Bildsuche (Grundstein)
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
| `flask` | ≥3.0 | ✅ | Web-Oberfläche |
| `phonenumbers` | ≥8.13 | ⭐ empfohlen | Land/Carrier/Typ/Zeitzone (Telefon) |
| `dnspython` | ≥2.3 | ⭐ empfohlen | DNS inkl. SPF/DMARC/DKIM/CAA |
| `opencv-python` / `insightface` / `onnxruntime` / `faiss-cpu` | – | ❌ optional | Lokale Gesichtserkennung (Modul *face*, im Aufbau) |
| `pyinstaller` | ≥6.0 | ❌ | Nur zum Erstellen der EXE |

---

## ⚠️ Rechtlicher Hinweis

Dieses Tool dient ausschließlich zu **Bildungszwecken** im Bereich Cybersecurity.
Nutze es nur für autorisierte Analysen und beachte die geltenden Gesetze.
Die Nutzung gegen Dritte ohne deren Einverständnis kann rechtswidrig sein.

---

## 🧠 Gesichtserkennung — Roadmap (Grundstein gelegt)

Das Modul **`face`** ist als Fundament angelegt. Schon nutzbar (ohne ML):
Reverse-Face-/Image-Such-Direktlinks (Google Lens, Yandex, Bing, TinEye) sowie
Verweise auf spezialisierte Engines (PimEyes, FaceCheck.ID, Search4Faces,
Lenso.ai) und optionale lokale Gesichts-Detektion (OpenCV, falls installiert).

Geplanter Ausbau zu einer PimEyes-artigen Eigenlösung (`FaceEngine` in
`modules/face_recognition.py` definiert die Schnittstelle):

1. **Detection** – Gesichter finden (RetinaFace / MTCNN / MediaPipe)
2. **Alignment** – Normalisierung über 5-Punkt-Landmarks
3. **Embedding** – 512-d Vektor je Gesicht (ArcFace / InsightFace `buffalo_l`)
4. **Index** – Vektor-Datenbank (FAISS / hnswlib) über gecrawlte Web-Bilder
5. **Matching** – Cosine-Similarity + Schwellenwert → Treffer mit Quelle
6. **Crawler** – sammelt & indexiert öffentlich zugängliche Bilder

> ⚠️ **Rechtlich/ethisch:** Biometrische Gesichtssuche ist hochsensibel und
> stark reguliert (EU/DSGVO Art. 9, US-BIPA). Nur mit Einwilligung bzw. klarer
> Autorisierung nutzen.

## 🔮 Weitere geplante Erweiterungen

- [x] Web-Interface (Flask)
- [x] Präzise Username-Detektion ohne False Positives
- [x] Breit aufgestelltes E-Mail-Modul (keyfreie Quellen)
- [ ] Lokale Gesichtserkennung aktiv schalten (siehe Roadmap oben)
- [ ] EXIF-/Metadaten-Analyse für Bilder
- [ ] Datenbank-Backend für Ergebnis-Historisierung
- [ ] Plugin-System für Community-Module
- [ ] Netzwerk-Graph-Visualisierung (Entitäts-Verknüpfung)
