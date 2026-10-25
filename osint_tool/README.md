# 🔍 OSINT Recon Tool v1.3.1

Ein modulares Open Source Intelligence (OSINT) Tool für Cybersecurity-Bildung.

---

## 📦 Features

### Module

| Modul | Eingabe | Was es tut |
|-------|---------|------------|
| **Username** | `@john_doe` | **87 Plattformen**: 28 API-Regeln mit exaktem Profilbezeichner, 45 HTML-Regeln mit Profil-Metadaten und negativer Gegenprobe, 14 ausschließlich manuelle Quellen. HTTP 200, Login-Seiten und Bot-Sperren zählen nicht als Treffer. |
| **E-Mail** | `test@example.com` | Format & Normalisierung (Gmail-Kanonisierung), Provider (Domain + MX), **MX/SPF/DMARC**, Wegwerf-/Rollen-Konto-Erkennung, **Gravatar** (Name/Ort/verknüpfte Accounts), **GitHub** (Commit-/User-Suche per E-Mail), **Account-Existenz im Holehe-Stil** über viele Seiten mit Spotify, Strava, Tumblr u.a.; Microsoft/Federation nur als unbestätigter Hinweis; keine automatischen Amazon/eBay-Logins, **keyfreie Breach-Checks** (XposedOrNot, LeakCheck, ProxyNova) sowie optional HIBP/Hunter/DeHashed, plus generierte **Such-/Dork-Links** |
| **Telefon** | `+43 660 1234567` | **libphonenumber**: Land/Region, Geocoding, **Carrier**, Nummerntyp (Mobil/Festnetz/VoIP), Zeitzonen, alle Formate; Messaging-Links (WhatsApp/Telegram/Viber); Reverse-Lookup/Spam/Telefonbuch (Truecaller, tellows, Das Örtliche, Herold …); NumVerify optional |
| **Domain/IP** | `example.com` / `1.2.3.4` | DNS (A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA, DoH-Fallback), **SPF/DMARC/DKIM**, RDAP/WHOIS, TLS-Zertifikat, HTTP-Security-Header-Grade, Subdomains (crt.sh), robots/sitemap/**security.txt**, **IP-Geo/ASN** (ipwho.is über HTTPS), **offene Ports & CVEs via Shodan InternetDB (keyfrei!)**, Wayback; Shodan optional |
| **Name** | `Max Mustermann` | Einzeln klickbare Such-/Dork-Links (Suchmaschinen, Social via Google-Dorks, **People-Search US**, **DE/AT/EU-Verzeichnisse & Register** – Das Telefonbuch, Herold, North Data, Handelsregister, OpenCorporates), Username-Varianten, **live ORCID- & GitHub-Suche** (Namenskandidaten, kein Identitätsnachweis), insgesamt 42 manuelle Recherchequellen |
| **Bild/Gesicht** 🆕 | `bild.jpg` / Bild-URL | **Grundstein** für PimEyes-artige Gesichtssuche: Direktlinks zu Reverse-Face-/Image-Engines (Google Lens, Yandex, Bing, TinEye, PimEyes, FaceCheck.ID, Search4Faces, Lenso.ai), optionale lokale Gesichts-Detektion, dokumentierte ML-Roadmap (Detection→Embedding→Index→Matching) |

### Allgemein
- ✅ **Auto-Erkennung** des Eingabetyps
- ✅ **Multi-Scan** (mehrere Ziele auf einmal)
- ✅ **3 Export-Formate**: JSON, TXT, interaktiver HTML-Report
- ✅ **Modulare Architektur** (eigene Module einfach hinzufügbar)
- ✅ **Progress-Callbacks** (GUI-ready)
- ✅ **Parallele Requests** (ThreadPool)
- ✅ **Optionale API-Keys** für erweiterte Funktionen
- ✅ **Präzise Detektion** – eindeutige Signale statt Rateversuch, mit gekennzeichneten Unsicherheiten
- ✅ **Login-Hinterlegung** (`site_auth`) als Ergänzung vorhandener Profilregeln; ohne verlässliche Regel bleibt die Quelle manuell
- ✅ **Kompilierbar als Windows-EXE** (PyInstaller)
- ✅ **Native Desktop-App** mit Ergebnistabelle, Details, Filtern und echtem Scan-Abbruch
- ✅ **Portables Windows-ZIP**: entpacken und EXE starten, ohne Python-Installation

### Zuverlässigkeit von Scans und Exporten

- Öffentliche Profile sind von Personenidentität zu unterscheiden. Derselbe Username
  auf zwei Seiten kann zwei verschiedenen Personen gehören. Namenstreffer bleiben Hinweise.
- Standardmäßig zeigt **Prüfergebnisse** nur Analysen/Abfragen, keine generierten
  Suchmaschinenlinks. Diese Links stehen unter **Manuelle Quellen** und werden nicht
  automatisch abgefragt. Die Zusammenfassung zählt sie getrennt von Prüfergebnissen.
- Die Desktop-Filter **Unbestätigt** und **Manuelle Quellen** trennen Hinweise von
  belegten Treffern. Details nennen den Grund und, bei Profilen, den Prüf-Endpunkt.
- E-Mail-Suchen fragen zusätzlich öffentliche GitLab- und ORCID-Profile ab,
  parallel zur GitHub-Prüfung. Nur die exakt veröffentlichte E-Mail-Adresse gilt
  als Profilbezug; private/fehlende E-Mail-Felder und reine Suchtreffer bleiben unbestätigt.
- Neue Plattformen: Codeberg, Gitea.com, Debian Salsa, GNOME GitLab, KDE Invent,
  Codewars, Codeforces, Scratch, Discogs, iNaturalist, Open Library, Launchpad,
  Lemmy.world, Lemmy.ml, OpenStreetMap, MusicBrainz, AtCoder und BoardGameGeek.
- Zusätzliche Namensrecherche: OpenAlex, ORCID, Semantic Scholar, PubMed, Internet
  Archive, Wikidata, Companies House, SEC EDGAR, ICIJ Offshore Leaks, OpenSanctions.
  Diese Links lösen keine automatische Recherche aus und sind keine Treffer.
- JSON-Profile benötigen einen Request; nur mögliche HTML-Treffer erhalten eine
  zusätzliche Gegenprobe mit zufälligem Nutzernamen. Antworten sind auf 2 MiB begrenzt.
  Es kommen keine Laufzeitabhängigkeiten hinzu. Zusätzliche Quellen/Gegenproben können
  die Dauer eines Online-Scans erhöhen; keine pauschale Geschwindigkeitsgarantie.
- Profilregeln und Fehlantworten sind durch Offline-Regressionsfälle geprüft.
  Ein flächendeckender Live-Test aller Anbieter war in der eingeschränkten Build-
  Umgebung nicht möglich. API-/Seitenänderungen, Sperren und Rate-Limits können Quellen
  weiterhin unbestätigt machen; die App versucht diese Sperren nicht zu umgehen.

- Die automatische Erkennung unterstützt gültige IPv4-/IPv6-Adressen,
  internationale Domainnamen und HTTP(S)-URLs mit Ports, Pfaden und Query-Parametern.
  Das Domain-Modul verwendet daraus den Hostnamen; ein angegebener Port wird nicht gescannt.
- CLI und Web-API akzeptieren Eingaben bis 2.048 Zeichen. Ungültige JSON-Anfragen
  und unbekannte Eingabetypen liefern in der Web-API verständliche Fehlermeldungen.
- Die Web-Oberfläche verhindert Doppelstarts, begrenzt jede Serveranfrage auf 15 Sekunden
  und wiederholt fehlgeschlagene Statusabfragen höchstens zweimal hintereinander.
  Ein Verbindungsabbruch in der Oberfläche beendet den Scan auf dem Server nicht.
- Jeder Export erhält einen eindeutigen Dateinamen. JSON, TXT und HTML eines Exports
  teilen denselben Namen vor der Dateiendung, auch bei parallelen Scans desselben Ziels.
- Modulfehler sind in der Oberfläche und im HTML-Report sichtbar. Verschachtelte Daten
  bleiben im TXT-Report erhalten; `false` und `0` werden in Detailansichten angezeigt.
- Externe Ergebnislinks werden auf unterstützte URL-Schemata geprüft und für HTML
  maskiert. Der Warnungsfilter der Oberfläche schließt kritische Ergebnisse ein.

---

## 🚀 Schnellstart

### Empfohlen: kleine Desktop-App für Windows

Die Desktop-App öffnet ein eigenes Fenster ohne Webserver. Sie verwendet dieselben
sechs Analysemodule. Eingabe und Typauswahl stehen oben, darunter Fortschritt,
Ergebnisliste und Details. Über **Quelle öffnen** werden ausgewählte externe Links
im Standardbrowser geöffnet. **Abbrechen** beendet den Scan-Prozess; das Fenster
bleibt bedienbar. Ergebnisse werden erst mit **Speichern…** als HTML, JSON oder TXT
auf die Festplatte geschrieben. Es gibt keine automatische Scan-Historie.

**Portable Ausgabe:** `OSINTReconTool-windows-x64.zip` entpacken und
`OSINTReconTool.exe` doppelklicken. Auf dem Zielrechner ist keine Python-Installation
nötig. Die EXE enthält Python, Tcl/Tk, die Kern-Abhängigkeiten und alle JSON-Datentabellen.
Online-Abfragen benötigen weiterhin Internet. Die optionale lokale ML-Gesichtserkennung
ist nicht Teil dieses schlanken Builds.

**EXE selbst bauen (auf Windows, Python 3.11+ mit Tcl/Tk):**

`osint_tool/BUILD_DESKTOP.bat` doppelklicken. Das Skript legt eine getrennte
`.venv-build` an und erzeugt im Repository-Hauptverzeichnis:

```text
dist/OSINTReconTool.exe
dist/OSINTReconTool-windows-x64.zip
```

Alternativ im Repository-Hauptverzeichnis:

```powershell
python -m pip install -r osint_tool/requirements-build.txt
python osint_tool/build.py
```

**GitHub Actions:** Der Workflow **Portable Windows desktop** baut auf einem
Windows-Runner, prüft die fertige EXE mit einer fiktiven Telefonnummer und allen
drei Exportformaten und stellt das ZIP als Workflow-Artefakt bereit. Er veröffentlicht
selbst kein Release. Der separate Release-Workflow übernimmt geprüfte Desktop-Pakete. Die Windows-EXE muss auf Windows gebaut werden; ein Linux-Build ist
keine Windows-EXE. Die App ist nicht digital signiert.

**Direkt aus dem Quellcode starten:**

```bash
python -m pip install -r osint_tool/requirements-desktop.txt
python -m osint_tool.desktop
# Windows: alternativ osint_tool/START_DESKTOP.bat
```

Unter Linux ist zusätzlich das Distributionspaket `python3-tk` erforderlich.
Ausgeliefert wird ausschließlich die Desktop-App. Alte Web-/Terminaldateien sind nur noch Entwicklungsquellen und werden weder eingebettet noch mitinstalliert.

### Schlanke Laufzeit ohne gekürzte Analysen

Desktop und Terminal benötigen nur **drei direkte Zusatzbibliotheken**:

| Bibliothek | Warum sie erhalten bleibt |
|------------|---------------------------|
| `requests` | HTTP-Verbindungen mit Pooling, Wiederholungen, Cookies, Proxies, TLS-Prüfung und korrekter Textdekodierung |
| `phonenumbers` | Vollständige Länder-, Carrier-, Orts- und Zeitzonen-Metadaten; die abgespeckte `phonenumberslite`-Variante würde Funktionen verlieren |
| `dnspython` | Vollständige DNS-Auflösung und Unterstützung aller verwendeten Record-Typen |

`requests` benötigt zusätzlich `urllib3`, `certifi`, `idna` und `charset-normalizer`.
Diese vier indirekten Abhängigkeiten bleiben für Verbindungsqualität, Zertifikate,
internationale Domains und Zeichensätze erhalten. Tkinter/Tcl/Tk kommt mit Python
und wird in die EXE eingebettet; eine zusätzliche GUI-Bibliothek ist nicht nötig.

Die gemeinsamen Analyse-Abhängigkeiten stehen in `requirements-core.txt`.
`requirements-desktop.txt` enthält keinen Webserver. `requirements.txt` installiert ebenfalls nur die Desktop-Abhängigkeiten.
Flask steht ausschließlich in `requirements-test.txt` für Regressionstests des alten Webcodes. `requirements-build.txt` ergänzt
PyInstaller ausschließlich für den Build-Rechner.

Die EXE schließt Build-Werkzeuge, Test-Frameworks und ungenutzte Hilfsprogramme aus.
Der HTTP-Stack wird erst bei der ersten Online-Abfrage geladen. Eine Telefonanalyse
ohne NumVerify-Key lädt ihn gar nicht. Verbindungs-Pooling, Request-Parallelität,
Prüfquellen und Analyse-Metadaten werden dabei nicht reduziert.

Jeder Build prüft die fertige EXE auf sämtliche Telefon-Metadaten, dynamische
DNS-Record-Module und TLS-Zertifikatsdaten. Der Bericht `dist/OSINTReconTool-build.json`
enthält die tatsächliche Größe und die eingebetteten Abhängigkeitsversionen.
Der Windows-Workflow baut in einer getrennten Umgebung mit den Desktop-Abhängigkeiten
und prüft danach zusätzlich HTTP/TLS, DNS, sämtliche Telefonregionen, GUI und Export.

Gemessener Vergleich des lokalen Testbuilds: etwa 7 % kleiner und 20 % schneller
bis zum App-Fenster. Methode, Umfang und Grenzen: [Messbericht](PERFORMANCE.md).

### Ein einziger Download

Auch die bisherige Downloadadresse `v0.8-alpha/osint_tool.zip` wird mit dem
portablen Desktop-ZIP bedient. `START.bat` öffnet ausschließlich die EXE.
Es gibt keine automatische Python- oder Paketinstallation beim Start.
Die Build-Prüfung verhindert, dass Web- oder Terminalmodule in der EXE landen.

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

Bei der **portablen EXE** liegt `config.local.json` direkt **neben der EXE**.
Die App liest diesen Ort auch beim Start über eine Verknüpfung oder aus einem
anderen Arbeitsverzeichnis. Nach Änderungen die App neu starten. Der Build erzeugt
eine leere eingebettete Konfiguration; lokale API-Keys und Logins werden nicht in
die EXE oder das ZIP kopiert. Umgebungsvariablen haben weiterhin Vorrang.

Als Exportziel schlägt die Desktop-App `user-data/results` neben der EXE vor.
Ist der Ordner schreibgeschützt, verwendet sie `%LOCALAPPDATA%/OSINTReconTool/results`.
Im Speichern-Dialog kann immer ein anderer Zielordner gewählt werden. Beim Start
aus dem Quellcode liegt der Standard-Exportordner im Benutzerprofil.

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

### Regressionstests

Aus dem Repository-Hauptverzeichnis (nach Installation der Python-Abhängigkeiten):

```bash
python -m unittest discover -s tests -v
node --test tests/web_ui.test.cjs
# Linux-CI mit virtuellem Display, inklusive echter Tk-Widgets:
xvfb-run -a python -m unittest discover -s tests -v
```

Die Tests benötigen keine API-Keys und fragen keine externen OSINT-Dienste ab.
Die JavaScript-Tests benötigen Node.js 22 oder neuer, aber keine npm-Pakete.
Geprüft werden unter anderem Eingabevalidierung, Scan-Isolation nach Fehlern,
parallele lokale Telefonanalysen mit Downloads, sichere Ergebnisdarstellung und
das Verhalten der Oberfläche bei verzögerten Antworten und Verbindungsfehlern.
Desktop-Tests prüfen außerdem Prozess-Abbruch und Neustart, native Ergebnisansicht,
Export sowie Konfigurationspfade der portablen App. Ohne Display werden nur die
beiden Tk-Widget-Tests übersprungen. Der Windows-Workflow prüft zusätzlich die
fertige EXE aus einem anderen Arbeitsverzeichnis.
GitHub Actions führt diese Prüfungen bei Änderungen am Tool und an den Tests aus.

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
