# Sicherheitsprüfung und Desktop-Auslieferung

Geprüfter Umfang: alle sechs OSINT-Module, Desktop-/Alt-Web-/Terminalstarter,
Konfigurations- und Exportcode, Windows Diagnostic, Windows Debloat, EXE-Starter,
Build- und Release-Workflows sowie Paketabhängigkeiten. Keine Untersuchung des
privaten Rechners; keine echten Systemänderungen oder Deinstallationen im Test.

Im gelesenen eigenen Quellcode wurde keine absichtliche Backdoor gefunden:
keine Reverse Shell, kein heimlicher Fernsteuerungsdienst, kein Keylogger,
keine automatische Installation von Persistenz und kein Auslesen persönlicher
Browserpasswörter. Das ist ein begrenztes Prüfergebnis, keine Unbedenklichkeits-
garantie für alle Rechner, externe Bibliotheken oder künftige Änderungen.

## Behobene Risiken

- Der alte START.bat-Download/Installationspfad wurde entfernt. Standardstarts
  öffnen ausschließlich die Desktop-App; beim Start wird nichts nachinstalliert.
- Release-ZIPs werden aus geprüften EXEs gebaut. Web-/Terminalcode und Flask
  werden nicht eingebettet oder ausgeliefert; eine Paketprüfung erzwingt das.
- HTTP übernimmt keine Zugangsdaten aus persönlichen .netrc-Dateien. Bei einem
  Originwechsel werden Login-, Cookie- und API-Header entfernt. HTTPS-Downgrades
  und das Weiterleiten von Request-Bodies an fremde Origins werden blockiert.
- Direkte HTTP/TLS-Verbindungen prüfen die DNS-Adressen und verbinden numerisch
  mit geprüften öffentlichen Adressen, um einen zweiten DNS-Wechsel auf private
  Ziele zu verhindern. Eigene, konfigurierte Proxies bleiben Vertrauensstellen:
  ihre tatsächliche DNS-Auflösung lässt sich vom Client nicht erzwingen.
- UNC-/Gerätepfade und file:-URLs für Bilder werden vor Dateizugriffen abgewiesen,
  damit ein Bildpfad keine unbeabsichtigte SMB-Anmeldung auslöst.
- Mail.ru-Passwort-Recovery und Amazon/eBay-Login-Flows laufen nicht automatisch.
  Sie werden als manuell zu prüfen ausgewiesen. Keine automatische Reset-/OTP-
  Anforderung. Die übrigen OSINT-Abfragen bleiben aktive Internetanfragen.
- API-Schlüssel werden in protokollierten Modulfehlern maskiert. Der unverschlüsselte
  IP-Geo-Fallback wurde entfernt; die HTTPS-Abfrage bleibt erhalten.
- Der im Entwicklungsquellcode verbliebene Webserver akzeptiert nur Loopback,
  prüft Host/Origin, verwendet einen lokalen Sitzungsschlüssel und Schutz für
  POST-Anfragen, begrenzt parallele Scans und deaktiviert den Debugger.
- Windows-EXEs entpacken Skripte mit expliziten ACLs. Bei erhöhten Rechten dürfen
  nur Administratoren und SYSTEM schreiben. PowerShell lädt nur Windows-Module
  aus dem Systemverzeichnis; PATH und temporäre Verzeichnisse werden begrenzt.
- Debloat führt keine HKCU-Deinstallationseinträge erhöht aus. Klassische
  Uninstaller müssen lokal, explizit adressiert und gültig signiert sein;
  Skriptinterpreter werden zurückgewiesen. Ungeeignete Uninstaller sind manuell
  über Windows zu entfernen. Signaturprüfung allein ersetzt keine Vertrauens-
  entscheidung über bereits installierte Drittanbietersoftware.
- Brave-Downloads und Debloat-Protokolle liegen in gesonderten Verzeichnissen
  mit geschützten ACLs. Brave wird nur nach Auswahl und gültiger Herausgeber-
  Signatur gestartet. Fehler werden nicht als erfolgreiche Deinstallation gezählt.

## Verbleibende Auswirkungen und Grenzen

OSINT ist nicht offline/anonym: Suchwerte (z.B. E-Mail, Username, Domain) werden
an die abgefragten Anbieter geschickt. Diese sehen die öffentliche IP und können
Anfragen protokollieren. Manuell geöffnete Ergebnislinks verlassen ebenfalls den
Rechner. Das Bildmodul lädt keine lokalen Bilder automatisch hoch. Telefonnummern
werden ohne optionalen NumVerify-Schlüssel lokal ausgewertet.

Das Diagnostic-Programm liest lokal sensible Angaben (Benutzer, Prozesse,
Netzwerkverbindungen, Seriennummer, Ereignisse). Es hat keinen eigenen Upload-
Code; exportierte Berichte sollten entsprechend vertraulich behandelt werden.

Debloat ist ausdrücklich ein Systemänderungswerkzeug. Gewählte Deinstallationen,
Dienst-/Registryänderungen, deaktivierte Suche/SysMain, OneDrive oder McAfee
können Funktionen, Leistung, Synchronisierung oder Schutz beeinträchtigen.
Keine dieser Änderungen ist vorausgewählt. Vor Anwendung wird die genaue Liste
gezeigt. Ein Wiederherstellungspunkt kann scheitern und ersetzt kein Backup.

API-Schlüssel und explizit hinterlegte Login-Cookies sind lokale Klartext-
Konfiguration. Die EXEs enthalten keine solchen Schlüssel. Wer das laufende
Benutzerkonto oder Administratorrechte bereits kontrolliert, liegt außerhalb
jeder hier behaupteten Schutzgrenze. Externe Antworten, Drittanbieterprogramme,
Windows und Bibliotheken bleiben zusätzliche Angriffsflächen.

## Nachweise

- Regressionstests unter tests/test_security.py: lokale Webzugriffe, Token,
  Parallelitätslimit, Header/Body-Redirects, .netrc, API-Key-Maskierung, UNC-Pfade,
  private Netzwerkziele und unterbundene Recovery-/Login-Aufrufe.
- Bestehende Analyse-, Export-, Prozess- und GUI-Tests; PowerShell-Kerntests
  mit simulierten Windows-Providern. Keine echten App-Deinstallationen.
- pip-audit des aufgelösten Build-/Web-/Desktop-Abhängigkeitsstands meldete keine
  bekannten Schwachstellen. Desktop-Versionen wurden daraufhin festgeschrieben.
  Das ist kein Beweis, dass ein Paket frei von unbekannten Fehlern oder Malware ist.
- Windows-Workflows prüfen die echten EXEs vor einer Veröffentlichung.
