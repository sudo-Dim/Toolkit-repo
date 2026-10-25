# Größe und Startverhalten der Desktop-App

Messung vom 25.10.2026. Vergleich des vorherigen Desktop-Builds mit dem bereinigten
Build, bei identischer Python- und Bibliotheksversion in derselben Linux-x64-Umgebung.
Windows-Werte müssen auf dem Windows-Build ermittelt werden.

| Messwert | Vorher | Nachher | Veränderung |
|----------|--------|---------|-------------|
| Ausführbare Einzeldatei | 24.716.488 Bytes | 22.933.680 Bytes | −7,2 % |
| Portables ZIP | 23.868.148 Bytes | 22.091.273 Bytes | −7,4 % |
| Start bis zum ersten App-Fenster, Median | 0,298 s | 0,237 s | −20,5 % |

Methode: sieben Starts je Version in wechselnder Reihenfolge mit bereits gefülltem
Dateisystem-Cache; Messung vom Prozessstart bis zum Erscheinen des X11-Fensters.
Python 3.12, Tcl/Tk 9. Die Ergebnisse sind Vergleichswerte dieser Umgebung und keine
Garantie für Kaltstarts, Virenscanner oder die Startzeit auf einem anderen Rechner.

## Was geändert wurde

- Nicht benötigte Build-, Test- und Dokumentationswerkzeuge werden aus der EXE
  ausgeschlossen, unter anderem setuptools und dessen indirekte Abhängigkeiten.
- Die vorhandenen PyInstaller-Hooks nehmen sämtliche Telefon-Metadaten und
  dynamischen DNS-Record-Typen mit; unnötiges pauschales Sammeln entfällt.
- HTTP-Bibliotheken werden erst bei einer Online-Abfrage geladen. Der GUI-Start
  und reine Telefonanalysen ohne NumVerify benötigen sie nicht im Arbeitsspeicher.
- Desktop-, Web- und Build-Abhängigkeiten sind getrennt. Der Windows-Workflow baut
  in einer eigenen Umgebung mit ausschließlich den Desktop-/Build-Abhängigkeiten.

## Erhaltene Funktionen und Prüfungen

- Drei direkte Laufzeit-Abhängigkeiten: requests, phonenumbers und dnspython;
  die vier notwendigen HTTP-Abhängigkeiten und Tcl/Tk bleiben ebenfalls enthalten.
- Alle 594 phonenumbers-Module und 84 dns.rdtypes-Module aus dem vorherigen Paket
  sind unverändert vorhanden. Region-, Carrier-, Orts- und Zeitzonendaten werden
  nicht beschnitten.
- Prüfung aller 245 unterstützten Telefonregionen sowie nicht geografischer
  Landeskennzahlen; neun DNS-Record-Typen werden serialisiert und zurückgelesen.
- Zertifikatsspeicher, TLS-Prüfung, HTTP-Pooling, Wiederholungen, Weiterleitungen,
  Cookies, Zeichensatzdekodierung und die optionale NumVerify-Abfrage sind geprüft.
- Der vollständige Bericht zur fiktiven Telefonnummer +12025550123 stimmt mit
  dem vorherigen Build überein, abgesehen von Zeitstempeln und Laufzeitangaben.
- 30 Python-Tests und 9 JavaScript-Tests bestehen. Der fertige Linux-Build besteht
  zusätzlich den GUI-, Prozess-, Metadaten- und Export-Selbsttest.

Online-Quellen und deren Antwortzeiten wurden für diese Messung nicht verändert
oder live verglichen. Der Buildbericht `dist/OSINTReconTool-build.json` dokumentiert
die tatsächlich eingebetteten Versionen, Modulzahlen und Dateigröße jedes Builds.
