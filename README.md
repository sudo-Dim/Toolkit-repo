# OSINT Recon Toolkit

Modulares Analyse-Toolkit mit einer kleinen nativen Desktop-App für Windows.

- **Desktop starten:** `osint_tool/START_DESKTOP.bat` oder `python -m osint_tool.desktop`.
- **Portable EXE bauen:** `osint_tool/BUILD_DESKTOP.bat` auf Windows doppelklicken
  (Python 3.11+ mit Tcl/Tk muss nur auf dem Build-Rechner installiert sein).
- **Fertiges Paket:** `dist/OSINTReconTool-windows-x64.zip` entpacken und die EXE starten.
  Auf dem Zielrechner werden weder Python noch ein Webserver benötigt.
- **GitHub Actions:** Der Workflow „Portable Windows desktop“ baut und prüft die EXE
  und stellt das portable ZIP als Artefakt bereit.

Die Oberfläche bietet Typ-Erkennung, Fortschritt, Abbruch, Ergebnisfilter,
Detailansicht und Exporte in HTML, JSON und TXT. Ausgeliefert wird ausschließlich die Desktop-App; alte Web-/Terminalquellen
werden nicht eingebettet oder mitinstalliert. Online-Abfragen benötigen Internet.

Die Desktop-Laufzeit hat drei direkte Zusatzbibliotheken: `requests`, `phonenumbers`
und `dnspython`. Die GUI verwendet das mitgelieferte Tkinter. HTTP wird erst bei
Bedarf geladen; Build- und Webwerkzeuge werden nicht in die Desktop-EXE eingebettet.
Alle Länder-/Carrier-Metadaten und DNS-Record-Typen bleiben erhalten und werden beim
Build automatisch auf Vollständigkeit geprüft.

Installation, Konfiguration und Tests: [Dokumentation](osint_tool/README.md).

Die eigenstaendigen Programme **Security Dashboard** und **Windows Debloat** sind
ebenfalls als kleine portable Windows-GUIs verfuegbar. Beide verwenden vorhandene
Windows-Komponenten und benoetigen keine Python-Installation oder externen
Laufzeitpakete. Quellcode, Bedienung und Build: [Windows-Programme](windows_tools/README.md).
