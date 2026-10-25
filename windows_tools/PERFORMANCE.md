# Umfang, Abhaengigkeiten und Pruefung

Vergleich mit den originalen Release-Dateien `SecurityDashboard.zip` aus
`v0.5-alpha` und `WindowsDebloatSetup.zip` aus `v0.7-alpha`.

## Weniger Abfragen

| Abfrage pro Durchlauf | Bisher | Jetzt |
| --- | --- | --- |
| Dashboard: Betriebssystem-CIM | 2 | 1 |
| Dashboard: Prozessor-CIM | 2 | 1 |
| Dashboard: Prozessabfragen bei N Netzwerkverbindungen | N + 2 | 1 |
| Debloat: provisionierte Pakete bei 107 Suchmustern | 107 | 1 im Modus Alle Benutzer; sonst 0 |
| Debloat: installierte AppX-Pakete | 107 bis 214 | 1 |
| Debloat: klassische Uninstall-Registry | 22 Abfragen | maximal 2; HKCU wird aus Sicherheitsgruenden ausgeschlossen |

Die Werte fuer den bisherigen Code ergeben sich aus seinen Schleifen und
Aufrufstellen. Die neuen Paket-, Registry-, CIM- und Prozessabfragen werden mit
Zaehlern in `tests/Core.Tests.ps1` kontrolliert. Der Diagnosetest verwendet
20 Netzwerkverbindungen; alle behalten ihren Prozessnamen. Die Regex fuer
App-Muster wird einmal aufgebaut und enthaelt nur maskierte Literalnamen.

Feste Wartezeiten von 10, 3, 2 und 1 Sekunden aus dem alten Debloat-Ablauf entfallen.
Stattdessen wartet der Code auf den jeweiligen Installer und prueft dessen
Exitcode. Es gibt keine Behauptung eines gemessenen Windows-Laufzeitgewinns:
Netzwerk, CIM/DISM, Uninstaller und Systemzustand bestimmen die reale Dauer.

## Groesse und Laufzeit

Beide Programme verwenden **null externe Laufzeitpakete**. Windows PowerShell 5.1,
.NET Framework und Windows Forms sind auf den unterstuetzten Windows-Systemen
vorhanden. Kein Python, Electron, WebView, Node.js oder eingebetteter Webserver.
Das Dashboard laedt `System.Web` nicht mehr; HTML-Escaping verwendet `System.Net`.

Die Einzel-EXEs enthalten einen kleinen C#-Starter und komprimierte Skripte. Die
genauen Bytegroessen und SHA-256-Pruefsummen stehen im erzeugten
`dist/windows-tools/build-info.json`. Die zusaetzlichen GUIs, die Aktionsauswahl
und Fehlerbehandlung vergroessern die ZIPs gegenueber den alten reinen
Skriptpaketen (10.541 und 8.774 Bytes). Das wird nicht als Dateigroessenreduktion
ausgegeben. Der Gewinn liegt in der kleinen portablen GUI, weniger Abfragen und
belastbareren Ergebnissen bei weiterhin null nachzuinstallierenden Abhaengigkeiten.

## Validierung

- Parser- und Funktionspruefungen unter PowerShell 7 auf Linux, mit simulierten
  Windows-Providern: Abfragezahlen, erhaltene Kandidaten, Deduplizierung,
  Deinstallationsfehler, Exitcodes, Nur-Benutzer-Umfang, WhatIf, IPv6,
  HTML-Escaping, deutsche Dezimaldarstellung und unbekannte Sicherheitswerte.
- Windows-PE-Dateien gegen die offiziellen .NET-Framework-4.8-Referenzassemblies
  kompiliert; komprimierte Ressourcen entsprechen den Quelltexten.
- Windows PowerShell 5.1, GUI-Start, echte CIM-Abfragen und Deinstallationen wurden
  hier **nicht** ausgefuehrt. Der hinzugefuegte Windows-Workflow deckt Build,
  Kernpruefungen, GUI-Start und nur lesende Erfassung ab. Destruktive Aktionen
  muessen separat auf einer entbehrlichen Windows-Testinstallation geprueft werden.
