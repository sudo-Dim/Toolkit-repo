# Portable Windows-Programme

Diese beiden eigenstaendigen Programme stammen aus den bisherigen Toolkit-Releases:

| Programm | Ursprung | Neue Startdatei |
| --- | --- | --- |
| Security Dashboard / Diagnostic | `v0.5-alpha/SecurityDashboard.zip` | `SecurityDashboard.exe` |
| Windows Debloat | `v0.7-alpha/WindowsDebloatSetup.zip` | `WindowsDebloat.exe` |

Die EXEs sind portable Einzeldateien fuer Windows 10/11 x64. Sie verwenden das
vorhandene Windows PowerShell 5.1, .NET Framework und Windows Forms. **Keine
Python-Installation, kein Browser-Frontend und keine nachzuinstallierenden
Laufzeitpakete.** Im EXE stecken komprimierte Skripte; beim Start werden sie in
einen eigenen temporaeren Ordner entpackt und beim normalen Beenden entfernt.
Die Programme sind nicht signiert. Auf verwalteten Rechnern koennen Richtlinien
die Ausfuehrung von EXEs oder PowerShell einschraenken.

## Start und Build

Fertige Pakete liegen unter `dist/windows-tools/` im Repository-Stamm. Das ZIP
entpacken und die jeweilige EXE starten. Debloat fordert Administratorrechte an;
das Dashboard kann ohne diese starten und kennzeichnet nicht lesbare Daten.
Fuer vollstaendige Sicherheitsprotokolle das Dashboard als Administrator starten.

Alternativ im Quellcode `START_DIAGNOSTIC.bat` oder `START_DEBLOAT.bat` starten.
`BUILD.bat` baut beide EXEs auf Windows mit dem vorhandenen .NET-Framework-Compiler.
Auch der Build benoetigt weder Python noch Downloads von Build-Paketen.
Der Workflow **Portable Windows utilities** baut und prueft die Programme auf
Windows und stellt die ZIPs als Artefakte bereit; er veroeffentlicht keine Releases.

## Dashboard

**Erfassen** liest System, Hardware, Prozesse, Netzwerk, Ereignisse, Benutzer,
Administratoren, Firewall, Autostart, Aufgaben und Sicherheitskonfiguration.
Die Erfassung laeuft im Hintergrund und laesst sich abbrechen. Die Tabellen sind
schreibgeschuetzt. HTML und JSON lassen sich bei Bedarf exportieren; ein Browser
wird nicht automatisch gestartet. Ereignisse: letzte 24 Stunden, maximal 50 pro
Abfrage. Prozesse: die ersten 15 nach kumulierter CPU-Zeit. Aufgaben: maximal 30
aktive Aufgaben ausserhalb des Microsoft-Pfades, wie im bisherigen Programm.

Fehlende Leserechte stehen unter **Erfassungsfehler**. Nicht lesbare SMB-, RDP-,
UAC- und Defender-Werte gelten als **Unknown**, nicht als nachgewiesenes Problem.
Ein leeres Ereignisprotokoll ist von einer fehlgeschlagenen Abfrage unterscheidbar.

CLI fuer einen lokalen Bericht ohne GUI:

```powershell
$data = & ./diagnostic/Collect-Diagnostics.ps1 -OutputPath ./report.html
$data.Errors
```

Windows-Systemereignisse sind historische Meldungen des Betriebssystems. Die
Stufe Critical/Error/Warning stammt aus Windows und belegt weder eine bestimmte
Ursache noch einen Fehler des Dashboards. Erfassungsfehler stehen separat.
Im Reiter Systemereignisse zeigt die ausgewaehlte Zeile unten den vollstaendigen,
kopierbaren Meldungstext. Im HTML-Export laesst sich jede Meldung aufklappen.
Datum mit Jahr und RecordID helfen beim Wiederfinden in der Ereignisanzeige.

## Debloat

1. Umfang waehlen und **Erfassen** klicken. Es wird dabei nichts deinstalliert.
2. Einzelne App-Pakete, Vorlagen fuer neue Benutzer und optionale Aenderungen
   auswaehlen. Alle 107 bisherigen App-Suchmuster und 11 Muster fuer signierte, systemweit installierte klassische
   Programme sind im Katalog erhalten. Ueberlappende Treffer erscheinen einmal.
3. **Auswahl anwenden** zeigt die vollstaendige, scrollbare Aktionsliste.
4. Nach Bestaetigung werden nur diese Aktionen ausgefuehrt. Das Ergebnis zeigt
   Erfolg, Fehler und Warnungen pro Aktion. Nach einem Lauf erneut erfassen.

Brave, OneDrive, Telemetrie, Dienste, Windows-Features, Game Bar und Taskbar sind
einzeln waehlbar. SysMain und Windows-Suche bleiben standardmaessig unveraendert:
ihr Abschalten ist keine allgemeingueltige Beschleunigung. Fuer Brave wird die
Authenticode-Signatur samt Herausgeber vor der Ausfuehrung geprueft. Die App
oeffnet keine Standard-App-Einstellungen und startet den Explorer nicht neu.
Eine Aenderung des Standardbrowsers erfolgt bei Bedarf manuell in Windows.
Benutzerspezifische HKCU-Uninstaller und unsignierte Programme werden nicht mit
Administratorrechten ausgefuehrt; dafuer die Windows-Appverwaltung verwenden.
Klassische EXE-Uninstaller werden nur mit einem registrierten QuietUninstallString
gestartet; MSI-Deinstallationen verwenden /qn /norestart. Fehlt ein solcher Modus,
wird die Aktion mit Begruendung als Skipped protokolliert. Es werden keine
interaktiven Dialoge versteckt und keine Silent-Parameter geraten. Unterprozesse
laufen ohne sichtbare Konsole, mit leerem Eingabekanal und verdecktem Startfenster;
Fehlerausgaben erscheinen im Ergebnis statt in zusaetzlichen Fenstern. Ob ein
Fremdhersteller seinen registrierten Silent-Modus einhaelt, liegt bei dessen
Uninstaller. Die Windows-Administratorabfrage und die Bestaetigung der Auswahl
bleiben sichtbar. Es gibt keine abschliessende Enter-Aufforderung; nach dem Lauf
zeigt die App das Ergebnis und leert die Auswahl.

Ein Wiederherstellungspunkt wird vor den Aenderungen versucht; Fehler dabei sind
im Ergebnis sichtbar. Das ist keine Garantie fuer eine vollstaendige Ruecknahme
von App-Deinstallationen. Es werden keine OneDrive-Nutzerordner geloescht. Die
Benutzereinstellungen betreffen das Konto, unter dem das Programm ausgefuehrt wird.

Protokolle und vorherige Registry-Werte liegen unter
`%PROGRAMDATA%\WindowsDebloat-<ID>\result.json`. Entfernte
Taskbar-Verknuepfungen werden dort im Unterordner `TaskbarPins` gesichert.
Registry-Sicherungen dienen der manuellen Wiederherstellung; eine automatische
Undo-Funktion wird nicht vorgetaeuscht. Windows wird nicht zwangsweise neu
gestartet. Taskbar-Aenderungen koennen erneutes Anmelden erfordern; erforderliche
Neustarts stehen im JSON-Protokoll. Ein laufender Aenderungsvorgang wird nicht
gewaltsam abgebrochen.

Fuer Skripte definiert `debloat/Debloat.Core.ps1` Funktionen, ohne beim Laden etwas
zu aendern. `Invoke-DebloatPlan` unterstuetzt `-WhatIf`. Inventarisierung und
Ausfuehrung sind getrennt; Paket-IDs aus dem Inventar werden exakt uebernommen.

## Pruefung und Grenzen

```powershell
powershell.exe -NoProfile -File ./tests/Core.Tests.ps1
```

Die Kernpruefungen verwenden simulierte Windows-Provider und nehmen keine
Systemaenderungen vor. Zusaetzlich prueft der Windows-Workflow beide echten GUIs,
ihre Hintergrund-Worker und eine reale, nur lesende Diagnose. `--self-test` am EXE
oeffnet und schliesst die GUI mit Testdaten; Debloat wird dabei nicht angewendet.

Die Windows-Builds und beide GUI-Starttests bestehen auf dem GitHub-Windows-Runner
(Windows Server 2025 mit Windows PowerShell 5.1). Auch eine reale, nur lesende
Diagnose mit HTML-Export wurde dort geprueft. Reale Deinstallationen wurden nicht
ausgefuehrt; diese muessen auf einer entbehrlichen Windows-Testinstallation
validiert werden. Einzelheiten: [PERFORMANCE.md](PERFORMANCE.md).
