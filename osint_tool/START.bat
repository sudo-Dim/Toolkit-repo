@echo off

REM ===========================================================
REM  OSINT Recon Tool - Launcher
REM  Fenster bleibt IMMER offen. Jeder Schritt wird angezeigt.
REM ===========================================================

REM Sicherheitsnetz: Fenster schliesst sich NIE von alleine
if "%~1"=="" (
    cmd /k "%~f0" run
    exit /b
)

REM "restart" Modus: Wurde nach Python-Installation neu gestartet
if "%~1"=="restart" (
    echo.
    echo   [*] Neustart nach Python-Installation...
    echo.
)

setlocal EnableDelayedExpansion
title OSINT Recon Tool
color 0F

echo.
echo  ===========================================================
echo   OSINT RECON TOOL - Launcher v1.0
echo  ===========================================================
echo.
echo   Jeder Schritt wird angezeigt.
echo   Dieses Fenster bleibt offen.
echo.
echo  -----------------------------------------------------------
echo   SCHRITT 1 von 4: Suche Python...
echo  -----------------------------------------------------------
echo.

set PYTHON_CMD=

REM -- Test 1: "python" --
echo   [Test] python --version
python --version 2>nul
if %ERRORLEVEL% equ 0 (
    set PYTHON_CMD=python
    echo   [OK]   python gefunden.
    goto :python_ok
)
echo   [--]   python nicht im PATH.

REM -- Test 2: "python3" --
echo   [Test] python3 --version
python3 --version 2>nul
if %ERRORLEVEL% equ 0 (
    set PYTHON_CMD=python3
    echo   [OK]   python3 gefunden.
    goto :python_ok
)
echo   [--]   python3 nicht im PATH.

REM -- Test 3: "py" Launcher --
echo   [Test] py --version
py --version 2>nul
if %ERRORLEVEL% equ 0 (
    set PYTHON_CMD=py
    echo   [OK]   py Launcher gefunden.
    goto :python_ok
)
echo   [--]   py Launcher nicht gefunden.

REM -- Test 4: Bekannte Ordner --
echo   [Test] Bekannte Installationspfade...

for %%V in (313 312 311 310) do (
    set "TRYPATH=%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe"
    if exist "!TRYPATH!" (
        echo   [OK]   Gefunden: !TRYPATH!
        set "PYTHON_CMD=!TRYPATH!"
        goto :python_ok
    )
)

for %%V in (313 312 311 310) do (
    set "TRYPATH=C:\Python%%V\python.exe"
    if exist "!TRYPATH!" (
        echo   [OK]   Gefunden: !TRYPATH!
        set "PYTHON_CMD=!TRYPATH!"
        goto :python_ok
    )
)

echo   [--]   Nichts gefunden.
echo.

REM -- Falls wir nach Neustart hier landen: Fehler --
if "%~1"=="restart" (
    echo  ===========================================================
    echo   [FEHLER] Python auch nach Neustart nicht gefunden.
    echo  ===========================================================
    echo.
    echo   Bitte Python manuell installieren:
    echo   1. Oeffne https://www.python.org/downloads/
    echo   2. Klicke "Download Python 3.x"
    echo   3. WICHTIG: Haken bei "Add Python to PATH" setzen!
    echo   4. Danach START.bat erneut doppelklicken.
    echo.
    pause
    exit /b 1
)

REM ===========================================================
REM  Python nicht gefunden --> Installieren
REM ===========================================================

echo  ===========================================================
echo   PYTHON WURDE NICHT GEFUNDEN
echo  ===========================================================
echo.
echo   Python muss installiert werden (einmalig, ca. 1-3 Min).
echo.
echo   Druecke eine beliebige Taste um fortzufahren.
echo   Oder schliesse das Fenster zum Abbrechen.
echo.
pause
echo.

REM -- Versuch 1: winget --
echo   [Test] Ist winget verfuegbar?
winget --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   [OK]   winget gefunden. Starte Installation...
    echo.
    echo          winget install Python.Python.3.13
    echo          Bitte warten, 1-2 Minuten...
    echo.
    winget install Python.Python.3.13 --accept-package-agreements --accept-source-agreements --scope user
    echo.
    if !ERRORLEVEL! equ 0 (
        echo   [OK]   Installation via winget erfolgreich.
        echo.
        goto :auto_restart
    ) else (
        echo   [WARN] winget fehlgeschlagen. Versuche Download...
        echo.
    )
) else (
    echo   [--]   winget nicht vorhanden. Verwende Download.
    echo.
)

REM -- Versuch 2: Download --
echo   [*] Lade Python 3.13 herunter...
echo       Von: python.org
echo       Nach: %TEMP%\python_installer.exe
echo       Bitte warten...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "Write-Host '       Download laeuft...'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.13.2/python-3.13.2-amd64.exe' -OutFile ($env:TEMP + '\python_installer.exe') -UseBasicParsing; Write-Host '       Fertig.' } catch { Write-Host ('       FEHLER: ' + $_.Exception.Message); exit 1 }"

if %ERRORLEVEL% neq 0 (
    echo.
    echo   [FEHLER] Download fehlgeschlagen.
    echo.
    echo   Bitte Python manuell installieren:
    echo   1. Oeffne https://www.python.org/downloads/
    echo   2. Klicke Download Python 3.x
    echo   3. WICHTIG: Haken bei "Add Python to PATH"
    echo   4. Danach START.bat erneut doppelklicken.
    echo.
    pause
    exit /b 1
)

echo   [OK]   Download abgeschlossen.
echo.
echo   [*] Starte Installation (ohne Admin)...
echo       Bitte warten...
echo.

"%TEMP%\python_installer.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_launcher=1 Include_tcltk=0 Include_test=0 Include_doc=0
set INST_EXIT=%ERRORLEVEL%
echo       Installer beendet (Code: %INST_EXIT%).

if %INST_EXIT% neq 0 (
    echo.
    echo   [WARN] Stille Installation fehlgeschlagen.
    echo          Oeffne manuellen Installer...
    echo.
    echo   *** WICHTIG: Haken bei "Add Python to PATH" setzen ***
    echo.
    echo   Druecke eine Taste um den Installer zu oeffnen...
    pause
    echo.
    "%TEMP%\python_installer.exe"
    echo.
    echo   Installer geschlossen.
)

del "%TEMP%\python_installer.exe" >nul 2>&1
echo   [OK]   Installer aufgeraeumt.
echo.

REM ===========================================================
:auto_restart
REM ===========================================================
REM
REM  KERNFIX: CMD kann den PATH nicht in der laufenden Sitzung
REM  aktualisieren. Loesung: Neuen CMD-Prozess starten, der
REM  den frischen PATH automatisch hat.
REM
REM ===========================================================

echo  ===========================================================
echo   Python wurde installiert.
echo   Launcher startet sich jetzt automatisch neu,
echo   damit der neue PATH aktiv wird.
echo  ===========================================================
echo.
echo   Neustart in 3 Sekunden...
timeout /t 3 /noq >nul
echo.

REM Starte ein komplett neues CMD-Fenster mit diesem Script
REM "restart" Parameter signalisiert: Komme von Installation
start "OSINT Recon Tool" cmd /k "%~f0" restart

REM Dieses alte Fenster schliessen
echo   [*] Altes Fenster wird geschlossen...
exit


REM ===========================================================
:python_ok
REM ===========================================================

echo.
echo  -----------------------------------------------------------
echo   SCHRITT 2 von 4: Pruefe pip...
echo  -----------------------------------------------------------
echo.

echo   [Test] !PYTHON_CMD! -m pip --version
!PYTHON_CMD! -m pip --version
if %ERRORLEVEL% neq 0 (
    echo   [WARN] pip fehlt. Installiere...
    !PYTHON_CMD! -m ensurepip --upgrade 2>nul
    if !ERRORLEVEL! neq 0 (
        echo   [*]    Lade get-pip.py herunter...
        powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile ($env:TEMP + '\get-pip.py') -UseBasicParsing"
        !PYTHON_CMD! "%TEMP%\get-pip.py"
        del "%TEMP%\get-pip.py" >nul 2>&1
    )
    echo.
    !PYTHON_CMD! -m pip --version
    if !ERRORLEVEL! neq 0 (
        echo   [FEHLER] pip konnte nicht installiert werden.
        pause
        exit /b 1
    )
)
echo   [OK]   pip ist bereit.


REM ===========================================================
echo.
echo  -----------------------------------------------------------
echo   SCHRITT 3 von 4: Installiere Pakete...
echo  -----------------------------------------------------------
echo.

echo   [Test] Ist Flask installiert?
!PYTHON_CMD! -c "import flask" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   [OK]   Flask vorhanden.
    !PYTHON_CMD! -c "import requests" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        echo   [OK]   requests vorhanden.
        echo   [OK]   Alle Pakete bereits installiert.
        goto :start_server
    )
)

echo   [*]    Installiere Pakete (einmalig)...
echo          !PYTHON_CMD! -m pip install -r requirements.txt
echo.

!PYTHON_CMD! -m pip install -r "%~dp0requirements.txt"

if %ERRORLEVEL% neq 0 (
    echo.
    echo   [WARN] Erster Versuch fehlgeschlagen.
    echo   [*]    Versuche mit --user ...
    echo.
    !PYTHON_CMD! -m pip install --user -r "%~dp0requirements.txt"
    if !ERRORLEVEL! neq 0 (
        echo.
        echo   [FEHLER] Paket-Installation fehlgeschlagen.
        echo            Versuche manuell:
        echo            !PYTHON_CMD! -m pip install flask requests
        pause
        exit /b 1
    )
)

echo.
echo   [OK]   Alle Pakete installiert.


REM ===========================================================
:start_server
REM ===========================================================

echo.
echo  -----------------------------------------------------------
echo   SCHRITT 4 von 4: Starte Web-Server
echo  -----------------------------------------------------------
echo.
echo   Python:  !PYTHON_CMD!
echo   Ordner:  %~dp0
echo.
echo  ===========================================================
echo.
echo     Browser oeffnet sich gleich automatisch.
echo.
echo     Falls nicht, oeffne manuell:
echo     http://127.0.0.1:5000
echo.
echo     Beenden: Ctrl+C oder Fenster schliessen
echo.
echo  ===========================================================
echo.

cd /d "%~dp0"

echo   [*] Starte Server...
echo.

!PYTHON_CMD! start_web.py

echo.
echo  -----------------------------------------------------------
echo   Server wurde beendet.
echo  -----------------------------------------------------------
echo.
pause
exit /b 0
