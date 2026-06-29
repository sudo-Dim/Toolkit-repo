@echo off
REM ===========================================================
REM  OSINT Recon Tool - LIGHT (Terminal-Only) Launcher
REM  Startet die schlanke Terminal-Variante (ohne Web-UI).
REM  Fenster bleibt offen.
REM ===========================================================

if "%~1"=="" (
    cmd /k "%~f0" run
    exit /b
)

setlocal EnableDelayedExpansion
title OSINT Recon Tool - Light

REM In den Repo-Ordner wechseln (Elternordner von osint_tool\)
cd /d "%~dp0\.."

REM Python finden
set PYTHON_CMD=
python --version >nul 2>&1 && set PYTHON_CMD=python
if "!PYTHON_CMD!"=="" ( python3 --version >nul 2>&1 && set PYTHON_CMD=python3 )
if "!PYTHON_CMD!"=="" ( py --version >nul 2>&1 && set PYTHON_CMD=py )

if "!PYTHON_CMD!"=="" (
    echo.
    echo   [!] Python wurde nicht gefunden. Bitte Python 3 installieren:
    echo       https://www.python.org/downloads/  ^(Haken bei "Add to PATH"^)
    echo.
    pause
    exit /b
)

echo.
echo   [*] Installiere/aktualisiere Abhaengigkeiten (einmalig, ruhig)...
!PYTHON_CMD! -m pip install -q -r osint_tool\requirements.txt 2>nul

echo   [*] Starte OSINT Recon Light...
echo.
!PYTHON_CMD! -m osint_tool.light

echo.
echo   [*] Beendet. Fenster bleibt offen.
