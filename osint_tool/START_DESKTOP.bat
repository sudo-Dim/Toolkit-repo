@echo off
setlocal
cd /d "%~dp0"
if exist "OSINTReconTool.exe" (
    start "" "%~dp0OSINTReconTool.exe"
    exit /b 0
)
if exist "..\dist\OSINTReconTool.exe" (
    start "" "%~dp0..\dist\OSINTReconTool.exe"
    exit /b 0
)
if exist "..\.venv\Scripts\pythonw.exe" (
    start "" "%~dp0..\.venv\Scripts\pythonw.exe" "%~dp0start_desktop.py"
    exit /b 0
)
py -3 --version >nul 2>&1
if not errorlevel 1 (
    py -3 start_desktop.py
) else (
    python start_desktop.py
)
if errorlevel 1 (
    echo.
    echo Desktop-Start fehlgeschlagen. Fuer die Quellcode-Version einmalig:
    echo python -m pip install -r requirements-desktop.txt
    echo Python muss mit Tcl/Tk installiert sein. Die portable EXE benoetigt kein Python.
    pause
    exit /b 1
)
