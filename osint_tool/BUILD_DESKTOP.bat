@echo off
setlocal
cd /d "%~dp0.."
py -3 --version >nul 2>&1
if not errorlevel 1 (
    py -3 -m venv .venv-build
) else (
    python -m venv .venv-build
)
if errorlevel 1 goto :failed
".venv-build\Scripts\python.exe" -m pip install -r osint_tool\requirements-build.txt
if errorlevel 1 goto :failed
".venv-build\Scripts\python.exe" osint_tool\build.py
if errorlevel 1 goto :failed
echo.
echo Fertig: dist\OSINTReconTool.exe und das portable ZIP im selben Ordner.
pause
exit /b 0
:failed
echo.
echo Build fehlgeschlagen. Details stehen oben. Python 3.11+ mit Tcl/Tk erforderlich.
pause
exit /b 1
