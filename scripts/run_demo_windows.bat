@echo off
setlocal
cd /d "%~dp0\.."
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher 'py' not found. Install Python 3.10+ first.
  exit /b 1
)
py -m venv .venv
if errorlevel 1 exit /b 1
call .venv\Scripts\activate.bat
python -m pip install -e .
if errorlevel 1 exit /b 1
vuln-skill demo --cve CVE-2026-85984
if errorlevel 1 exit /b 1
echo.
echo Offline Arsenal demo completed. Open demo-output for generated reports.
endlocal
