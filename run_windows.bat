@echo off
setlocal
cd /d "%~dp0"
echo.
echo  AppShip Readiness Toolkit
echo Local-first Google Play / Apple App Store source preflight
echo.
set "PYTHON_CMD=python"
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
if errorlevel 1 (
  set "PYTHON_CMD=py -3"
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
  if errorlevel 1 (
    echo ERROR: Python 3.10 or newer was not found or could not run.
    echo Install Python from https://www.python.org/downloads/windows/
    echo During setup, enable "Add python.exe to PATH" and include Tcl/Tk.
    echo Close and reopen this window after installation.
    pause
    exit /b 1
  )
)
%PYTHON_CMD% --version
%PYTHON_CMD% app.py
if errorlevel 1 (
  echo.
  echo The app closed with an error. Copy the error text when asking for help.
  echo If the error mentions tkinter, reinstall Python with Tcl/Tk included.
  pause
)
endlocal
