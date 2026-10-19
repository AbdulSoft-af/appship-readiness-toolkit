@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_CMD=python"
%PYTHON_CMD% -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
if errorlevel 1 (
  set "PYTHON_CMD=py -3"
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
  if errorlevel 1 (
    echo ERROR: Python 3.10 or newer not found.
    echo Install from https://www.python.org/downloads/windows/
    pause
    exit /b 1
  )
)
%PYTHON_CMD% -m appship.cli %*
endlocal
