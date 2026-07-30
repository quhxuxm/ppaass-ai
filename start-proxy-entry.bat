@echo off
setlocal
REM Start Proxy Entry (Windows)
REM Assumes proxy-entry.exe and proxy-entry.toml are in the same directory as this script.


cd /d "%~dp0"

if not exist "proxy-entry.exe" (
  echo Error: proxy-entry.exe not found in script directory.
  exit /b 1
)

set "CONFIG_PATH=proxy-entry.toml"

if not exist "logs" mkdir "logs"

echo Starting Proxy Entry...

if defined CONFIG_PATH (
  "%~dp0proxy-entry.exe" --config "%CONFIG_PATH%" > "%~dp0logs\proxy-entry.out" 2>&1
) else (
  "%~dp0proxy-entry.exe" > "%~dp0logs\proxy-entry.out" 2>&1
)

endlocal
