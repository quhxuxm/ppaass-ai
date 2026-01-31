@echo off
setlocal
REM Start Proxy (Windows)
REM Assumes proxy.exe and proxy.toml are in the same directory as this script.


cd /d "%~dp0"

if not exist "proxy.exe" (
  echo Error: proxy.exe not found in script directory.
  exit /b 1
)

set "CONFIG_PATH=proxy.toml"

echo Starting Proxy...
if not exist "logs" mkdir "logs"

if defined CONFIG_PATH (
  "%~dp0proxy.exe" --config "%CONFIG_PATH%" > "%~dp0logs\proxy.out" 2>&1
) else (
  "%~dp0proxy.exe" > "%~dp0logs\proxy.out" 2>&1
)

endlocal
