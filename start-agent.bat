@echo off
setlocal
REM Start Agent (Windows)
REM Assumes agent.exe and agent.toml are in the same directory as this script.

cd /d "%~dp0"

if not exist "agent.exe" (
  echo Error: agent.exe not found in script directory.
  exit /b 1
)

set "CONFIG_PATH=agent.toml"
if not exist "%CONFIG_PATH%" (
  echo Warning: agent.toml not found. Starting without --config (using defaults).
  set "CONFIG_PATH="
)

echo Starting Agent...
if not exist "logs" mkdir "logs"

if defined CONFIG_PATH (
  "%~dp0agent.exe" --config "%CONFIG_PATH%" > "%~dp0logs\agent.out" 2>&1
) else (
  "%~dp0agent.exe" > "%~dp0logs\agent.out" 2>&1
)

endlocal
