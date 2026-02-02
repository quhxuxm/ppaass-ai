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

for /f "tokens=2" %%P in ('tasklist /FI "IMAGENAME eq agent.exe" ^| findstr /I "agent.exe"') do (
  echo Stopping existing Agent process PID: %%P
  taskkill /F /PID %%P >nul 2>&1
)

echo Starting Agent...
if not exist "logs" mkdir "logs"

if defined CONFIG_PATH (
  start "" /B "%~dp0agent.exe" --config "%CONFIG_PATH%" > "%~dp0logs\agent.out" 2>&1
) else (
  start "" /B "%~dp0agent.exe" > "%~dp0logs\agent.out" 2>&1
)

endlocal
