@echo off
setlocal
REM Start Agent (Windows)
REM Assumes desktop-agent.exe and agent.toml are in the same directory as this script.

cd /d "%~dp0"

fltmc >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator privileges...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
  exit /b
)

if not exist "desktop-agent.exe" (
  echo Error: desktop-agent.exe not found in script directory.
  exit /b 1
)

set "CONFIG_PATH=agent.toml"

for /f "tokens=2" %%P in ('tasklist /FI "IMAGENAME eq desktop-agent.exe" ^| findstr /I "desktop-agent.exe"') do (
  echo Stopping existing Agent process PID: %%P
  taskkill /F /PID %%P >nul 2>&1
)

echo Starting Agent...
if not exist "logs" mkdir "logs"

if defined CONFIG_PATH (
  start "" /B "%~dp0desktop-agent.exe" --config "%CONFIG_PATH%"
) else (
  start "" /B "%~dp0desktop-agent.exe"
)

endlocal
