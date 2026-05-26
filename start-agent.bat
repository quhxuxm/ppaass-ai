@echo off
setlocal
REM Start Agent (Windows)
REM Assumes desktop-agent.exe and agent.toml are in the same directory as this script.

cd /d "%~dp0"

if not exist "desktop-agent.exe" (
  echo Error: desktop-agent.exe not found in script directory.
  exit /b 1
)

set "CONFIG_PATH=agent.toml"
set "TASK_NAME=PPAASS Desktop Agent TUN"

call :EnsureTunLaunchPath
if errorlevel 2 exit /b %ERRORLEVEL%
if "%USE_TUN_TASK%"=="1" goto StartTunTask

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
exit /b 0

:StartTunTask
for /f "tokens=2" %%P in ('tasklist /FI "IMAGENAME eq desktop-agent.exe" ^| findstr /I "desktop-agent.exe"') do (
  echo Stopping existing Agent process PID: %%P
  taskkill /F /PID %%P >nul 2>&1
)

echo Starting Agent via elevated Windows task...
schtasks /End /TN "%TASK_NAME%" >nul 2>&1
schtasks /Run /TN "%TASK_NAME%"
endlocal
exit /b %ERRORLEVEL%

:EnsureTunLaunchPath
set "USE_TUN_TASK=0"
if not exist "%CONFIG_PATH%" exit /b 0

powershell -NoProfile -ExecutionPolicy Bypass -Command "$inTun=$false;$enabled=$false; foreach($line in Get-Content -LiteralPath '%CONFIG_PATH%'){ $trim=$line.Trim(); if($trim -match '^\[.*\]'){ $inTun=($trim -match '^\[tun\]'); continue }; if($inTun){ $clean=($line -replace '\s*#.*$','').Trim(); if($clean -match '^enabled\s*=\s*true\s*$'){ $enabled=$true } } }; if($enabled){ exit 0 } else { exit 1 }"
if errorlevel 1 exit /b 0

set "USE_TUN_TASK=1"
schtasks /Query /TN "%TASK_NAME%" >nul 2>&1
if not errorlevel 1 exit /b 0

echo TUN mode is enabled; installing elevated Windows startup task...
set "PPAASS_TASK_NAME=%TASK_NAME%"
set "PPAASS_AGENT_PATH=%~dp0desktop-agent.exe"
set "PPAASS_CONFIG_PATH=%~dp0%CONFIG_PATH%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$script='$q=[char]34; $taskName=$env:PPAASS_TASK_NAME; $agent=$env:PPAASS_AGENT_PATH; $config=$env:PPAASS_CONFIG_PATH; $tr=$q+$agent+$q+'' --config ''+$q+$config+$q; & schtasks.exe /Create /TN $taskName /SC ONDEMAND /RL HIGHEST /TR $tr /F; exit $LASTEXITCODE'; $p=Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$script); exit $p.ExitCode"
if errorlevel 1 (
  echo Error: failed to install elevated Windows startup task.
  exit /b 2
)
exit /b 0
