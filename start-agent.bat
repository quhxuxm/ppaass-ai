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
set "PPAASS_TASK_NAME=%TASK_NAME%"
set "PPAASS_AGENT_PATH=%~dp0desktop-agent.exe"
set "PPAASS_CONFIG_PATH=%~dp0%CONFIG_PATH%"
set "PPAASS_WORK_DIR=%~dp0"
set "PPAASS_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PPAASS_POWERSHELL%" set "PPAASS_POWERSHELL=powershell.exe"

"%PPAASS_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; $taskName=$env:PPAASS_TASK_NAME; $agent=(Resolve-Path -LiteralPath $env:PPAASS_AGENT_PATH).Path; $config=(Resolve-Path -LiteralPath $env:PPAASS_CONFIG_PATH).Path; $workDir=($env:PPAASS_WORK_DIR).TrimEnd('\'); $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; if($null -eq $task){ exit 1 }; $action=@($task.Actions)[0]; if($null -eq $action){ exit 1 }; $execute=[Environment]::ExpandEnvironmentVariables([string]$action.Execute); try { $execute=(Resolve-Path -LiteralPath $execute -ErrorAction Stop).Path } catch {}; $arguments=[string]$action.Arguments; $taskWorkDir=([string]$action.WorkingDirectory).TrimEnd('\'); if(($execute -ieq $agent) -and ($arguments -like ('*'+$config+'*')) -and ($taskWorkDir -ieq $workDir)){ exit 0 }; exit 1"
if not errorlevel 1 exit /b 0

echo TUN mode is enabled; installing or updating elevated Windows startup task...
"%PPAASS_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -Command "$script='$ErrorActionPreference=''Stop''; $taskName=$env:PPAASS_TASK_NAME; $agent=(Resolve-Path -LiteralPath $env:PPAASS_AGENT_PATH).Path; $config=(Resolve-Path -LiteralPath $env:PPAASS_CONFIG_PATH).Path; $workDir=$env:PPAASS_WORK_DIR; $user=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $action=New-ScheduledTaskAction -Execute $agent -Argument (''--config "''+$config+''"'') -WorkingDirectory $workDir; $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest; $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DisallowStartIfOnBatteries:$false; Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null'; $p=Start-Process -FilePath $env:PPAASS_POWERSHELL -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$script); exit $p.ExitCode"
if errorlevel 1 (
  echo Error: failed to install or update elevated Windows startup task.
  exit /b 2
)
exit /b 0
