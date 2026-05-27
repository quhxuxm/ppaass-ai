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
set "PPAASS_BAT_PATH=%~f0"
set "PPAASS_INSTALL_LOG=%~dp0logs\tun-task-install.log"
if not exist "%PPAASS_POWERSHELL%" set "PPAASS_POWERSHELL=powershell.exe"

"%PPAASS_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; $taskName=$env:PPAASS_TASK_NAME; $agent=(Resolve-Path -LiteralPath $env:PPAASS_AGENT_PATH).Path; $config=(Resolve-Path -LiteralPath $env:PPAASS_CONFIG_PATH).Path; $workDir=($env:PPAASS_WORK_DIR).TrimEnd('\'); $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; if($null -eq $task){ exit 1 }; $action=@($task.Actions)[0]; if($null -eq $action){ exit 1 }; $principal=$task.Principal; if($null -eq $principal){ exit 1 }; $execute=[Environment]::ExpandEnvironmentVariables([string]$action.Execute); try { $execute=(Resolve-Path -LiteralPath $execute -ErrorAction Stop).Path } catch {}; $arguments=[string]$action.Arguments; $taskWorkDir=([string]$action.WorkingDirectory).TrimEnd('\'); if(($execute -ieq $agent) -and ($arguments -like ('*'+$config+'*')) -and ($taskWorkDir -ieq $workDir) -and ([string]$principal.RunLevel -eq 'Highest')){ exit 0 }; exit 1"
if not errorlevel 1 exit /b 0

if not exist "logs" mkdir "logs"

echo TUN mode is enabled; installing or updating elevated Windows startup task...
"%PPAASS_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $lines=Get-Content -LiteralPath $env:PPAASS_BAT_PATH; $inside=$false; $scriptLines=foreach($line in $lines){ if($line -eq ':::BEGIN_INSTALL_TUN_TASK_PS1'){ $inside=$true; continue }; if($line -eq ':::END_INSTALL_TUN_TASK_PS1'){ break }; if($inside){ if($line.StartsWith(':::')){ $line.Substring(3) } else { $line } } }; if(-not $scriptLines){ throw 'Embedded Windows TUN task installer not found.' }; $script=[string]::Join([Environment]::NewLine,$scriptLines); $block=[scriptblock]::Create($script); & $block -TaskName $env:PPAASS_TASK_NAME -AgentPath $env:PPAASS_AGENT_PATH -ConfigPath $env:PPAASS_CONFIG_PATH -WorkDir $env:PPAASS_WORK_DIR -LogPath $env:PPAASS_INSTALL_LOG -BatchPath $env:PPAASS_BAT_PATH"
if errorlevel 1 (
  echo Error: failed to install or update elevated Windows startup task.
  echo See log: "%PPAASS_INSTALL_LOG%"
  exit /b 2
)
exit /b 0

:::BEGIN_INSTALL_TUN_TASK_PS1
:::param(
:::    [string]$TaskName,
:::    [string]$AgentPath,
:::    [string]$ConfigPath,
:::    [string]$WorkDir,
:::    [string]$LogPath,
:::    [string]$BatchPath
:::)
:::
:::$ErrorActionPreference = 'Stop'
:::$script:LogPathValue = $LogPath
:::
:::function Write-InstallLog {
:::    param([string]$Message)
:::
:::    if ([string]::IsNullOrWhiteSpace($script:LogPathValue)) {
:::        return
:::    }
:::
:::    try {
:::        $logDir = Split-Path -Parent $script:LogPathValue
:::        if (-not [string]::IsNullOrWhiteSpace($logDir) -and -not (Test-Path -LiteralPath $logDir)) {
:::            New-Item -ItemType Directory -Force -Path $logDir | Out-Null
:::        }
:::
:::        Add-Content -LiteralPath $script:LogPathValue `
:::            -Encoding UTF8 `
:::            -Value ('{0} {1}' -f (Get-Date -Format o), $Message)
:::    } catch {
:::        # Logging must not hide the real installer failure.
:::    }
:::}
:::
:::function Test-IsElevated {
:::    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
:::    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
:::    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
:::}
:::
:::function Resolve-RequiredPath {
:::    param(
:::        [string]$Path,
:::        [string]$Name
:::    )
:::
:::    if ([string]::IsNullOrWhiteSpace($Path)) {
:::        throw "$Name is empty."
:::    }
:::
:::    return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
:::}
:::
:::function Invoke-ElevatedSelf {
:::    param(
:::        [hashtable]$Payload,
:::        [string]$Path
:::    )
:::
:::    if ([string]::IsNullOrWhiteSpace($Path)) {
:::        throw 'BatchPath is empty.'
:::    }
:::
:::    $resolvedBatchPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
:::    $payloadJson = $Payload | ConvertTo-Json -Depth 4 -Compress
:::    $batch64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($resolvedBatchPath))
:::    $payload64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payloadJson))
:::    $extractor = @'
:::$ErrorActionPreference = 'Stop'
:::$batchPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__BATCH64__'))
:::$payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD64__'))
:::$payload = $payloadJson | ConvertFrom-Json
:::$lines = Get-Content -LiteralPath $batchPath
:::$inside = $false
:::$scriptLines = foreach ($line in $lines) {
:::    if ($line -eq ':::BEGIN_INSTALL_TUN_TASK_PS1') {
:::        $inside = $true
:::        continue
:::    }
:::
:::    if ($line -eq ':::END_INSTALL_TUN_TASK_PS1') {
:::        break
:::    }
:::
:::    if ($inside) {
:::        if ($line.StartsWith(':::')) {
:::            $line.Substring(3)
:::        } else {
:::            $line
:::        }
:::    }
:::}
:::if (-not $scriptLines) {
:::    throw 'Embedded Windows TUN task installer not found.'
:::}
:::$script = [string]::Join([Environment]::NewLine, $scriptLines)
:::$block = [scriptblock]::Create($script)
:::& $block -TaskName $payload.TaskName -AgentPath $payload.AgentPath -ConfigPath $payload.ConfigPath -WorkDir $payload.WorkDir -LogPath $payload.LogPath -BatchPath $batchPath
:::'@
:::
:::    $elevatedScript = $extractor.Replace('__BATCH64__', $batch64).Replace('__PAYLOAD64__', $payload64)
:::    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($elevatedScript))
:::    $powershellPath = (Get-Process -Id $PID).Path
:::    $arguments = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
:::
:::    Write-InstallLog 'Requesting UAC elevation for scheduled task installation.'
:::    $process = Start-Process -FilePath $powershellPath `
:::        -Verb RunAs `
:::        -Wait `
:::        -PassThru `
:::        -ArgumentList $arguments
:::
:::    if ($process.ExitCode -ne 0) {
:::        throw "Elevated installer exited with code $($process.ExitCode)."
:::    }
:::}
:::
:::try {
:::    Write-InstallLog 'Starting Windows TUN scheduled task installation.'
:::
:::    if ([string]::IsNullOrWhiteSpace($TaskName)) {
:::        throw 'TaskName is empty.'
:::    }
:::
:::    $agent = Resolve-RequiredPath -Path $AgentPath -Name 'AgentPath'
:::    $config = Resolve-RequiredPath -Path $ConfigPath -Name 'ConfigPath'
:::    $resolvedWorkDir = Resolve-RequiredPath -Path $WorkDir -Name 'WorkDir'
:::    $resolvedWorkDir = $resolvedWorkDir.TrimEnd('\')
:::
:::    if (-not (Test-IsElevated)) {
:::        Invoke-ElevatedSelf -Payload @{
:::            TaskName = $TaskName
:::            AgentPath = $agent
:::            ConfigPath = $config
:::            WorkDir = $resolvedWorkDir
:::            LogPath = $LogPath
:::        } -Path $BatchPath
:::
:::        Write-InstallLog 'Elevated scheduled task installation completed.'
:::        exit 0
:::    }
:::
:::    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
:::    Write-InstallLog ("Registering task '{0}' for user '{1}'." -f $TaskName, $user)
:::
:::    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
:::    if ($null -ne $existingTask -and $existingTask.State -eq 'Running') {
:::        Write-InstallLog 'Existing task is running; stopping it before update.'
:::        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
:::        Start-Sleep -Milliseconds 500
:::    }
:::
:::    $action = New-ScheduledTaskAction `
:::        -Execute $agent `
:::        -Argument ('--config "' + $config + '"') `
:::        -WorkingDirectory $resolvedWorkDir
:::    $principal = New-ScheduledTaskPrincipal `
:::        -UserId $user `
:::        -LogonType Interactive `
:::        -RunLevel Highest
:::    $settingsParameters = @{
:::        AllowStartIfOnBatteries = $true
:::    }
:::    $settingsCommand = Get-Command New-ScheduledTaskSettingsSet
:::    if ($settingsCommand.Parameters.ContainsKey('DontStopIfGoingOnBatteries')) {
:::        $settingsParameters.DontStopIfGoingOnBatteries = $true
:::    }
:::    $settings = New-ScheduledTaskSettingsSet @settingsParameters
:::
:::    Register-ScheduledTask `
:::        -TaskName $TaskName `
:::        -Action $action `
:::        -Principal $principal `
:::        -Settings $settings `
:::        -Force | Out-Null
:::
:::    $registeredTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
:::    if ($null -eq $registeredTask) {
:::        throw "Task '$TaskName' was not found after registration."
:::    }
:::
:::    Write-InstallLog 'Scheduled task registered successfully.'
:::    exit 0
:::} catch {
:::    $message = ($_ | Out-String).Trim()
:::    Write-InstallLog ("ERROR: {0}" -f $message)
:::    [Console]::Error.WriteLine($message)
:::    exit 1
:::}
:::END_INSTALL_TUN_TASK_PS1
