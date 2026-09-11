; PPAASSAgentService runs the installed application executable. During an
; upgrade NSIS must stop and remove the old registration before replacing that
; executable, then register the newly installed executable again.

!macro PPAASS_REMOVE_AGENT_SERVICE
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "if (Get-Service -Name PPAASSAgentService -ErrorAction SilentlyContinue) { Stop-Service -Name PPAASSAgentService -Force -ErrorAction SilentlyContinue; (Get-Service -Name PPAASSAgentService -ErrorAction SilentlyContinue).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15)); & sc.exe delete PPAASSAgentService | Out-Null }"'
!macroend

!macro PPAASS_INSTALL_AGENT_SERVICE
  ; Prefer the live roaming configuration. Earlier releases used LocalAppData
  ; for credentials, so retain it only as a compatibility fallback.
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$roots = @((Join-Path $$env:APPDATA $\'com.ppaass.agent$\'), (Join-Path $$env:LOCALAPPDATA $\'com.ppaass.agent$\')); $$configRoot = $$roots | Where-Object { Test-Path -LiteralPath (Join-Path $$_ $\'agent.toml$\') -PathType Leaf } | Select-Object -First 1; $$agent = Join-Path $\'$INSTDIR$\' $\'desktop-agent-ui.exe$\'; if ($$null -ne $$configRoot -and (Test-Path -LiteralPath $$agent -PathType Leaf)) { & $$agent --ppaass-install-service --ppaass-service-config-root $$configRoot; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE } }"'
!macroend

; Remove only application-owned configuration files. Keep credentials, captures,
; and any other user data so uninstall does not destroy unrelated persisted data.
!macro PPAASS_REMOVE_AGENT_CONFIG_ROOT APP_DATA_ROOT
  SetFileAttributes "${APP_DATA_ROOT}\com.ppaass.agent\agent.toml" NORMAL
  Delete "${APP_DATA_ROOT}\com.ppaass.agent\agent.toml"
  RMDir "${APP_DATA_ROOT}\com.ppaass.agent"
!macroend

!macro PPAASS_REMOVE_AGENT_CONFIG
  !insertmacro PPAASS_REMOVE_AGENT_CONFIG_ROOT $APPDATA
  !insertmacro PPAASS_REMOVE_AGENT_CONFIG_ROOT $LOCALAPPDATA
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro PPAASS_REMOVE_AGENT_SERVICE
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro PPAASS_INSTALL_AGENT_SERVICE
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro PPAASS_REMOVE_AGENT_SERVICE
  !insertmacro PPAASS_REMOVE_AGENT_CONFIG
!macroend
