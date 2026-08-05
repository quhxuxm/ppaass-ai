; PPAASSAgentService runs the installed application executable. During an
; upgrade NSIS must stop and remove the old registration before replacing that
; executable, then register the newly installed executable again.

!macro PPAASS_REMOVE_AGENT_SERVICE
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "if (Get-Service -Name PPAASSAgentService -ErrorAction SilentlyContinue) { Stop-Service -Name PPAASSAgentService -Force -ErrorAction SilentlyContinue; (Get-Service -Name PPAASSAgentService -ErrorAction SilentlyContinue).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15)); & sc.exe delete PPAASSAgentService | Out-Null }"'
!macroend

!macro PPAASS_INSTALL_AGENT_SERVICE
  ; A first-time install has no managed user directory until login, so the app
  ; still performs its normal on-demand installation in that case. An upgrade
  ; already has this directory and must leave a current, running service behind.
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$configRoot = Join-Path $$env:LOCALAPPDATA $\'com.ppaass.agent$\'; $$agent = Join-Path $\'$INSTDIR$\' $\'desktop-agent-ui.exe$\'; if ((Test-Path -LiteralPath $$configRoot -PathType Container) -and (Test-Path -LiteralPath $$agent -PathType Leaf)) { & $$agent --ppaass-install-service --ppaass-service-config-root $$configRoot; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE } }"'
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
  !insertmacro PPAASS_REMOVE_AGENT_CONFIG
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro PPAASS_INSTALL_AGENT_SERVICE
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro PPAASS_REMOVE_AGENT_SERVICE
  !insertmacro PPAASS_REMOVE_AGENT_CONFIG
!macroend
