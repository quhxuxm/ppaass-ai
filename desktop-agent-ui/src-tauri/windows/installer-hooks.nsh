; PPAASS installs PPAASSAgentService on demand when TUN mode first starts.
; Because the service is created outside the installer, NSIS must explicitly stop
; and delete it before replacing or removing the application executable.

!macro PPAASS_REMOVE_AGENT_SERVICE
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "if (Get-Service -Name PPAASSAgentService -ErrorAction SilentlyContinue) { Stop-Service -Name PPAASSAgentService -Force -ErrorAction SilentlyContinue; (Get-Service -Name PPAASSAgentService -ErrorAction SilentlyContinue).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15)); & sc.exe delete PPAASSAgentService | Out-Null }"'
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

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro PPAASS_REMOVE_AGENT_SERVICE
  !insertmacro PPAASS_REMOVE_AGENT_CONFIG
!macroend
