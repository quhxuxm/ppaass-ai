; PPAASS installs PPAASSAgentService on demand when TUN mode first starts.
; Because the service is created outside the installer, NSIS must explicitly stop
; and delete it before replacing or removing the application executable.

!macro PPAASS_REMOVE_AGENT_SERVICE
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "if (Get-Service -Name PPAASSAgentService -ErrorAction SilentlyContinue) { Stop-Service -Name PPAASSAgentService -Force -ErrorAction SilentlyContinue; (Get-Service -Name PPAASSAgentService -ErrorAction SilentlyContinue).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15)); & sc.exe delete PPAASSAgentService | Out-Null }"'
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro PPAASS_REMOVE_AGENT_SERVICE
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro PPAASS_REMOVE_AGENT_SERVICE
!macroend
