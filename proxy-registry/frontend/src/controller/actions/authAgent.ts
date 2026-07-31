import {
  approveAgentDeviceAuthorization,
  clearClientSession,
  denyAgentDeviceAuthorization,
  inspectAgentDeviceAuthorization,
  login,
  logout,
  register,
} from '../../api'
import {
  PASSWORD_MIN_CHARACTERS,
  clearAgentAuthorizationLocation,
  clearStoredAgentAuthorization,
  storeAgentAuthorization,
} from '../model'
import type { ControllerServices } from '../services'
import type { ControllerState } from '../state'

export function createAuthAgentActions(
  state: ControllerState,
  services: ControllerServices,
) {
  const {
    toast, authForm, authMode, authLoading, session,
    agentAuthorizationActive, agentAuthorizationCode,
    agentAuthorizationInput, agentAuthorization, agentAuthorizationLoading,
    agentAuthorizationDecisionLoading, agentAuthorizationOutcome,
    agentAuthorizationError, self, adminUsers, adminKeyRequests,
    accessRecords, accessHostFilter, accessRecordsFirst,
    keyRequestDialogVisible, activePage,
  } = state

  async function submitAuth(): Promise<void> {
    const username = authForm.username.trim()
    if (!username) {
      toast.add({ severity: 'warn', summary: '请输入用户名', life: 2600 })
      return
    }
    if (!authForm.password) {
      toast.add({ severity: 'warn', summary: '请输入密码', life: 2600 })
      return
    }
    if (
      authMode.value === 'register' &&
      Array.from(authForm.password).length < PASSWORD_MIN_CHARACTERS
    ) {
      toast.add({
        severity: 'warn',
        summary: `密码至少需要 ${PASSWORD_MIN_CHARACTERS} 个字符`,
        life: 3200,
      })
      return
    }

    authLoading.value = true
    try {
      const payload = { username, password: authForm.password }
      session.value =
        authMode.value === 'register'
          ? await register(payload)
          : await login(payload)
      authForm.password = ''
      await services.refreshSelf()
      if (agentAuthorizationActive.value && agentAuthorizationCode.value) {
        await refreshAgentAuthorization()
      }
      toast.add({
        severity: 'success',
        summary:
          authMode.value === 'register' ? '账号注册成功' : '欢迎回来',
        life: 2600,
      })
    } catch (error) {
      services.showError(
        authMode.value === 'register' ? '注册失败' : '登录失败',
        error,
      )
    } finally {
      authForm.password = ''
      authLoading.value = false
    }
  }

  async function performLogout(): Promise<void> {
    services.resetPasswordForm()
    try {
      await logout()
    } catch {
      clearClientSession()
    }
    session.value = null
    self.value = null
    adminUsers.value = []
    adminKeyRequests.value = []
    accessRecords.value = []
    accessHostFilter.value = ''
    accessRecordsFirst.value = 0
    keyRequestDialogVisible.value = false
    activePage.value = 'account'
    authForm.password = ''
    agentAuthorization.value = null
    agentAuthorizationOutcome.value = null
    agentAuthorizationError.value = ''
    toast.add({ severity: 'info', summary: '已安全退出', life: 2200 })
  }

  async function refreshAgentAuthorization(): Promise<void> {
    const code = agentAuthorizationInput.value.trim()
    if (!code) {
      agentAuthorizationError.value = '请输入 Agent 显示的设备授权短码'
      return
    }
    agentAuthorizationLoading.value = true
    agentAuthorizationError.value = ''
    agentAuthorizationOutcome.value = null
    try {
      const next = await inspectAgentDeviceAuthorization(code)
      agentAuthorizationCode.value = code
      agentAuthorizationInput.value = code
      agentAuthorization.value = next
      agentAuthorizationOutcome.value =
        next.status === 'authorized' || next.status === 'denied'
          ? next.status
          : null
      storeAgentAuthorization(code)
    } catch (error) {
      agentAuthorization.value = null
      agentAuthorizationError.value = services.errorMessage(error)
    } finally {
      agentAuthorizationLoading.value = false
    }
  }

  async function decideAgentAuthorization(
    decision: 'approve' | 'deny',
  ): Promise<void> {
    if (!agentAuthorization.value || !agentAuthorizationCode.value) return
    agentAuthorizationDecisionLoading.value = decision
    agentAuthorizationError.value = ''
    try {
      if (decision === 'approve') {
        await approveAgentDeviceAuthorization(agentAuthorizationCode.value)
        agentAuthorizationOutcome.value = 'authorized'
        agentAuthorization.value.status = 'authorized'
      } else {
        await denyAgentDeviceAuthorization(agentAuthorizationCode.value)
        agentAuthorizationOutcome.value = 'denied'
        agentAuthorization.value.status = 'denied'
      }
      clearStoredAgentAuthorization()
      clearAgentAuthorizationLocation()
    } catch (error) {
      agentAuthorizationError.value = services.errorMessage(error)
    } finally {
      agentAuthorizationDecisionLoading.value = null
    }
  }

  function leaveAgentAuthorization(): void {
    clearStoredAgentAuthorization()
    agentAuthorizationActive.value = false
    agentAuthorizationCode.value = ''
    agentAuthorizationInput.value = ''
    agentAuthorization.value = null
    agentAuthorizationOutcome.value = null
    agentAuthorizationError.value = ''
    clearAgentAuthorizationLocation()
  }

  return {
    submitAuth, performLogout, refreshAgentAuthorization,
    decideAgentAuthorization, leaveAgentAuthorization,
  }
}
