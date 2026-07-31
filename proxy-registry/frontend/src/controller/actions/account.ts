import {
  ApiError,
  changeMyPassword,
  clearClientSession,
  getMe,
  getMyKeyRequest,
  listMyAccessRecords,
  rotateMyKey,
  submitMyKeyRequest,
  updateMyProfile,
  type UpdateMyProfilePayload,
} from '../../api'
import { PASSWORD_MIN_CHARACTERS } from '../model'
import type { ControllerServices } from '../services'
import type { ControllerState } from '../state'

export function createAccountActions(
  state: ControllerState,
  services: ControllerServices,
) {
  const {
    toast, confirm, passwordForm, passwordSaving, account, session, self,
    adminUsers, adminKeyRequests, accessRecords, accessHostFilter,
    accessRecordsFirst, keyRequestDialogVisible, activePage, authMode, authForm,
    profileSaving, pageLoading, accessRecordsLoading, accessRetentionDays,
    keyRequestLoading, profile, keyRotationLoading, ownRotationVisible,
    ownRotationReason, isAdmin,
  } = state

  async function submitPasswordChange(): Promise<void> {
    const currentPassword = passwordForm.currentPassword
    const newPassword = passwordForm.newPassword
    const loginUsername = account.value?.username ?? ''
    if (!currentPassword || !newPassword || !passwordForm.confirmPassword) {
      toast.add({
        severity: 'warn',
        summary: '请完整填写三个密码字段',
        life: 2800,
      })
      return
    }
    if (Array.from(newPassword).length < PASSWORD_MIN_CHARACTERS) {
      toast.add({
        severity: 'warn',
        summary: `新密码至少需要 ${PASSWORD_MIN_CHARACTERS} 个字符`,
        life: 3200,
      })
      return
    }
    if (newPassword !== passwordForm.confirmPassword) {
      toast.add({
        severity: 'warn',
        summary: '两次输入的新密码不一致',
        life: 3000,
      })
      return
    }
    if (newPassword === currentPassword) {
      toast.add({
        severity: 'warn',
        summary: '新密码不能与当前密码相同',
        life: 3000,
      })
      return
    }

    passwordSaving.value = true
    try {
      await changeMyPassword({
        current_password: currentPassword,
        new_password: newPassword,
      })
      services.resetPasswordForm()
      clearClientSession()
      session.value = null
      self.value = null
      adminUsers.value = []
      adminKeyRequests.value = []
      accessRecords.value = []
      accessHostFilter.value = ''
      accessRecordsFirst.value = 0
      keyRequestDialogVisible.value = false
      activePage.value = 'account'
      authMode.value = 'login'
      authForm.username = loginUsername
      authForm.password = ''
      toast.add({
        severity: 'success',
        summary: '密码已更新，请使用新密码重新登录',
        life: 5000,
      })
    } catch (error) {
      services.showError('修改密码失败', error)
    } finally {
      passwordSaving.value = false
    }
  }

  async function saveMyProfile(
    payload: UpdateMyProfilePayload,
  ): Promise<void> {
    profileSaving.value = true
    try {
      await updateMyProfile(payload)
      await refreshSelf()
      toast.add({
        severity: 'success',
        summary: '个人资料已更新',
        life: 3000,
      })
    } catch (error) {
      services.showError('保存个人资料失败', error)
    } finally {
      profileSaving.value = false
    }
  }

  async function refreshSelf(): Promise<void> {
    pageLoading.value = true
    try {
      const nextSelf = await getMe()
      try {
        nextSelf.pendingKeyRequest = await getMyKeyRequest(
          nextSelf.profile?.username ?? nextSelf.account.username,
        )
      } catch {
        // /me 自带待审批申请，独立刷新暂时失败时保留原值。
      }
      self.value = nextSelf
      if (nextSelf.account) {
        session.value = {
          registryInstanceId:
            session.value?.registryInstanceId ?? 'unknown',
          authenticated: true,
          account: nextSelf.account,
          agentHandoff: session.value?.agentHandoff ?? false,
        }
      }
      if (nextSelf.account.role === 'admin') {
        await Promise.all([
          refreshAccessRecords(false),
          services.refreshAdminUsers(),
        ])
      } else {
        await refreshAccessRecords(false)
      }
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        session.value = null
        self.value = null
        keyRequestDialogVisible.value = false
        clearClientSession()
      } else {
        services.showError('无法读取账户信息', error)
      }
    } finally {
      pageLoading.value = false
    }
  }

  async function refreshAccessRecords(showFailure = true): Promise<void> {
    accessRecordsLoading.value = true
    try {
      const result = await listMyAccessRecords()
      accessRecords.value = result.records
      accessRetentionDays.value = result.retentionDays
    } catch (error) {
      if (showFailure) services.showError('无法读取最近访问记录', error)
    } finally {
      accessRecordsLoading.value = false
    }
  }

  function openKeyRequestDialog(): void {
    keyRequestDialogVisible.value = true
  }

  async function submitKeyRequest(message: string | null): Promise<void> {
    keyRequestLoading.value = true
    try {
      const request = await submitMyKeyRequest(
        profile.value?.username ?? account.value?.username,
        message,
      )
      if (self.value) self.value.pendingKeyRequest = request
      keyRequestDialogVisible.value = false
      toast.add({
        severity: 'success',
        summary: '密钥申请已提交',
        detail: '管理员批准并设置有效期后，已授权 Agent 可以领取新凭据',
        life: 5000,
      })
    } catch (error) {
      services.showError('密钥申请提交失败', error)
    } finally {
      keyRequestLoading.value = false
    }
  }

  async function refreshKeyRequest(): Promise<void> {
    keyRequestLoading.value = true
    try {
      await refreshSelf()
    } finally {
      keyRequestLoading.value = false
    }
  }

  function confirmRotateOwnKey(): void {
    if (isAdmin.value) {
      ownRotationReason.value = ''
      ownRotationVisible.value = true
      return
    }
    confirm.require({
      header: '重新生成密钥对',
      message:
        '旧连接凭据会立即失效。已经建立的连接不会被强制断开，但之后的新连接必须使用新凭据。',
      icon: 'pi pi-refresh',
      acceptLabel: '生成新密钥',
      rejectLabel: '取消',
      acceptClass: 'p-button-danger',
      accept: () => {
        void rotateOwnKey()
      },
    })
  }

  async function rotateOwnKey(reason?: string): Promise<void> {
    const normalizedReason = reason?.trim()
    if (isAdmin.value && !normalizedReason) {
      toast.add({
        severity: 'warn',
        summary: '请输入重生成密钥的原因',
        life: 2800,
      })
      return
    }
    keyRotationLoading.value = true
    try {
      await rotateMyKey(normalizedReason)
      ownRotationVisible.value = false
      ownRotationReason.value = ''
      await refreshSelf()
      toast.add({
        severity: 'success',
        summary: '新密钥对已生成',
        detail: '已授权 Agent 将在下次认证时领取新的连接凭据',
        life: 5000,
      })
    } catch (error) {
      services.showError('密钥更新失败', error)
    } finally {
      keyRotationLoading.value = false
    }
  }

  function hasEffectivePermission(code: string): boolean {
    return (
      isAdmin.value ||
      Boolean(profile.value?.permissions.includes(code))
    )
  }

  return {
    submitPasswordChange, saveMyProfile, refreshSelf, refreshAccessRecords,
    openKeyRequestDialog, submitKeyRequest, refreshKeyRequest,
    confirmRotateOwnKey, rotateOwnKey, hasEffectivePermission,
  }
}
