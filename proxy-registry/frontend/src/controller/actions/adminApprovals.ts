import {
  approveKeyRequest,
  rejectKeyRequest,
  type KeyRequest,
} from '../../api'
import {
  defaultExpiry,
  managedUsername,
  minimumFutureExpiry,
} from '../model'
import type { ControllerServices } from '../services'
import type { ControllerState } from '../state'

export function createAdminApprovalActions(
  state: ControllerState,
  services: ControllerServices,
) {
  const {
    toast, approvalRequest, approvalMinimumExpiry, approvalExpiresAt,
    adminUsers, approvalProxyAddressIds, approvalVisible, approvalReason,
    approvalSaving, rejectionRequest, rejectionReason, rejectionVisible,
    rejectingRequestId,
  } = state

  function openApproval(request: KeyRequest): void {
    approvalRequest.value = request
    approvalMinimumExpiry.value = minimumFutureExpiry()
    approvalExpiresAt.value = defaultExpiry()
    const managed = adminUsers.value.find(
      (user) => managedUsername(user) === request.username,
    )
    approvalProxyAddressIds.value =
      managed?.proxyAddresses.map((address) => address.id) ?? []
    approvalVisible.value = true
    approvalReason.value = ''
  }

  async function submitApproval(): Promise<void> {
    const request = approvalRequest.value
    const expiresAt = approvalExpiresAt.value
    if (!request || !expiresAt || expiresAt.getTime() <= Date.now()) {
      toast.add({
        severity: 'warn',
        summary: '请选择未来的密钥过期时间',
        detail: '批准申请前必须为新密钥设置明确的未来有效期',
        life: 3600,
      })
      return
    }
    if (!approvalProxyAddressIds.value.length) {
      toast.add({
        severity: 'warn',
        summary: '请选择至少一个 Proxy 地址',
        detail: '批准密钥申请时必须给账号分配可用地址',
        life: 3600,
      })
      return
    }
    if (!approvalReason.value.trim()) {
      toast.add({
        severity: 'warn',
        summary: '请输入批准原因',
        life: 2800,
      })
      return
    }

    approvalSaving.value = true
    try {
      await approveKeyRequest(
        request.id,
        expiresAt.toISOString(),
        approvalProxyAddressIds.value,
        approvalReason.value.trim(),
      )
      approvalVisible.value = false
      approvalRequest.value = null
      await services.refreshAdminUsers()
      toast.add({
        severity: 'success',
        summary: '密钥申请已批准',
        detail: '新密钥已生成，只有用户本人登录后可以查看',
        life: 5000,
      })
    } catch (error) {
      services.showError('批准密钥申请失败', error)
    } finally {
      approvalSaving.value = false
    }
  }

  function confirmRejectKeyRequest(request: KeyRequest): void {
    rejectionRequest.value = request
    rejectionReason.value = ''
    rejectionVisible.value = true
  }

  async function performRejectKeyRequest(): Promise<void> {
    const request = rejectionRequest.value
    if (!request) return
    if (!rejectionReason.value.trim()) {
      toast.add({
        severity: 'warn',
        summary: '请输入拒绝原因',
        life: 2800,
      })
      return
    }
    rejectingRequestId.value = request.id
    try {
      await rejectKeyRequest(request.id, rejectionReason.value)
      rejectionVisible.value = false
      rejectionRequest.value = null
      rejectionReason.value = ''
      await services.refreshAdminUsers()
      toast.add({
        severity: 'success',
        summary: '密钥申请已拒绝',
        life: 3000,
      })
    } catch (error) {
      services.showError('拒绝密钥申请失败', error)
    } finally {
      rejectingRequestId.value = ''
    }
  }

  return {
    openApproval, submitApproval, confirmRejectKeyRequest,
    performRejectKeyRequest,
  }
}
