import {
  createManagedUser,
  deleteManagedUser,
  rotateManagedUserKey,
  updateManagedUser,
  type ManagedUser,
} from '../../api'
import {
  PASSWORD_MIN_CHARACTERS,
  agentPermissionCodes,
  agentPermissionOptions,
  allAgentPermissionCodes,
  basePermissionCodes,
  defaultExpiry,
  deleteBlockedReason,
  isRootAdmin,
  managedUsername,
  minimumFutureExpiry,
  parseDate,
  retiredPermissionCodes,
} from '../model'
import type { ControllerServices } from '../services'
import type { ControllerState } from '../state'

export function createAdminUserActions(
  state: ControllerState,
  services: ControllerServices,
) {
  const {
    toast, confirm, createForm, createMinimumExpiry, createVisible,
    createSaving, editingUser, editForm, editingCustomPermissions,
    editVisible, editingHasEditableFields, editingRequiresAuditReason,
    editingPermissionsChanged, editingProfileReadOnly, editSaving,
    rotationUser, rotationReason, rotationVisible, rotatingUsername,
    deletingUsername,
  } = state

  function parseAdditionalPermissions(
    value: string,
    selectedAgentPermissionCount = 0,
  ): string[] | null {
    const permissions = [
      ...new Set(
        value
          .split(/[\s,，]+/)
          .map((permission) => permission.trim())
          .filter(Boolean),
      ),
    ].filter(
      (permission) =>
        !basePermissionCodes.has(permission) &&
        !agentPermissionCodes.has(permission) &&
        !retiredPermissionCodes.has(permission),
    )
    const invalid = permissions.find(
      (permission) =>
        new TextEncoder().encode(permission).byteLength > 64 ||
        !/^[a-z0-9._-]+$/.test(permission),
    )
    if (invalid) {
      toast.add({
        severity: 'warn',
        summary: '附加权限 code 无效',
        detail:
          `“${invalid}”只能包含 ASCII 小写字母、数字、点、下划线或连字符，且不超过 64 字节`,
        life: 5200,
      })
      return null
    }
    const maximumCustomPermissions = 28 - selectedAgentPermissionCount
    if (permissions.length > maximumCustomPermissions) {
      toast.add({
        severity: 'warn',
        summary: '附加权限过多',
        detail:
          `当前已选择 ${selectedAgentPermissionCount} 项 Agent 权限，最多还能分配 ${maximumCustomPermissions} 项自定义权限`,
        life: 4200,
      })
      return null
    }
    return permissions.sort()
  }

  function openCreate(): void {
    createForm.username = ''
    createForm.password = ''
    createForm.expiresAt = defaultExpiry()
    createForm.agentPermissions = []
    createForm.additionalPermissions = ''
    createForm.proxyAddressIds = []
    createForm.auditReason = ''
    createMinimumExpiry.value = minimumFutureExpiry()
    createVisible.value = true
  }

  function generateTemporaryPassword(): void {
    const alphabet =
      'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*'
    const bytes = crypto.getRandomValues(new Uint8Array(20))
    createForm.password = Array.from(
      bytes,
      (byte) => alphabet[byte % alphabet.length],
    ).join('')
  }

  async function submitCreate(): Promise<void> {
    const username = createForm.username.trim()
    if (!username) {
      toast.add({ severity: 'warn', summary: '请输入用户名', life: 2400 })
      return
    }
    if (Array.from(createForm.password).length < PASSWORD_MIN_CHARACTERS) {
      toast.add({
        severity: 'warn',
        summary: `初始密码至少需要 ${PASSWORD_MIN_CHARACTERS} 个字符`,
        life: 3000,
      })
      return
    }
    if (
      !createForm.expiresAt ||
      createForm.expiresAt.getTime() <= Date.now()
    ) {
      toast.add({
        severity: 'warn',
        summary: '请选择未来的密钥过期时间',
        detail: '新建用户的有效期为必填项，且必须晚于当前时间',
        life: 3600,
      })
      return
    }
    const additionalPermissions = parseAdditionalPermissions(
      createForm.additionalPermissions,
      createForm.agentPermissions.length,
    )
    if (!additionalPermissions) return
    if (!createForm.proxyAddressIds.length) {
      toast.add({
        severity: 'warn',
        summary: '请选择至少一个 Proxy 地址',
        detail: '新用户必须分配可用的远端 Proxy 地址',
        life: 3600,
      })
      return
    }
    if (!createForm.auditReason.trim()) {
      toast.add({
        severity: 'warn',
        summary: '请输入创建和权限分配原因',
        life: 3000,
      })
      return
    }
    createSaving.value = true
    try {
      await createManagedUser({
        username,
        password: createForm.password,
        expires_at: createForm.expiresAt.toISOString(),
        permissions: [
          ...createForm.agentPermissions,
          ...additionalPermissions,
        ],
        proxy_address_ids: createForm.proxyAddressIds,
        audit_reason: createForm.auditReason.trim(),
      })
      createVisible.value = false
      createForm.password = ''
      await services.refreshAdminUsers()
      toast.add({
        severity: 'success',
        summary: '用户和密钥对已创建',
        detail: '连接凭据已加密存储，只能由该用户授权的 Agent 领取',
        life: 6000,
      })
    } catch (error) {
      services.showError('创建用户失败', error)
    } finally {
      createSaving.value = false
    }
  }

  function openEdit(user: ManagedUser): void {
    editingUser.value = user
    editForm.role = user.account?.role ?? 'user'
    editForm.status = user.account?.status ?? 'active'
    editForm.enabled = user.profile?.enabled ?? true
    editForm.expiresAt = parseDate(user.profile?.expiresAt ?? null)
    const permissions = user.profile?.permissions ?? []
    editForm.agentPermissions =
      user.account?.role === 'admin'
        ? [...allAgentPermissionCodes]
        : agentPermissionOptions
            .filter((permission) =>
              permissions.includes(permission.code),
            )
            .map((permission) => permission.code)
    editForm.proxyAddressIds = user.proxyAddresses.map(
      (address) => address.id,
    )
    editForm.auditReason = ''
    editingCustomPermissions.value = permissions.filter(
      (permission) =>
        !basePermissionCodes.has(permission) &&
        !agentPermissionCodes.has(permission) &&
        !retiredPermissionCodes.has(permission),
    )
    editVisible.value = true
  }

  async function submitEdit(): Promise<void> {
    const user = editingUser.value
    if (!user) return
    if (!editingHasEditableFields.value) {
      editVisible.value = false
      return
    }
    if (
      user.account &&
      user.profile &&
      user.profile.origin !== 'legacy' &&
      (editForm.status !== 'disabled' || user.proxyAddresses.length > 0) &&
      !editForm.proxyAddressIds.length
    ) {
      toast.add({
        severity: 'warn',
        summary: '请选择至少一个 Proxy 地址',
        detail: '账号必须保留至少一个可用的远端 Proxy 地址',
        life: 3600,
      })
      return
    }
    if (
      editingRequiresAuditReason.value &&
      !editForm.auditReason.trim()
    ) {
      toast.add({
        severity: 'warn',
        summary: '请输入本次修改原因',
        detail: '管理员敏感操作必须写入审计原因',
        life: 3200,
      })
      return
    }
    const statusChanged =
      Boolean(user.account) &&
      !isRootAdmin(user) &&
      editForm.status !== user.account?.status
    const proxyAccessChanged =
      Boolean(user.profile) &&
      editForm.enabled !== user.profile?.enabled
    const permissionsChanged = editingPermissionsChanged.value
    editSaving.value = true
    try {
      await updateManagedUser(managedUsername(user), {
        role:
          user.account && !isRootAdmin(user)
            ? editForm.role
            : undefined,
        status: statusChanged ? editForm.status : undefined,
        enabled: proxyAccessChanged ? editForm.enabled : undefined,
        expires_at:
          user.profile && !editingProfileReadOnly.value
            ? editForm.expiresAt?.toISOString() ?? null
            : undefined,
        permissions:
          permissionsChanged &&
          user.profile &&
          user.profile.origin !== 'legacy' &&
          user.account
            ? [
                ...editForm.agentPermissions,
                ...editingCustomPermissions.value,
              ]
            : undefined,
        proxy_address_ids:
          user.account &&
          user.profile &&
          user.profile.origin !== 'legacy' &&
          editForm.proxyAddressIds.length
            ? editForm.proxyAddressIds
            : undefined,
        audit_reason: editingRequiresAuditReason.value
          ? editForm.auditReason.trim()
          : undefined,
      })
      editVisible.value = false
      editingUser.value = null
      await services.refreshAdminUsers()
      toast.add({
        severity: 'success',
        summary: '用户配置已更新',
        life: 2600,
      })
    } catch (error) {
      services.showError('更新用户失败', error)
    } finally {
      editSaving.value = false
    }
  }

  function confirmRotateAdminKey(user: ManagedUser): void {
    rotationUser.value = user
    rotationReason.value = ''
    rotationVisible.value = true
  }

  async function rotateAdminKey(user: ManagedUser): Promise<void> {
    const username = managedUsername(user)
    const reason = rotationReason.value.trim()
    if (!reason) {
      toast.add({
        severity: 'warn',
        summary: '请输入重生成密钥的原因',
        life: 2800,
      })
      return
    }
    rotatingUsername.value = username
    try {
      await rotateManagedUserKey(username, reason)
      rotationVisible.value = false
      rotationUser.value = null
      rotationReason.value = ''
      await services.refreshAdminUsers()
      toast.add({
        severity: 'success',
        summary: '用户密钥已重新生成',
        detail: '新的连接凭据只能由该用户授权的 Agent 领取',
        life: 5000,
      })
    } catch (error) {
      services.showError('无法重新生成用户密钥', error)
    } finally {
      rotatingUsername.value = ''
    }
  }

  function confirmDelete(user: ManagedUser): void {
    const blockedReason = deleteBlockedReason(user)
    if (blockedReason) {
      toast.add({
        severity: 'warn',
        summary: '暂不能删除用户',
        detail: blockedReason,
        life: 3600,
      })
      return
    }
    const username = managedUsername(user)
    confirm.require({
      header: '删除用户',
      message:
        `确定删除“${username}”吗？该用户的登录账户、代理配置和加密私钥都会被删除。`,
      icon: 'pi pi-trash',
      acceptLabel: '删除用户',
      rejectLabel: '取消',
      acceptClass: 'p-button-danger',
      accept: () => {
        void performDelete(username)
      },
    })
  }

  async function performDelete(username: string): Promise<void> {
    deletingUsername.value = username
    try {
      await deleteManagedUser(username)
      await services.refreshAdminUsers()
      toast.add({
        severity: 'success',
        summary: '用户已删除',
        life: 2600,
      })
    } catch (error) {
      services.showError('删除用户失败', error)
    } finally {
      deletingUsername.value = ''
    }
  }

  return {
    parseAdditionalPermissions, openCreate, generateTemporaryPassword,
    submitCreate, openEdit, submitEdit, confirmRotateAdminKey,
    rotateAdminKey, confirmDelete, performDelete,
  }
}
