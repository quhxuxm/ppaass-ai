import { computed, reactive, ref, watch } from 'vue'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import type {
  AccessRecord,
  AccountRole,
  AccountStatus,
  AgentDeviceAuthorizationInspection,
  AuditAction,
  AuditEvent,
  KeyRequest,
  ManagedUser,
  ProviderAvailability,
  ProxyAddress,
  SelfView,
  SessionState,
} from '../api'
import {
  agentPermissionCodes,
  allAgentPermissionCodes,
  basePermissionCodes,
  defaultExpiry,
  isExpired,
  isRootAdmin,
  managedUsername,
  minimumFutureExpiry,
  requestedAuthMode,
  restoreAgentAuthorization,
  retiredPermissionCodes,
  type AdminSection,
  type AppPage,
  type AuthMode,
} from './model'

export function createControllerState() {
  const toast = useToast()
  const confirm = useConfirm()
  const currentTime = ref(Date.now())
  const booting = ref(true)
  const authMode = ref<AuthMode>(requestedAuthMode())
  const authLoading = ref(false)
  const providers = ref<ProviderAvailability>({ localRegistration: true })
  const session = ref<SessionState | null>(null)
  const self = ref<SelfView | null>(null)
  const activePage = ref<AppPage>('account')
  const pageLoading = ref(false)
  const authForm = reactive({ username: '', password: '' })
  const initialAgentAuthorization = restoreAgentAuthorization()
  const agentAuthorizationActive = ref(initialAgentAuthorization.active)
  const agentAuthorizationCode = ref(initialAgentAuthorization.code)
  const agentAuthorizationInput = ref(initialAgentAuthorization.code)
  const agentAuthorization =
    ref<AgentDeviceAuthorizationInspection | null>(null)
  const agentAuthorizationLoading = ref(false)
  const agentAuthorizationDecisionLoading =
    ref<'approve' | 'deny' | null>(null)
  const agentAuthorizationOutcome = ref<'authorized' | 'denied' | null>(null)
  const agentAuthorizationError = ref('')

  const keyRequestLoading = ref(false)
  const keyRequestDialogVisible = ref(false)
  const keyRotationLoading = ref(false)
  const ownRotationVisible = ref(false)
  const ownRotationReason = ref('')
  const passwordSaving = ref(false)
  const profileSaving = ref(false)
  const passwordForm = reactive({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  })
  const accessRecords = ref<AccessRecord[]>([])
  const accessRecordsLoading = ref(false)
  const accessRetentionDays = ref(7)
  const accessHostFilter = ref('')
  const accessRecordsFirst = ref(0)

  const adminUsers = ref<ManagedUser[]>([])
  const adminKeyRequests = ref<KeyRequest[]>([])
  const adminAuditEvents = ref<AuditEvent[]>([])
  const proxyAddresses = ref<ProxyAddress[]>([])
  const adminLoading = ref(false)
  const keyRequestsLoading = ref(false)
  const auditEventsLoading = ref(false)
  const auditEventsLoadingMore = ref(false)
  const auditEventsHasMore = ref(false)
  const auditEventsLoaded = ref(false)
  const auditSearch = ref('')
  const auditAction = ref<AuditAction | null>(null)
  const activeAdminSection = ref<AdminSection>('users')
  const adminSearch = ref('')
  const createVisible = ref(false)
  const createSaving = ref(false)
  const createMinimumExpiry = ref(minimumFutureExpiry())
  const createForm = reactive({
    username: '',
    password: '',
    expiresAt: defaultExpiry(),
    agentPermissions: [] as string[],
    additionalPermissions: '',
    proxyAddressIds: [] as string[],
    auditReason: '',
  })
  const editVisible = ref(false)
  const editSaving = ref(false)
  const editingUser = ref<ManagedUser | null>(null)
  const editForm = reactive({
    role: 'user' as AccountRole,
    status: 'active' as AccountStatus,
    enabled: true,
    expiresAt: null as Date | null,
    agentPermissions: [] as string[],
    proxyAddressIds: [] as string[],
    auditReason: '',
  })
  const displayedEditAgentPermissions = computed({
    get: () =>
      editForm.role === 'admin'
        ? allAgentPermissionCodes
        : editForm.agentPermissions,
    set: (permissions: string[]) => {
      if (editForm.role === 'user') editForm.agentPermissions = permissions
    },
  })
  const editingCustomPermissions = ref<string[]>([])
  const deletingUsername = ref('')
  const rotatingUsername = ref('')
  const approvalVisible = ref(false)
  const approvalSaving = ref(false)
  const approvalRequest = ref<KeyRequest | null>(null)
  const approvalMinimumExpiry = ref(minimumFutureExpiry())
  const approvalExpiresAt = ref<Date | null>(defaultExpiry())
  const approvalProxyAddressIds = ref<string[]>([])
  const approvalReason = ref('')
  const rejectingRequestId = ref('')
  const rejectionVisible = ref(false)
  const rejectionRequest = ref<KeyRequest | null>(null)
  const rejectionReason = ref('')
  const rotationVisible = ref(false)
  const rotationUser = ref<ManagedUser | null>(null)
  const rotationReason = ref('')
  const retentionDays = ref<number | null>(7)
  const retentionSaving = ref(false)
  const enabledProxyAddresses = computed(() =>
    proxyAddresses.value.filter((address) => address.enabled),
  )

  const isAuthenticated = computed(
    () =>
      session.value?.authenticated === true &&
      session.value.account !== null,
  )
  const isAgentHandoffSession = computed(
    () => session.value?.agentHandoff === true,
  )
  const isAdmin = computed(() => session.value?.account?.role === 'admin')
  const account = computed(
    () => self.value?.account ?? session.value?.account ?? null,
  )
  const profile = computed(() => self.value?.profile ?? null)
  const additionalPermissions = computed(() =>
    [
      ...new Set(
        (profile.value?.permissions ?? []).filter(
          (permission) =>
            !basePermissionCodes.has(permission) &&
            !agentPermissionCodes.has(permission) &&
            !retiredPermissionCodes.has(permission),
        ),
      ),
    ].sort((left, right) => left.localeCompare(right)),
  )
  const keyState = computed(() => {
    const value = self.value?.keyState ?? 'missing'
    return value === 'active' &&
      isExpired(profile.value?.expiresAt ?? null, currentTime.value)
      ? 'expired'
      : value
  })
  const pendingKeyRequest = computed(
    () => self.value?.pendingKeyRequest ?? null,
  )
  const profileExpired = computed(() =>
    isExpired(profile.value?.expiresAt ?? null, currentTime.value),
  )
  const canRotateOwnKey = computed(
    () =>
      keyState.value === 'active' &&
      Boolean(profile.value?.enabled) &&
      !profileExpired.value &&
      (isAdmin.value ||
        Boolean(profile.value?.permissions.includes('key.rotate'))),
  )
  const filteredAccessRecords = computed(() => {
    const query = accessHostFilter.value.trim().toLocaleLowerCase()
    if (!query) return accessRecords.value
    return accessRecords.value.filter((record) =>
      record.targetHost.toLocaleLowerCase().includes(query),
    )
  })
  watch(accessHostFilter, () => {
    accessRecordsFirst.value = 0
  })
  const filteredAdminUsers = computed(() => {
    const query = adminSearch.value.trim().toLocaleLowerCase()
    if (!query) return adminUsers.value
    return adminUsers.value.filter((user) =>
      [
        managedUsername(user),
        user.account?.displayName,
        user.account?.email,
        user.profile?.origin,
      ].some((value) => value?.toLocaleLowerCase().includes(query)),
    )
  })
  const adminMetrics = computed(() => {
    let activeAccounts = 0
    let disabledAccounts = 0
    for (const user of adminUsers.value) {
      if (user.account?.status === 'active') activeAccounts += 1
      else if (user.account?.status === 'disabled') disabledAccounts += 1
    }
    return {
      total: adminUsers.value.length,
      activeAccounts,
      disabledAccounts,
      pending: adminKeyRequests.value.length,
    }
  })
  const adminSectionOptions = computed(() => [
    {
      value: 'users' as const,
      label: '用户列表',
      icon: 'pi pi-users',
      count: adminMetrics.value.total,
    },
    {
      value: 'approvals' as const,
      label: '密钥审批',
      icon: 'pi pi-key',
      count: adminMetrics.value.pending,
    },
    {
      value: 'proxies' as const,
      label: 'Proxy 节点',
      icon: 'pi pi-server',
      count: proxyAddresses.value.length,
    },
    {
      value: 'audit' as const,
      label: '操作审计',
      icon: 'pi pi-shield',
      count: null,
    },
  ])
  const editingProfileReadOnly = computed(() => {
    const user = editingUser.value
    return (
      !user?.profile ||
      user.profile.origin === 'legacy' ||
      user.keyState === 'missing' ||
      user.keyState === 'expired'
    )
  })
  const editingRootAdmin = computed(() => isRootAdmin(editingUser.value))
  const editingHasEditableFields = computed(
    () =>
      (Boolean(editingUser.value?.account) && !editingRootAdmin.value) ||
      Boolean(editingUser.value?.profile),
  )
  const editingPermissionsChanged = computed(() => {
    const user = editingUser.value
    if (
      !user?.profile ||
      user.profile.origin === 'legacy' ||
      !user.account ||
      editForm.role !== 'user'
    ) {
      return false
    }
    const desired = new Set([
      ...basePermissionCodes,
      ...editForm.agentPermissions,
      ...editingCustomPermissions.value,
    ])
    const current = new Set(user.profile.permissions)
    return (
      desired.size !== current.size ||
      [...desired].some((permission) => !current.has(permission))
    )
  })
  const editingRequiresAuditReason = computed(() => {
    const user = editingUser.value
    return Boolean(
      user &&
        ((user.account &&
          !isRootAdmin(user) &&
          editForm.status !== user.account.status) ||
          (user.profile && editForm.enabled !== user.profile.enabled) ||
          editingPermissionsChanged.value),
    )
  })

  return {
    toast, confirm, currentTime, booting, authMode, authLoading, providers,
    session, self, activePage, pageLoading, authForm,
    agentAuthorizationActive, agentAuthorizationCode,
    agentAuthorizationInput, agentAuthorization, agentAuthorizationLoading,
    agentAuthorizationDecisionLoading, agentAuthorizationOutcome,
    agentAuthorizationError, keyRequestLoading, keyRequestDialogVisible,
    keyRotationLoading, ownRotationVisible, ownRotationReason, passwordSaving,
    profileSaving, passwordForm, accessRecords, accessRecordsLoading,
    accessRetentionDays, accessHostFilter, accessRecordsFirst, adminUsers,
    adminKeyRequests, adminAuditEvents, proxyAddresses, adminLoading,
    keyRequestsLoading, auditEventsLoading, auditEventsLoadingMore,
    auditEventsHasMore, auditEventsLoaded, auditSearch, auditAction,
    activeAdminSection, adminSearch, createVisible, createSaving,
    createMinimumExpiry, createForm, editVisible, editSaving, editingUser,
    editForm, displayedEditAgentPermissions, editingCustomPermissions,
    deletingUsername, rotatingUsername, approvalVisible, approvalSaving,
    approvalRequest, approvalMinimumExpiry, approvalExpiresAt,
    approvalProxyAddressIds, approvalReason, rejectingRequestId,
    rejectionVisible, rejectionRequest, rejectionReason, rotationVisible,
    rotationUser, rotationReason, retentionDays, retentionSaving,
    enabledProxyAddresses, isAuthenticated, isAgentHandoffSession, isAdmin,
    account, profile, additionalPermissions, keyState, pendingKeyRequest,
    profileExpired, canRotateOwnKey, filteredAccessRecords,
    filteredAdminUsers, adminMetrics, adminSectionOptions,
    editingProfileReadOnly, editingRootAdmin, editingHasEditableFields,
    editingPermissionsChanged, editingRequiresAuditReason,
  }
}

export type ControllerState = ReturnType<typeof createControllerState>
