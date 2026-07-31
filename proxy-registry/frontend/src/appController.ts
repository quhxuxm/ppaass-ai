import {
  computed,
  inject,
  onMounted,
  onUnmounted,
  reactive,
  ref,
  watch,
  type InjectionKey,
} from 'vue'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import {
  ApiError,
  approveAgentDeviceAuthorization,
  approveKeyRequest,
  changeMyPassword,
  clearClientSession,
  createManagedUser,
  deleteManagedUser,
  denyAgentDeviceAuthorization,
  getAccessLogSettings,
  getMe,
  getMyKeyRequest,
  getProviders,
  getSession,
  inspectAgentDeviceAuthorization,
  listPendingKeyRequests,
  listAuditEvents,
  listProxyAddresses,
  listMyAccessRecords,
  listManagedUsers,
  login,
  logout,
  register,
  rejectKeyRequest,
  rotateManagedUserKey,
  rotateMyKey,
  submitMyKeyRequest,
  updateAccessLogSettings,
  updateManagedUser,
  updateMyProfile,
  type AccessRecord,
  type AuditAction,
  type AuditEvent,
  type AgentDeviceAuthorizationInspection,
  type AccountRole,
  type AccountStatus,
  type KeyRequest,
  type ManagedUser,
  type ProviderAvailability,
  type ProxyAddress,
  type SelfView,
  type SessionState,
  type UpdateMyProfilePayload,
} from './api'

export function useAppController() {
type AuthMode = 'login' | 'register'
type AppPage = 'account' | 'admin'
type AdminSection = 'users' | 'approvals' | 'proxies' | 'audit'

const PASSWORD_MIN_CHARACTERS = 8
const AGENT_AUTHORIZATION_STORAGE_KEY = 'ppaass-agent-authorization'

function requestedAuthMode(): AuthMode {
  return new URLSearchParams(window.location.search).get('mode') === 'register'
    ? 'register'
    : 'login'
}

interface PermissionOption {
  code: string
  label: string
  description: string
}

const basePermissionOptions: PermissionOption[] = [
  {
    code: 'proxy.connect.tcp',
    label: 'TCP 代理',
    description: '允许建立 TCP 隧道',
  },
  {
    code: 'proxy.connect.udp',
    label: 'UDP 代理',
    description: '允许建立 UDP 隧道',
  },
  {
    code: 'key.private.read',
    label: 'Agent 凭据领取',
    description: '允许本人授权的 Agent 安全领取连接凭据',
  },
  {
    code: 'key.rotate',
    label: '更新密钥',
    description: '允许用户重新生成密钥对',
  },
]

const basePermissionCodes = new Set(
  basePermissionOptions.map((permission) => permission.code),
)

const agentPermissionOptions: PermissionOption[] = [
  {
    code: 'agent.packet_capture',
    label: '抓包',
    description: '允许使用抓包页面；无权限时 Agent 不显示抓包功能',
  },
  {
    code: 'agent.egress.edit',
    label: '修改出口配置',
    description: '允许显示并修改出口；无权限时隐藏出口并使用内置默认值',
  },
  {
    code: 'agent.runtime_threads.edit',
    label: '修改系统运行参数',
    description: '允许显示并修改运行参数；无权限时隐藏面板并使用内置默认值',
  },
]

const allAgentPermissionCodes = agentPermissionOptions.map(
  (permission) => permission.code,
)
const agentPermissionCodes = new Set(allAgentPermissionCodes)
const retiredPermissionCodes = new Set(['agent.config.view'])

const roleOptions = [
  { label: '普通用户', value: 'user' },
  { label: '管理员', value: 'admin' },
]

const statusOptions = [
  { label: '启用账号（允许登录）', value: 'active' },
  { label: '停用账号（禁止登录）', value: 'disabled' },
]

const toast = useToast()
const confirm = useConfirm()
const currentTime = ref(Date.now())
let clockTimer: ReturnType<typeof setInterval> | undefined

const booting = ref(true)
const authMode = ref<AuthMode>(requestedAuthMode())
const authLoading = ref(false)
const providers = ref<ProviderAvailability>({
  localRegistration: true,
})
const session = ref<SessionState | null>(null)
const self = ref<SelfView | null>(null)
const activePage = ref<AppPage>('account')
const pageLoading = ref(false)
const authForm = reactive({ username: '', password: '' })
const initialAgentAuthorization = restoreAgentAuthorization()
const agentAuthorizationActive = ref(initialAgentAuthorization.active)
const agentAuthorizationCode = ref(initialAgentAuthorization.code)
const agentAuthorizationInput = ref(initialAgentAuthorization.code)
const agentAuthorization = ref<AgentDeviceAuthorizationInspection | null>(null)
const agentAuthorizationLoading = ref(false)
const agentAuthorizationDecisionLoading = ref<'approve' | 'deny' | null>(null)
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
    if (editForm.role === 'user') {
      editForm.agentPermissions = permissions
    }
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
  () => session.value?.authenticated === true && session.value.account !== null,
)
const isAgentHandoffSession = computed(
  () => session.value?.agentHandoff === true,
)
const isAdmin = computed(() => session.value?.account?.role === 'admin')
const account = computed(() => self.value?.account ?? session.value?.account ?? null)
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
  const state = self.value?.keyState ?? 'missing'
  return state === 'active' && isExpired(profile.value?.expiresAt ?? null)
    ? 'expired'
    : state
})
const pendingKeyRequest = computed(() => self.value?.pendingKeyRequest ?? null)
const profileExpired = computed(() => isExpired(profile.value?.expiresAt ?? null))
const canRotateOwnKey = computed(
  () =>
    keyState.value === 'active' &&
    Boolean(profile.value?.enabled) &&
    !profileExpired.value &&
    hasEffectivePermission('key.rotate'),
)
const filteredAccessRecords = computed(() => {
  const query = accessHostFilter.value.trim().toLocaleLowerCase()
  if (!query) {
    return accessRecords.value
  }
  return accessRecords.value.filter((record) =>
    record.targetHost.toLocaleLowerCase().includes(query),
  )
})
watch(accessHostFilter, () => {
  accessRecordsFirst.value = 0
})
const filteredAdminUsers = computed(() => {
  const query = adminSearch.value.trim().toLocaleLowerCase()
  if (!query) {
    return adminUsers.value
  }
  return adminUsers.value.filter((user) => {
    const values = [
      managedUsername(user),
      user.account?.displayName,
      user.account?.email,
      user.profile?.origin,
    ]
    return values.some((value) => value?.toLocaleLowerCase().includes(query))
  })
})
const adminMetrics = computed(() => {
  let activeAccounts = 0
  let disabledAccounts = 0
  for (const user of adminUsers.value) {
    if (user.account?.status === 'active') {
      activeAccounts += 1
    } else if (user.account?.status === 'disabled') {
      disabledAccounts += 1
    }
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
  if (!user) return false
  if (
    !user.profile ||
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
  if (!user) return false
  return (
    (Boolean(user.account) &&
      !isRootAdmin(user) &&
      editForm.status !== user.account?.status) ||
    (Boolean(user.profile) && editForm.enabled !== user.profile?.enabled) ||
    editingPermissionsChanged.value
  )
})
onMounted(async () => {
  clockTimer = setInterval(() => {
    currentTime.value = Date.now()
  }, 5000)
  try {
    const [providerResult, sessionResult] = await Promise.allSettled([
      getProviders(),
      getSession(),
    ])
    if (providerResult.status === 'fulfilled') {
      providers.value = providerResult.value
      if (!providers.value.localRegistration && authMode.value === 'register') {
        authMode.value = 'login'
      }
    }
    if (sessionResult.status === 'fulfilled') {
      session.value = sessionResult.value
    }

    if (session.value?.authenticated) {
      await refreshSelf()
      if (agentAuthorizationActive.value && agentAuthorizationCode.value) {
        await refreshAgentAuthorization()
      }
    }
  } finally {
    booting.value = false
  }
})

onUnmounted(() => {
  if (clockTimer) {
    clearInterval(clockTimer)
  }
})

watch(activePage, async (page) => {
  if (page !== 'account') {
    resetPasswordForm()
  }
  if (page === 'admin' && isAdmin.value) {
    await refreshAdminUsers()
    if (activeAdminSection.value === 'audit') {
      await refreshAuditEvents()
    }
  }
})

watch(createVisible, (visible) => {
  if (!visible) {
    createForm.password = ''
  }
})

function errorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) {
    return error.message
  }
  return '发生未知错误，请稍后重试'
}

function showError(summary: string, error: unknown): void {
  toast.add({
    severity: 'error',
    summary,
    detail: errorMessage(error),
    life: 5000,
  })
}

function resetPasswordForm(): void {
  passwordForm.currentPassword = ''
  passwordForm.newPassword = ''
  passwordForm.confirmPassword = ''
}

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
    resetPasswordForm()
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
    showError('修改密码失败', error)
  } finally {
    passwordSaving.value = false
  }
}

async function saveMyProfile(payload: UpdateMyProfilePayload): Promise<void> {
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
    showError('保存个人资料失败', error)
  } finally {
    profileSaving.value = false
  }
}

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
    await refreshSelf()
    if (agentAuthorizationActive.value && agentAuthorizationCode.value) {
      await refreshAgentAuthorization()
    }
    toast.add({
      severity: 'success',
      summary: authMode.value === 'register' ? '账号注册成功' : '欢迎回来',
      life: 2600,
    })
  } catch (error) {
    showError(authMode.value === 'register' ? '注册失败' : '登录失败', error)
  } finally {
    authForm.password = ''
    authLoading.value = false
  }
}

async function performLogout(): Promise<void> {
  resetPasswordForm()
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
    persistAgentAuthorization()
  } catch (error) {
    agentAuthorization.value = null
    agentAuthorizationError.value = errorMessage(error)
  } finally {
    agentAuthorizationLoading.value = false
  }
}

async function decideAgentAuthorization(
  decision: 'approve' | 'deny',
): Promise<void> {
  if (!agentAuthorization.value || !agentAuthorizationCode.value) {
    return
  }
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
    agentAuthorizationError.value = errorMessage(error)
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

async function refreshSelf(): Promise<void> {
  pageLoading.value = true
  try {
    const nextSelf = await getMe()
    try {
      nextSelf.pendingKeyRequest = await getMyKeyRequest(
        nextSelf.profile?.username ?? nextSelf.account.username,
      )
    } catch {
      // /me already carries the pending request; keep it if the refresh endpoint
      // is temporarily unavailable.
    }
    self.value = nextSelf
    if (nextSelf.account) {
      session.value = {
        registryInstanceId: session.value?.registryInstanceId ?? 'unknown',
        authenticated: true,
        account: nextSelf.account,
        agentHandoff: session.value?.agentHandoff ?? false,
      }
    }
    if (nextSelf.account.role === 'admin') {
      // 管理员登录完成后立即读取待审批申请。不能只依赖切换到“用户管理”
      // 页面的 watch；页面状态被保留或申请刚刚提交时，watch 不一定再次触发。
      await Promise.all([
        refreshAccessRecords(false),
        refreshAdminUsers(),
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
      showError('无法读取账户信息', error)
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
    if (showFailure) {
      showError('无法读取最近访问记录', error)
    }
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
    if (self.value) {
      self.value.pendingKeyRequest = request
    }
    keyRequestDialogVisible.value = false
    toast.add({
      severity: 'success',
      summary: '密钥申请已提交',
      detail: '管理员批准并设置有效期后，已授权 Agent 可以领取新凭据',
      life: 5000,
    })
  } catch (error) {
    showError('密钥申请提交失败', error)
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
    toast.add({ severity: 'warn', summary: '请输入重生成密钥的原因', life: 2800 })
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
    showError('密钥更新失败', error)
  } finally {
    keyRotationLoading.value = false
  }
}

async function refreshAdminUsers(): Promise<void> {
  if (!isAdmin.value) {
    return
  }
  adminLoading.value = true
  keyRequestsLoading.value = true
  try {
    const [usersResult, requestsResult, settingsResult, addressesResult] =
      await Promise.allSettled([
        listManagedUsers(),
        listPendingKeyRequests(),
        getAccessLogSettings(),
        listProxyAddresses(),
      ])
    if (usersResult.status === 'fulfilled') {
      adminUsers.value = usersResult.value
    } else {
      showError('无法读取用户列表', usersResult.reason)
    }
    if (requestsResult.status === 'fulfilled') {
      adminKeyRequests.value = requestsResult.value.filter(
        (request) => request.status === 'pending',
      )
    } else {
      showError('无法读取密钥申请', requestsResult.reason)
    }
    if (settingsResult.status === 'fulfilled') {
      retentionDays.value = settingsResult.value.retentionDays
    }
    if (addressesResult.status === 'fulfilled') {
      proxyAddresses.value = addressesResult.value
    } else {
      showError('无法读取 Proxy 地址目录', addressesResult.reason)
    }
    auditEventsLoaded.value = false
  } finally {
    adminLoading.value = false
    keyRequestsLoading.value = false
  }
}

async function refreshAuditEvents(): Promise<void> {
  auditEventsLoading.value = true
  try {
    const page = await listAuditEvents({
      limit: 50,
      search: auditSearch.value,
      action: auditAction.value,
    })
    adminAuditEvents.value = page.events
    auditEventsHasMore.value = page.hasMore
    auditEventsLoaded.value = true
  } catch (error) {
    showError('无法读取操作审计', error)
  } finally {
    auditEventsLoading.value = false
  }
}

async function selectAdminSection(section: AdminSection): Promise<void> {
  activeAdminSection.value = section
  if (section === 'audit' && !auditEventsLoaded.value) {
    await refreshAuditEvents()
  }
}

async function filterAuditEvents(
  search: string,
  action: AuditAction | null,
): Promise<void> {
  auditSearch.value = search
  auditAction.value = action
  await refreshAuditEvents()
}

async function loadMoreAuditEvents(): Promise<void> {
  if (
    auditEventsLoading.value ||
    auditEventsLoadingMore.value ||
    !auditEventsHasMore.value
  ) {
    return
  }
  const beforeId =
    adminAuditEvents.value[adminAuditEvents.value.length - 1]?.id
  if (!beforeId) {
    return
  }
  auditEventsLoadingMore.value = true
  try {
    const page = await listAuditEvents({
      beforeId,
      limit: 50,
      search: auditSearch.value,
      action: auditAction.value,
    })
    const knownIds = new Set(adminAuditEvents.value.map((event) => event.id))
    adminAuditEvents.value.push(
      ...page.events.filter((event) => !knownIds.has(event.id)),
    )
    auditEventsHasMore.value = page.hasMore
  } catch (error) {
    showError('无法加载更早的操作审计', error)
  } finally {
    auditEventsLoadingMore.value = false
  }
}

async function saveRetentionDays(): Promise<void> {
  const days = retentionDays.value
  if (!Number.isInteger(days) || days === null || days < 1 || days > 365) {
    toast.add({
      severity: 'warn',
      summary: '保留天数无效',
      detail: '请输入 1 到 365 之间的整数',
      life: 3200,
    })
    return
  }
  retentionSaving.value = true
  try {
    const settings = await updateAccessLogSettings(days)
    retentionDays.value = settings.retentionDays
    toast.add({
      severity: 'success',
      summary: '访问记录保留策略已更新',
      detail: `普通用户现在可以查看最近 ${settings.retentionDays} 天的本人访问记录`,
      life: 4200,
    })
  } catch (error) {
    showError('更新访问记录保留策略失败', error)
  } finally {
    retentionSaving.value = false
  }
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
  if (!additionalPermissions) {
    return
  }
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
    await refreshAdminUsers()
    toast.add({
      severity: 'success',
      summary: '用户和密钥对已创建',
      detail: '连接凭据已加密存储，只能由该用户授权的 Agent 领取',
      life: 6000,
    })
  } catch (error) {
    showError('创建用户失败', error)
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
          .filter((permission) => permissions.includes(permission.code))
          .map((permission) => permission.code)
  editForm.proxyAddressIds = user.proxyAddresses.map((address) => address.id)
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
  if (!user) {
    return
  }
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
  if (editingRequiresAuditReason.value && !editForm.auditReason.trim()) {
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
    Boolean(user.profile) && editForm.enabled !== user.profile?.enabled
  const permissionsChanged = editingPermissionsChanged.value
  editSaving.value = true
  try {
    await updateManagedUser(managedUsername(user), {
      role: user.account && !isRootAdmin(user) ? editForm.role : undefined,
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
    await refreshAdminUsers()
    toast.add({ severity: 'success', summary: '用户配置已更新', life: 2600 })
  } catch (error) {
    showError('更新用户失败', error)
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
    toast.add({ severity: 'warn', summary: '请输入重生成密钥的原因', life: 2800 })
    return
  }
  rotatingUsername.value = username
  try {
    await rotateManagedUserKey(username, reason)
    rotationVisible.value = false
    rotationUser.value = null
    rotationReason.value = ''
    await refreshAdminUsers()
    toast.add({
      severity: 'success',
      summary: '用户密钥已重新生成',
      detail: '新的连接凭据只能由该用户授权的 Agent 领取',
      life: 5000,
    })
  } catch (error) {
    showError('无法重新生成用户密钥', error)
  } finally {
    rotatingUsername.value = ''
  }
}

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
    toast.add({ severity: 'warn', summary: '请输入批准原因', life: 2800 })
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
    await refreshAdminUsers()
    toast.add({
      severity: 'success',
      summary: '密钥申请已批准',
      detail: '新密钥已生成，只有用户本人登录后可以查看',
      life: 5000,
    })
  } catch (error) {
    showError('批准密钥申请失败', error)
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
  if (!request) {
    return
  }
  if (!rejectionReason.value.trim()) {
    toast.add({ severity: 'warn', summary: '请输入拒绝原因', life: 2800 })
    return
  }
  rejectingRequestId.value = request.id
  try {
    await rejectKeyRequest(request.id, rejectionReason.value)
    rejectionVisible.value = false
    rejectionRequest.value = null
    rejectionReason.value = ''
    await refreshAdminUsers()
    toast.add({
      severity: 'success',
      summary: '密钥申请已拒绝',
      life: 3000,
    })
  } catch (error) {
    showError('拒绝密钥申请失败', error)
  } finally {
    rejectingRequestId.value = ''
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
    message: `确定删除“${username}”吗？该用户的登录账户、代理配置和加密私钥都会被删除。`,
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
    await refreshAdminUsers()
    toast.add({ severity: 'success', summary: '用户已删除', life: 2600 })
  } catch (error) {
    showError('删除用户失败', error)
  } finally {
    deletingUsername.value = ''
  }
}

function managedUsername(user: ManagedUser): string {
  return (
    user.profile?.username ??
    user.account?.linkedUsername ??
    user.account?.username ??
    '未知用户'
  )
}

function deleteBlockedReason(user: ManagedUser): string | null {
  if (isRootAdmin(user)) {
    return '根管理员 admin 不能停用、降级或删除'
  }
  if (user.account) {
    return user.account.status === 'disabled' ? null : '请先停用账号'
  }
  if (user.profile?.origin === 'legacy') {
    return user.profile.enabled ? '请先暂停代理连接' : null
  }
  return '该用户没有可删除的 Web 账号或 legacy 配置'
}

function isRootAdmin(user: ManagedUser | null): boolean {
  return user?.account?.username === 'admin'
}

function accountStatusLabel(user: ManagedUser): string {
  if (!user.account) {
    return '无 Web 账号'
  }
  return user.account.status === 'active' ? '账号已启用' : '账号已停用'
}

function canAdminRotateDirectly(user: ManagedUser): boolean {
  return (
    Boolean(user.profile) &&
    user.profile?.origin !== 'legacy' &&
    user.keyState === 'active'
  )
}

function keyRequestKindLabel(request: KeyRequest): string {
  return request.kind === 'rotate' ? '过期重生成' : '首次申请'
}

function managedAgentPermissions(user: ManagedUser): PermissionOption[] {
  const permissions = new Set(user.profile?.permissions ?? [])
  return agentPermissionOptions.filter((permission) =>
    permissions.has(permission.code),
  )
}

function managedCustomPermissions(user: ManagedUser): string[] {
  return (user.profile?.permissions ?? []).filter(
    (permission) =>
      !basePermissionCodes.has(permission) &&
      !agentPermissionCodes.has(permission) &&
      !retiredPermissionCodes.has(permission),
  )
}

function managedPermissionsTitle(user: ManagedUser): string {
  if (user.account?.role === 'admin') {
    return '管理员拥有全部 Agent 权限'
  }

  const permissions = [
    ...managedAgentPermissions(user).map((permission) => permission.label),
    ...managedCustomPermissions(user),
  ]
  return permissions.length
    ? permissions.join('、')
    : '仅包含固定授予的 Agent 基础功能'
}

function managedHiddenPermissionCount(user: ManagedUser): number {
  const visibleAgentPermissions = Math.min(
    managedAgentPermissions(user).length,
    2,
  )
  return Math.max(
    0,
    managedAgentPermissions(user).length +
      managedCustomPermissions(user).length -
      visibleAgentPermissions,
  )
}

function managedProxyAddressesTitle(user: ManagedUser): string {
  return user.proxyAddresses
    .map((address) => `${address.label}（${address.address}）`)
    .join('\n')
}

function hasEffectivePermission(code: string): boolean {
  return isAdmin.value || Boolean(profile.value?.permissions.includes(code))
}

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
      detail: `“${invalid}”只能包含 ASCII 小写字母、数字、点、下划线或连字符，且不超过 64 字节`,
      life: 5200,
    })
    return null
  }
  const maximumCustomPermissions = 28 - selectedAgentPermissionCount
  if (permissions.length > maximumCustomPermissions) {
    toast.add({
      severity: 'warn',
      summary: '附加权限过多',
      detail: `当前已选择 ${selectedAgentPermissionCount} 项 Agent 权限，最多还能分配 ${maximumCustomPermissions} 项自定义权限`,
      life: 4200,
    })
    return null
  }
  return permissions.sort()
}

function formatExpiry(value: string | null | undefined): string {
  if (!value) {
    return '永久有效'
  }
  const date = parseDate(value)
  if (!date) {
    return value
  }
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date)
}

function parseDate(value: string | null): Date | null {
  if (!value) {
    return null
  }
  if (/^-?\d+$/.test(value)) {
    const numeric = Number(value)
    const milliseconds = Math.abs(numeric) < 100_000_000_000 ? numeric * 1000 : numeric
    const date = new Date(milliseconds)
    return Number.isNaN(date.getTime()) ? null : date
  }
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

function isExpired(value: string | null): boolean {
  const date = parseDate(value)
  return date !== null && date.getTime() <= currentTime.value
}

function defaultExpiry(): Date {
  const value = new Date()
  value.setFullYear(value.getFullYear() + 1)
  value.setSeconds(0, 0)
  return value
}

function minimumFutureExpiry(): Date {
  return new Date(Date.now() + 60_000)
}

function restoreAgentAuthorization(): { active: boolean; code: string } {
  const hash = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash
  if (hash === 'agent-authorize') {
    return { active: true, code: '' }
  }
  if (hash.startsWith('agent-authorize=')) {
    const code = decodeURIComponent(hash.slice('agent-authorize='.length)).trim()
    try {
      window.sessionStorage.setItem(
        AGENT_AUTHORIZATION_STORAGE_KEY,
        JSON.stringify({ active: true, code }),
      )
    } catch {
      // sessionStorage 可能被浏览器隐私策略禁用；页面内状态仍然可用。
    }
    return { active: true, code }
  }
  try {
    const stored = window.sessionStorage.getItem(
      AGENT_AUTHORIZATION_STORAGE_KEY,
    )
    if (stored) {
      const value = JSON.parse(stored) as {
        active?: unknown
        code?: unknown
      }
      if (value.active === true) {
        return {
          active: true,
          code: typeof value.code === 'string' ? value.code : '',
        }
      }
    }
  } catch {
    // 忽略损坏或不可用的浏览器临时存储。
  }
  return { active: false, code: '' }
}

function persistAgentAuthorization(): void {
  if (!agentAuthorizationActive.value) {
    return
  }
  try {
    window.sessionStorage.setItem(
      AGENT_AUTHORIZATION_STORAGE_KEY,
      JSON.stringify({
        active: true,
        code: agentAuthorizationCode.value || agentAuthorizationInput.value.trim(),
      }),
    )
  } catch {
    // 页面当前生命周期内仍会保留授权状态。
  }
}

function clearStoredAgentAuthorization(): void {
  try {
    window.sessionStorage.removeItem(AGENT_AUTHORIZATION_STORAGE_KEY)
  } catch {
    // 无需阻止用户离开授权页面。
  }
}

function clearAgentAuthorizationLocation(): void {
  window.history.replaceState(
    {},
    document.title,
    `${window.location.pathname}${window.location.search}`,
  )
}

  return {
    PASSWORD_MIN_CHARACTERS,
    AGENT_AUTHORIZATION_STORAGE_KEY,
    requestedAuthMode,
    basePermissionOptions,
    basePermissionCodes,
    agentPermissionOptions,
    allAgentPermissionCodes,
    agentPermissionCodes,
    retiredPermissionCodes,
    roleOptions,
    statusOptions,
    toast,
    confirm,
    currentTime,
    clockTimer,
    booting,
    authMode,
    authLoading,
    providers,
    session,
    self,
    activePage,
    pageLoading,
    authForm,
    initialAgentAuthorization,
    agentAuthorizationActive,
    agentAuthorizationCode,
    agentAuthorizationInput,
    agentAuthorization,
    agentAuthorizationLoading,
    agentAuthorizationDecisionLoading,
    agentAuthorizationOutcome,
    agentAuthorizationError,
    keyRequestLoading,
    keyRequestDialogVisible,
    keyRotationLoading,
    ownRotationVisible,
    ownRotationReason,
    passwordSaving,
    profileSaving,
    passwordForm,
    accessRecords,
    accessRecordsLoading,
    accessRetentionDays,
    accessHostFilter,
    accessRecordsFirst,
    adminUsers,
    adminKeyRequests,
    adminAuditEvents,
    proxyAddresses,
    adminLoading,
    keyRequestsLoading,
    auditEventsLoading,
    auditEventsLoadingMore,
    auditEventsHasMore,
    auditEventsLoaded,
    auditSearch,
    auditAction,
    activeAdminSection,
    adminSearch,
    createVisible,
    createSaving,
    createMinimumExpiry,
    createForm,
    editVisible,
    editSaving,
    editingUser,
    editForm,
    displayedEditAgentPermissions,
    editingCustomPermissions,
    deletingUsername,
    rotatingUsername,
    approvalVisible,
    approvalSaving,
    approvalRequest,
    approvalMinimumExpiry,
    approvalExpiresAt,
    approvalProxyAddressIds,
    approvalReason,
    rejectingRequestId,
    rejectionVisible,
    rejectionRequest,
    rejectionReason,
    rotationVisible,
    rotationUser,
    rotationReason,
    retentionDays,
    retentionSaving,
    enabledProxyAddresses,
    isAuthenticated,
    isAgentHandoffSession,
    isAdmin,
    account,
    profile,
    additionalPermissions,
    keyState,
    pendingKeyRequest,
    profileExpired,
    canRotateOwnKey,
    filteredAccessRecords,
    filteredAdminUsers,
    adminMetrics,
    adminSectionOptions,
    editingProfileReadOnly,
    editingRootAdmin,
    editingHasEditableFields,
    editingPermissionsChanged,
    editingRequiresAuditReason,
    errorMessage,
    showError,
    resetPasswordForm,
    submitPasswordChange,
    saveMyProfile,
    submitAuth,
    performLogout,
    refreshAgentAuthorization,
    decideAgentAuthorization,
    leaveAgentAuthorization,
    refreshSelf,
    refreshAccessRecords,
    openKeyRequestDialog,
    submitKeyRequest,
    refreshKeyRequest,
    confirmRotateOwnKey,
    rotateOwnKey,
    refreshAdminUsers,
    refreshAuditEvents,
    selectAdminSection,
    filterAuditEvents,
    loadMoreAuditEvents,
    saveRetentionDays,
    openCreate,
    generateTemporaryPassword,
    submitCreate,
    openEdit,
    submitEdit,
    confirmRotateAdminKey,
    rotateAdminKey,
    openApproval,
    submitApproval,
    confirmRejectKeyRequest,
    performRejectKeyRequest,
    confirmDelete,
    performDelete,
    managedUsername,
    deleteBlockedReason,
    isRootAdmin,
    accountStatusLabel,
    canAdminRotateDirectly,
    keyRequestKindLabel,
    managedAgentPermissions,
    managedCustomPermissions,
    managedPermissionsTitle,
    managedHiddenPermissionCount,
    managedProxyAddressesTitle,
    hasEffectivePermission,
    parseAdditionalPermissions,
    formatExpiry,
    parseDate,
    isExpired,
    defaultExpiry,
    minimumFutureExpiry,
    restoreAgentAuthorization,
    persistAgentAuthorization,
    clearStoredAgentAuthorization,
    clearAgentAuthorizationLocation,
  }
}

export type AppController = ReturnType<typeof useAppController>

export const appControllerKey: InjectionKey<AppController> = Symbol('appController')

export function useAppControllerContext(): AppController {
  const controller = inject(appControllerKey)
  if (!controller) {
    throw new Error('App controller is unavailable')
  }
  return controller
}
