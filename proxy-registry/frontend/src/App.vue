<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import Avatar from 'primevue/avatar'
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import Column from 'primevue/column'
import ConfirmDialog from 'primevue/confirmdialog'
import DataTable from 'primevue/datatable'
import DatePicker from 'primevue/datepicker'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Password from 'primevue/password'
import ProgressSpinner from 'primevue/progressspinner'
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import Toast from 'primevue/toast'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import KeyRequestDialog from './components/KeyRequestDialog.vue'
import AuditEventPanel from './components/AuditEventPanel.vue'
import ProfileEditor from './components/ProfileEditor.vue'
import ProxyAddressCatalog from './components/ProxyAddressCatalog.vue'
import ProxyAddressChecklist from './components/ProxyAddressChecklist.vue'
import RequestMessage from './components/RequestMessage.vue'
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

</script>

<template>
  <Toast />
  <ConfirmDialog />

  <div v-if="booting" class="boot-screen" aria-live="polite">
    <div class="brand-mark"><i class="pi pi-shield" /></div>
    <ProgressSpinner stroke-width="4" />
    <p>正在安全连接账户服务…</p>
  </div>

  <main v-else-if="!isAuthenticated" class="auth-page">
    <section class="auth-intro" aria-labelledby="auth-title">
      <a class="brand" href="/" aria-label="PPAASS 首页">
        <span class="brand-mark"><i class="pi pi-shield" /></span>
        <span>PPAASS</span>
      </a>
      <div class="intro-copy">
        <p class="eyebrow">SECURE ACCESS</p>
        <h1 id="auth-title">你的代理身份，<br />由你掌控。</h1>
        <p>
          登录后管理账户密码，并查看代理有效期、权限与密钥状态。
        </p>
      </div>
      <div class="intro-security">
        <span><i class="pi pi-database" /> SQLite 加密存储</span>
        <span><i class="pi pi-desktop" /> Agent 安全领取凭据</span>
        <span><i class="pi pi-lock" /> HttpOnly 安全会话</span>
      </div>
    </section>

    <section
      class="auth-panel"
      aria-label="账户登录和注册"
    >
      <div class="auth-card">
        <div
          v-if="agentAuthorizationActive"
          class="agent-authorization-context"
          role="status"
        >
          <i class="pi pi-desktop" />
          <span>
            <strong>正在登录 Agent</strong>
            <small v-if="agentAuthorizationCode">
              设备授权短码：{{ agentAuthorizationCode }}
            </small>
            <small v-else>登录后输入 Agent 显示的设备授权短码。</small>
          </span>
        </div>
        <div class="auth-heading">
          <p class="eyebrow">{{ authMode === 'login' ? '欢迎回来' : '创建账户' }}</p>
          <h2>{{ authMode === 'login' ? '登录 PPAASS' : '注册普通用户' }}</h2>
          <p>
            {{
              authMode === 'login'
                ? '使用用户名和密码继续。'
                : '注册后可以提交密钥申请；管理员批准有效期后，即可通过 Agent 使用代理。'
            }}
          </p>
        </div>

        <div class="auth-tabs" role="tablist" aria-label="登录或注册">
          <button
            type="button"
            role="tab"
            :aria-selected="authMode === 'login'"
            :class="{ active: authMode === 'login' }"
            @click="authMode = 'login'"
          >
            登录
          </button>
          <button
            v-if="providers.localRegistration"
            type="button"
            role="tab"
            :aria-selected="authMode === 'register'"
            :class="{ active: authMode === 'register' }"
            @click="authMode = 'register'"
          >
            注册
          </button>
        </div>

        <form class="auth-form" @submit.prevent="submitAuth">
          <label for="auth-username">用户名</label>
          <InputText
            id="auth-username"
            v-model="authForm.username"
            autocomplete="username"
            placeholder="输入用户名"
            fluid
          />
          <div class="field-label-row">
            <label for="auth-password">密码</label>
            <small v-if="authMode === 'register'">
              至少 {{ PASSWORD_MIN_CHARACTERS }} 个字符
            </small>
          </div>
          <Password
            v-model="authForm.password"
            input-id="auth-password"
            :feedback="authMode === 'register'"
            :toggle-mask="true"
            :input-props="{
              autocomplete:
                authMode === 'register' ? 'new-password' : 'current-password',
              minlength:
                authMode === 'register' ? PASSWORD_MIN_CHARACTERS : undefined,
            }"
            placeholder="输入密码"
            fluid
          />
          <Button
            type="submit"
            :label="authMode === 'login' ? '登录' : '注册账户'"
            :icon="authMode === 'login' ? 'pi pi-sign-in' : 'pi pi-user-plus'"
            :loading="authLoading"
            fluid
          />
        </form>

        <p v-if="!providers.localRegistration && authMode === 'login'" class="registration-note">
          当前未开放自主注册，请联系管理员创建账号。
        </p>
      </div>
    </section>
  </main>

  <main
    v-else-if="agentAuthorizationActive"
    class="agent-authorization-page"
  >
    <section class="agent-authorization-card" aria-labelledby="agent-authorization-title">
      <a class="brand" href="/" aria-label="PPAASS 首页" @click.prevent="leaveAgentAuthorization">
        <span class="brand-mark"><i class="pi pi-shield" /></span>
        <span>PPAASS</span>
      </a>

      <template v-if="agentAuthorizationOutcome">
        <div
          class="agent-authorization-outcome"
          :class="agentAuthorizationOutcome"
          role="status"
        >
          <span class="outcome-icon">
            <i
              :class="
                agentAuthorizationOutcome === 'authorized'
                  ? 'pi pi-check'
                  : 'pi pi-times'
              "
            />
          </span>
          <h1>
            {{
              agentAuthorizationOutcome === 'authorized'
                ? 'Agent 登录已授权'
                : 'Agent 登录已拒绝'
            }}
          </h1>
          <p>
            {{
              agentAuthorizationOutcome === 'authorized'
                ? '你可以返回 Agent，它会自动领取账户配置和私钥。设备码只能使用一次。'
                : 'Agent 无法使用这次设备码登录。如需登录，请从 Agent 重新发起。'
            }}
          </p>
          <Button
            label="返回用户中心"
            icon="pi pi-arrow-left"
            @click="leaveAgentAuthorization"
          />
        </div>
      </template>

      <template v-else>
        <div class="agent-authorization-heading">
          <p class="eyebrow">AGENT SIGN-IN</p>
          <h1 id="agent-authorization-title">确认 Agent 登录</h1>
          <p>只有你正在操作自己的 Agent 时才批准。我们不会在此页面展示或传输私钥。</p>
        </div>

        <div class="agent-authorization-account">
        <Avatar
            :image="account?.avatarUrl || undefined"
            :label="
              account?.avatarUrl
                ? undefined
                : (account?.displayName || account?.username || 'U')
                    .slice(0, 1)
                    .toUpperCase()
            "
            shape="circle"
          />
          <span>
            <small>当前登录账户</small>
            <strong>{{ account?.displayName || account?.username }}</strong>
          </span>
          <Button
            label="切换账户"
            severity="secondary"
            text
            size="small"
            @click="performLogout"
          />
        </div>

        <form
          v-if="!agentAuthorization"
          class="agent-authorization-code-form"
          @submit.prevent="refreshAgentAuthorization"
        >
          <label for="agent-authorization-code">设备授权短码</label>
          <InputText
            id="agent-authorization-code"
            v-model="agentAuthorizationInput"
            autocomplete="one-time-code"
            autocapitalize="characters"
            placeholder="例如 ABCD-EFGH-JKLM"
            :disabled="agentAuthorizationLoading"
            fluid
          />
          <Button
            type="submit"
            label="继续"
            icon="pi pi-arrow-right"
            :loading="agentAuthorizationLoading"
            fluid
          />
        </form>

        <template v-else>
          <div class="agent-device-summary">
            <span class="summary-icon blue">
              <i
                :class="
                  agentAuthorization.platform === 'android'
                    ? 'pi pi-mobile'
                    : 'pi pi-desktop'
                "
              />
            </span>
            <span>
              <small>申请登录的设备</small>
              <strong>{{ agentAuthorization.clientName }}</strong>
              <small>
                {{
                  agentAuthorization.platform === 'android' ? 'Android' : 'Windows'
                }}
                · 授权码 {{ agentAuthorizationCode }}
              </small>
            </span>
          </div>

          <div class="agent-authorization-warning">
            <i class="pi pi-exclamation-triangle" />
            <span>
              <strong>请核对 Agent 上显示的短码</strong>
              <small>
                此请求将在
                {{ formatExpiry(String(agentAuthorization.expiresAt)) }}
                失效。批准后，Agent 可一次性领取你的代理配置和私钥。
              </small>
            </span>
          </div>

          <div class="agent-authorization-actions">
            <Button
              label="拒绝"
              icon="pi pi-times"
              severity="secondary"
              outlined
              :loading="agentAuthorizationDecisionLoading === 'deny'"
              :disabled="
                agentAuthorizationDecisionLoading !== null &&
                agentAuthorizationDecisionLoading !== 'deny'
              "
              @click="decideAgentAuthorization('deny')"
            />
            <Button
              label="批准登录"
              icon="pi pi-check"
              :loading="agentAuthorizationDecisionLoading === 'approve'"
              :disabled="
                agentAuthorizationDecisionLoading !== null &&
                agentAuthorizationDecisionLoading !== 'approve'
              "
              @click="decideAgentAuthorization('approve')"
            />
          </div>
        </template>

        <p
          v-if="agentAuthorizationError"
          class="agent-authorization-error"
          role="alert"
        >
          <i class="pi pi-exclamation-circle" />
          {{ agentAuthorizationError }}
        </p>
      </template>
    </section>
  </main>

  <div v-else class="app-shell">
    <header class="topbar">
      <a class="brand compact" href="/" aria-label="PPAASS 首页">
        <span class="brand-mark"><i class="pi pi-shield" /></span>
        <span>
          <strong>PPAASS</strong>
          <small>用户中心</small>
        </span>
      </a>

      <nav class="main-nav" aria-label="主导航">
        <button
          type="button"
          :class="{ active: activePage === 'account' }"
          @click="activePage = 'account'"
        >
          <i class="pi pi-id-card" /> 我的账户
        </button>
        <button
          v-if="isAdmin"
          type="button"
          :class="{ active: activePage === 'admin' }"
          @click="activePage = 'admin'"
        >
          <i class="pi pi-users" /> 用户管理
        </button>
      </nav>

      <div class="account-menu">
        <Avatar
          :image="account?.avatarUrl || undefined"
          :label="
            account?.avatarUrl
              ? undefined
              : (account?.displayName || account?.username || 'U')
                  .slice(0, 1)
                  .toUpperCase()
          "
          shape="circle"
        />
        <span class="account-menu-copy">
          <strong>{{ account?.displayName || account?.username }}</strong>
          <small>{{ account?.role === 'admin' ? '管理员' : '普通用户' }}</small>
        </span>
        <Button
          :class="[
            'topbar-logout-action',
            { 'agent-handoff-logout': isAgentHandoffSession },
          ]"
          v-tooltip.bottom="'退出登录'"
          icon="pi pi-sign-out"
          label="退出登录"
          severity="secondary"
          text
          rounded
          aria-label="退出登录"
          @click="performLogout"
        />
      </div>
    </header>

    <main class="workspace">
      <section v-if="activePage === 'account'" class="page-section">
        <div class="page-heading">
          <div>
            <p class="eyebrow">ACCOUNT OVERVIEW</p>
            <h1>我的代理身份</h1>
            <p>查看当前身份状态、连接权限和账户安全设置。</p>
          </div>
          <Tag
            :value="account?.status === 'active' ? '账号已启用' : '账号已停用'"
            :severity="account?.status === 'active' ? 'success' : 'danger'"
            rounded
          />
        </div>

        <div v-if="pageLoading" class="content-loading">
          <ProgressSpinner stroke-width="4" />
          <span>正在读取账户信息…</span>
        </div>

        <template v-else>
          <div v-if="profile" class="summary-grid">
            <article class="summary-card">
              <span class="summary-icon blue"><i class="pi pi-user" /></span>
              <div><small>代理用户名</small><strong>{{ profile.username }}</strong></div>
            </article>
            <article class="summary-card">
              <span class="summary-icon green"><i class="pi pi-calendar" /></span>
              <div>
                <small>有效期</small>
                <strong>{{
                  keyState === 'missing' ? '等待审批' : formatExpiry(profile.expiresAt)
                }}</strong>
              </div>
            </article>
            <article class="summary-card">
              <span class="summary-icon purple"><i class="pi pi-key" /></span>
              <div>
                <small>密钥状态</small>
                <strong>{{
                  keyState === 'active'
                    ? '有效'
                    : keyState === 'expired'
                      ? '已过期'
                      : keyState === 'disabled'
                        ? '已停用'
                        : '尚未生成'
                }}</strong>
              </div>
            </article>
            <article class="summary-card">
              <span class="summary-icon orange"><i class="pi pi-bolt" /></span>
              <div>
                <small>代理状态</small>
                <strong>{{
                  !profile.enabled
                    ? '已停用'
                    : keyState === 'active'
                      ? '可连接'
                      : keyState === 'disabled'
                        ? '已停用'
                        : '等待密钥'
                }}</strong>
              </div>
            </article>
          </div>

          <section v-if="profile" class="content-card permissions-card">
            <div class="card-heading">
              <div>
                <h2>我的权限</h2>
                <p>服务端会在每次连接和密钥操作时校验这些权限。</p>
              </div>
              <Tag
                :value="isAdmin ? '管理员全权限' : `${profile.permissions.length} 项`"
                severity="info"
                rounded
              />
            </div>
            <div class="permission-list">
              <div
                v-for="permission in basePermissionOptions"
                :key="permission.code"
                class="permission-item"
                :class="{ granted: hasEffectivePermission(permission.code) }"
              >
                <i
                  :class="
                    hasEffectivePermission(permission.code)
                      ? 'pi pi-check-circle'
                      : 'pi pi-minus-circle'
                  "
                />
                <span>
                  <strong>{{ permission.label }}</strong>
                  <small>{{ permission.description }}</small>
                </span>
                <Tag
                  :value="isAdmin ? '管理员固有' : hasEffectivePermission(permission.code) ? '已授权' : '未授权'"
                  :severity="
                    hasEffectivePermission(permission.code) ? 'success' : 'secondary'
                  "
                />
              </div>
            </div>
            <div class="agent-permissions-overview">
              <div class="additional-permissions-heading">
                <span>
                  <strong>Agent 管理权限</strong>
                  <small>决定 Agent 中可使用的本机管理功能。</small>
                </span>
              </div>
              <div class="permission-list">
                <div
                  v-for="permission in agentPermissionOptions"
                  :key="permission.code"
                  class="permission-item"
                  :class="{ granted: hasEffectivePermission(permission.code) }"
                >
                  <i
                    :class="
                      hasEffectivePermission(permission.code)
                        ? 'pi pi-check-circle'
                        : 'pi pi-minus-circle'
                    "
                  />
                  <span>
                    <strong>{{ permission.label }}</strong>
                    <small>{{ permission.description }}</small>
                  </span>
                  <Tag
                    :value="
                      isAdmin
                        ? '管理员固有'
                        : hasEffectivePermission(permission.code)
                          ? '已授权'
                          : '未授权'
                    "
                    :severity="
                      hasEffectivePermission(permission.code) ? 'success' : 'secondary'
                    "
                  />
                </div>
              </div>
            </div>
            <div class="additional-permissions">
              <div class="additional-permissions-heading">
                <span>
                  <strong>附加权限</strong>
                  <small>由管理员按业务需要分配，此处仅供查看。</small>
                </span>
                <Tag
                  :value="`${additionalPermissions.length} 项`"
                  severity="secondary"
                  rounded
                />
              </div>
              <div
                v-if="additionalPermissions.length"
                class="additional-permission-tags"
                aria-label="附加权限列表"
              >
                <Tag
                  v-for="permission in additionalPermissions"
                  :key="permission"
                  :value="permission"
                  severity="info"
                  rounded
                />
              </div>
              <div v-else class="additional-permissions-empty">
                <i class="pi pi-minus-circle" />
                <span>无</span>
              </div>
            </div>
          </section>

          <ProfileEditor
            v-if="account"
            :account="account"
            :saving="profileSaving"
            @save="saveMyProfile"
          />

          <section class="content-card account-security-card">
            <div class="card-heading">
              <div>
                <h2>登录安全</h2>
                <p>修改用于登录 Proxy Registry 和 Agent 的账户密码。</p>
              </div>
              <Tag value="密码保护" severity="success" rounded />
            </div>
            <form class="password-change-form" @submit.prevent="submitPasswordChange">
              <div class="password-fields">
                <div class="form-field">
                  <label for="account-current-password">当前密码</label>
                  <Password
                    v-model="passwordForm.currentPassword"
                    input-id="account-current-password"
                    :feedback="false"
                    :toggle-mask="true"
                    :input-props="{ autocomplete: 'current-password' }"
                    placeholder="输入当前密码"
                    fluid
                  />
                </div>
                <div class="form-field">
                  <label for="account-new-password">新密码</label>
                  <Password
                    v-model="passwordForm.newPassword"
                    input-id="account-new-password"
                    :feedback="true"
                    :toggle-mask="true"
                    :input-props="{
                      autocomplete: 'new-password',
                      minlength: PASSWORD_MIN_CHARACTERS,
                    }"
                    :placeholder="`至少 ${PASSWORD_MIN_CHARACTERS} 个字符`"
                    fluid
                  />
                </div>
                <div class="form-field">
                  <label for="account-confirm-password">确认新密码</label>
                  <Password
                    v-model="passwordForm.confirmPassword"
                    input-id="account-confirm-password"
                    :feedback="false"
                    :toggle-mask="true"
                    :input-props="{
                      autocomplete: 'new-password',
                      minlength: PASSWORD_MIN_CHARACTERS,
                    }"
                    placeholder="再次输入新密码"
                    fluid
                  />
                </div>
              </div>
              <div class="password-change-actions">
                <small>
                  修改后会退出全部 Web 会话，请使用新密码重新登录。
                </small>
                <Button
                  type="submit"
                  label="更新登录密码"
                  icon="pi pi-lock"
                  :loading="passwordSaving"
                />
              </div>
            </form>
          </section>

          <section
            v-if="keyState === 'active' && profile"
            class="rotate-banner"
            :class="{ unavailable: !canRotateOwnKey }"
          >
            <div class="rotate-icon"><i class="pi pi-refresh" /></div>
            <div>
              <h2>重新生成密钥对</h2>
              <p v-if="canRotateOwnKey">
                在有效期内可以直接更新。更新后，已授权 Agent 会自动领取新的连接凭据。
              </p>
              <p v-else>
                当前账户没有更新密钥的权限，或代理连接已被暂停。
              </p>
            </div>
            <Button
              label="生成新密钥"
              icon="pi pi-refresh"
              severity="danger"
              outlined
              :loading="keyRotationLoading"
              :disabled="!canRotateOwnKey"
              @click="confirmRotateOwnKey"
            />
          </section>

          <section
            v-else
            class="content-card key-request-card"
            :class="`state-${keyState}`"
          >
            <div class="key-request-icon">
              <i
                :class="
                  keyState !== 'disabled' && pendingKeyRequest?.status === 'pending'
                    ? 'pi pi-clock'
                    : pendingKeyRequest?.status === 'rejected'
                      ? 'pi pi-times-circle'
                    : keyState === 'expired'
                      ? 'pi pi-calendar-times'
                      : keyState === 'disabled'
                        ? 'pi pi-lock'
                      : keyState === 'active'
                        ? 'pi pi-exclamation-circle'
                        : 'pi pi-key'
                "
              />
            </div>
            <div class="key-request-copy">
              <p class="eyebrow">KEY ACCESS</p>
              <h2
                v-if="
                  keyState !== 'disabled' &&
                  pendingKeyRequest?.status === 'pending'
                "
              >
                {{
                  pendingKeyRequest.kind === 'rotate'
                    ? '密钥重生成申请正在等待审批'
                    : '首次密钥申请正在等待审批'
                }}
              </h2>
              <h2 v-else-if="pendingKeyRequest?.status === 'rejected'">
                密钥申请已被拒绝
              </h2>
              <h2 v-else-if="keyState === 'expired'">密钥已过期，请申请续期</h2>
              <h2 v-else-if="keyState === 'missing'">申请你的第一组代理密钥</h2>
              <h2 v-else-if="keyState === 'disabled'">代理连接已被暂停</h2>
              <h2 v-else>密钥信息暂不可用</h2>
              <p
                v-if="
                  keyState !== 'disabled' &&
                  pendingKeyRequest?.status === 'pending'
                "
              >
                申请于
                {{ pendingKeyRequest.createdAt ? formatExpiry(pendingKeyRequest.createdAt) : '刚刚' }}
                提交。管理员批准并设置新的有效期后，已授权 Agent 会领取新的连接凭据。
              </p>
              <p v-else-if="pendingKeyRequest?.status === 'rejected'">
                {{
                  pendingKeyRequest.reviewerLoginName
                    ? `管理员 ${pendingKeyRequest.reviewerLoginName} 已处理这项申请。`
                    : '管理员已处理这项申请。'
                }}
                你可以根据拒绝理由修改说明后重新提交。
              </p>
              <p v-else-if="keyState === 'expired'">
                旧密钥已失效，不能继续用于新连接。提交申请后，管理员将审核并设置新的有效期。
              </p>
              <p v-else-if="keyState === 'missing'">
                管理员批准并设置有效期后，系统才会生成密钥。管理员无法查看生成的 PEM 内容。
              </p>
              <p v-else-if="keyState === 'disabled'">
                停用状态下不能申请、查看或更新密钥，也不能建立新的代理连接。请联系管理员重新启用账户配置。
              </p>
              <p v-else>
                当前状态显示密钥有效，但未返回完整的密钥状态。请刷新后重试。
              </p>
              <RequestMessage
                v-if="
                  keyState !== 'disabled' &&
                  pendingKeyRequest?.status === 'pending'
                "
                :message="pendingKeyRequest.requestMessage"
                label="我的留言"
              />
              <RequestMessage
                v-if="pendingKeyRequest?.status === 'rejected'"
                :message="pendingKeyRequest.rejectionReason"
                label="拒绝理由"
                empty-text="管理员未填写拒绝理由。"
              />
              <div class="key-request-actions">
                <Button
                  v-if="
                    (keyState === 'missing' || keyState === 'expired') &&
                    pendingKeyRequest?.status !== 'pending'
                  "
                  :label="keyState === 'expired' ? '申请续期并生成新密钥' : '申请生成密钥'"
                  icon="pi pi-send"
                  :loading="keyRequestLoading"
                  :disabled="account?.status !== 'active' || profile?.enabled === false"
                  @click="openKeyRequestDialog"
                />
                <Button
                  label="刷新状态"
                  icon="pi pi-refresh"
                  severity="secondary"
                  outlined
                  :loading="keyRequestLoading"
                  @click="refreshKeyRequest"
                />
              </div>
            </div>
            <Tag
              :value="
                keyState !== 'disabled' && pendingKeyRequest?.status === 'pending'
                  ? '待管理员审批'
                  : pendingKeyRequest?.status === 'rejected'
                    ? '申请被拒绝'
                  : keyState === 'expired'
                    ? '已过期'
                    : keyState === 'disabled'
                      ? '已停用'
                    : keyState === 'missing'
                      ? '未生成'
                      : '信息不完整'
              "
              :severity="
                keyState !== 'disabled' && pendingKeyRequest?.status === 'pending'
                  ? 'info'
                  : pendingKeyRequest?.status === 'rejected'
                    ? 'danger'
                  : keyState === 'expired'
                    ? 'danger'
                    : keyState === 'disabled'
                      ? 'secondary'
                    : 'warn'
              "
              rounded
            />
          </section>

          <section class="content-card access-records-card">
            <div class="table-toolbar">
              <div>
                <h2>最近访问</h2>
                <p>
                  仅显示你本人最近 {{ accessRetentionDays }} 天内访问过的目标；相同地址合并并累计次数。
                </p>
              </div>
              <div class="table-actions">
                <span class="search-box">
                  <i class="pi pi-search" />
                  <InputText
                    v-model="accessHostFilter"
                    type="search"
                    placeholder="过滤主机名或 IP"
                    aria-label="过滤访问主机"
                  />
                </span>
                <Button
                  label="刷新"
                  icon="pi pi-refresh"
                  severity="secondary"
                  outlined
                  size="small"
                  :loading="accessRecordsLoading"
                  @click="refreshAccessRecords()"
                />
              </div>
            </div>
            <div class="access-privacy-note">
              <i class="pi pi-info-circle" />
              <span>
                对 HTTPS 连接，代理只能记录目标域名或 IP、最近使用的端口和传输方式，不会看到或记录具体页面 URL 与路径。
              </span>
            </div>
            <DataTable
              :value="filteredAccessRecords"
              :loading="accessRecordsLoading"
              :paginator="filteredAccessRecords.length > 10"
              :rows="10"
              v-model:first="accessRecordsFirst"
              data-key="targetHost"
              sort-field="accessedAt"
              :sort-order="-1"
              removable-sort
              scrollable
              table-style="min-width: 53rem"
            >
              <template #empty>
                <div class="table-empty access-empty">
                  <i class="pi pi-history" />
                  <span>
                    {{
                      accessHostFilter.trim()
                        ? '没有匹配的主机'
                        : '保留周期内暂无代理访问记录'
                    }}
                  </span>
                </div>
              </template>
              <Column
                field="accessedAt"
                header="最近访问"
                sortable
                style="min-width: 13rem"
              >
                <template #body="{ data }">
                  {{ formatExpiry(data.accessedAt) }}
                </template>
              </Column>
              <Column
                field="targetHost"
                header="目标域名 / IP"
                sortable
                style="min-width: 17rem"
              >
                <template #body="{ data }">
                  <code class="target-host">{{ data.targetHost }}</code>
                </template>
              </Column>
              <Column field="targetPort" header="端口" sortable style="min-width: 6rem">
                <template #body="{ data }">
                  <code>{{ data.targetPort }}</code>
                </template>
              </Column>
              <Column field="transport" header="传输" sortable style="min-width: 7rem">
                <template #body="{ data }">
                  <Tag
                    :value="data.transport.toUpperCase()"
                    :severity="data.transport === 'tcp' ? 'info' : 'warn'"
                    rounded
                  />
                </template>
              </Column>
              <Column field="accessCount" header="访问次数" sortable style="min-width: 7rem">
                <template #body="{ data }">
                  <strong>{{ data.accessCount }} 次</strong>
                </template>
              </Column>
            </DataTable>
          </section>
        </template>

      </section>

      <section v-else-if="activePage === 'admin' && isAdmin" class="page-section">
        <div class="page-heading admin-heading">
          <div>
            <p class="eyebrow">ADMIN CONSOLE</p>
            <h1>用户管理</h1>
            <p>管理账户、代理连接和有效期，并可触发密钥生成；连接凭据只由账户本人授权的 Agent 领取。</p>
          </div>
          <div class="admin-heading-actions">
            <Tag
              :value="`Registry：${session?.registryInstanceId || 'unknown'}`"
              severity="info"
              icon="pi pi-server"
              rounded
            />
            <Button label="新建普通用户" icon="pi pi-user-plus" @click="openCreate" />
          </div>
        </div>

        <div class="summary-grid admin-summary">
          <article class="summary-card">
            <span class="summary-icon blue"><i class="pi pi-users" /></span>
            <div><small>全部用户</small><strong>{{ adminMetrics.total }}</strong></div>
          </article>
          <article class="summary-card">
            <span class="summary-icon green"><i class="pi pi-check" /></span>
            <div>
              <small>启用账号</small>
              <strong>{{ adminMetrics.activeAccounts }}</strong>
            </div>
          </article>
          <article class="summary-card">
            <span class="summary-icon red"><i class="pi pi-ban" /></span>
            <div>
              <small>停用账号</small>
              <strong>{{ adminMetrics.disabledAccounts }}</strong>
            </div>
          </article>
          <article class="summary-card pending-metric">
            <span class="summary-icon orange"><i class="pi pi-bell" /></span>
            <div><small>待审批申请</small><strong>{{ adminMetrics.pending }}</strong></div>
          </article>
        </div>

        <nav class="admin-section-tabs" aria-label="管理员工作区" role="tablist">
          <button
            v-for="section in adminSectionOptions"
            :key="section.value"
            type="button"
            role="tab"
            :aria-selected="activeAdminSection === section.value"
            :class="{ active: activeAdminSection === section.value }"
            @click="selectAdminSection(section.value)"
          >
            <i :class="section.icon" />
            <span>{{ section.label }}</span>
            <small v-if="section.count !== null">{{ section.count }}</small>
          </button>
        </nav>

        <section
          v-if="activeAdminSection === 'approvals'"
          class="content-card approval-card"
        >
          <div class="approval-card-heading">
            <div class="approval-title">
              <span class="approval-title-icon"><i class="pi pi-key" /></span>
              <div>
                <h2>密钥申请审批</h2>
                <p>批准时只设置有效期并触发生成，连接凭据只能由用户授权的 Agent 领取。</p>
              </div>
            </div>
            <div class="approval-heading-actions">
              <Tag
                :value="`${adminKeyRequests.length} 项待处理`"
                :severity="adminKeyRequests.length ? 'warn' : 'success'"
                rounded
              />
              <Button
                v-tooltip.top="'刷新申请'"
                icon="pi pi-refresh"
                severity="secondary"
                text
                rounded
                aria-label="刷新密钥申请"
                :loading="keyRequestsLoading"
                @click="refreshAdminUsers"
              />
            </div>
          </div>

          <div v-if="keyRequestsLoading && !adminKeyRequests.length" class="approval-loading">
            <ProgressSpinner stroke-width="4" />
            <span>正在读取待审批申请…</span>
          </div>
          <div v-else-if="adminKeyRequests.length" class="approval-list">
            <article
              v-for="request in adminKeyRequests"
              :key="request.id"
              class="approval-item"
            >
              <Avatar
                :image="request.avatarUrl || undefined"
                :label="request.username.slice(0, 1).toUpperCase()"
                shape="circle"
              />
              <div class="approval-request-main">
                <div class="approval-user">
                  <strong>{{ request.displayName || request.username }}</strong>
                  <span>
                    {{ request.username }}
                    <template v-if="request.email"> · {{ request.email }}</template>
                  </span>
                </div>
                <RequestMessage
                  :message="request.requestMessage"
                  compact
                />
              </div>
              <Tag
                :value="keyRequestKindLabel(request)"
                :severity="request.kind === 'rotate' ? 'warn' : 'info'"
              />
              <span class="approval-time">
                <i class="pi pi-clock" />
                {{ request.createdAt ? formatExpiry(request.createdAt) : '刚刚提交' }}
              </span>
              <div class="approval-actions">
                <Button
                  label="拒绝"
                  icon="pi pi-times"
                  severity="danger"
                  outlined
                  size="small"
                  :loading="rejectingRequestId === request.id"
                  :disabled="approvalSaving"
                  @click="confirmRejectKeyRequest(request)"
                />
                <Button
                  label="批准并设置有效期"
                  icon="pi pi-check"
                  size="small"
                  :disabled="rejectingRequestId !== ''"
                  @click="openApproval(request)"
                />
              </div>
            </article>
          </div>
          <div v-else class="approval-empty">
            <span><i class="pi pi-check-circle" /></span>
            <div>
              <strong>没有待审批的密钥申请</strong>
              <small>首次申请和过期重生成申请会显示在这里。</small>
            </div>
          </div>
        </section>

        <ProxyAddressCatalog
          v-if="activeAdminSection === 'proxies'"
          :addresses="proxyAddresses"
          :loading="adminLoading"
          @changed="refreshAdminUsers"
        />

        <section
          v-if="activeAdminSection === 'audit'"
          class="content-card retention-card"
        >
          <div class="retention-copy">
            <span class="retention-icon"><i class="pi pi-history" /></span>
            <div>
              <h2>访问记录保留策略</h2>
              <p>
                设置所有普通用户可查看本人访问记录的天数。默认 7 天，管理员不能借此查看任何用户的具体记录。
              </p>
            </div>
          </div>
          <div class="retention-control">
            <label for="retention-days">全局保留天数</label>
            <div>
              <InputNumber
                v-model="retentionDays"
                input-id="retention-days"
                :min="1"
                :max="365"
                :step="1"
                show-buttons
                suffix=" 天"
                :use-grouping="false"
                aria-describedby="retention-help"
              />
              <Button
                label="保存设置"
                icon="pi pi-check"
                :loading="retentionSaving"
                @click="saveRetentionDays"
              />
            </div>
            <small id="retention-help">允许范围 1–365 天；超出保留期的记录由服务端清理。</small>
          </div>
        </section>

        <AuditEventPanel
          v-if="activeAdminSection === 'audit'"
          :action="auditAction"
          :events="adminAuditEvents"
          :has-more="auditEventsHasMore"
          :loading="auditEventsLoading"
          :loading-more="auditEventsLoadingMore"
          :search="auditSearch"
          @filter="filterAuditEvents"
          @load-more="loadMoreAuditEvents"
          @refresh="refreshAuditEvents"
        />

        <section
          v-if="activeAdminSection === 'users'"
          class="content-card users-card"
        >
          <div class="table-toolbar">
            <div>
              <h2>用户列表</h2>
              <p>历史数据库用户没有 Web 登录账号；如需登录，请由管理员新建正式账号。</p>
            </div>
            <div class="table-actions">
              <span class="search-box">
                <i class="pi pi-search" />
                <InputText
                  v-model="adminSearch"
                  placeholder="搜索用户名或邮箱"
                  aria-label="搜索用户"
                />
              </span>
              <Button
                v-tooltip.top="'刷新'"
                icon="pi pi-refresh"
                severity="secondary"
                outlined
                aria-label="刷新用户列表"
                :loading="adminLoading"
                @click="refreshAdminUsers"
              />
            </div>
          </div>

          <DataTable
            :value="filteredAdminUsers"
            :loading="adminLoading"
            data-key="profile.username"
            paginator
            :rows="10"
            :rows-per-page-options="[10, 25, 50]"
            scrollable
            table-style="min-width: 72rem"
            paginator-template="FirstPageLink PrevPageLink PageLinks NextPageLink LastPageLink RowsPerPageDropdown"
            current-page-report-template="第 {first}–{last} 条，共 {totalRecords} 条"
          >
            <template #empty>
              <div class="table-empty">
                <i class="pi pi-users" />
                <span>{{ adminSearch ? '没有匹配的用户' : '还没有用户' }}</span>
              </div>
            </template>
            <Column header="用户" frozen style="min-width: 11.5rem">
              <template #body="{ data }">
                <div class="user-cell">
                  <Avatar :label="managedUsername(data).slice(0, 1).toUpperCase()" shape="circle" />
                  <span>
                    <strong :title="managedUsername(data)">
                      {{ managedUsername(data) }}
                    </strong>
                  </span>
                </div>
              </template>
            </Column>
            <Column header="角色" style="min-width: 7rem">
              <template #body="{ data }">
                <div class="tag-stack">
                  <Tag
                    :value="
                      isRootAdmin(data)
                        ? '根管理员'
                        : data.account?.role === 'admin'
                          ? '管理员'
                          : '普通用户'
                    "
                    :severity="data.account?.role === 'admin' ? 'info' : 'secondary'"
                  />
                </div>
              </template>
            </Column>
            <Column header="状态" style="min-width: 5rem">
              <template #body="{ data }">
                <span
                  class="account-status-indicator"
                  :class="{ active: data.account?.status === 'active' }"
                  :title="accountStatusLabel(data)"
                  :aria-label="accountStatusLabel(data)"
                  role="img"
                />
              </template>
            </Column>
            <Column header="密钥有效期" style="min-width: 9.5rem">
              <template #body="{ data }">
                <span
                  class="key-expiry-value"
                  :class="{ expired: data.keyState === 'expired' }"
                  :title="data.keyState === 'expired' ? '密钥已过期' : undefined"
                >
                  {{ data.profile ? formatExpiry(data.profile.expiresAt) : '—' }}
                </span>
              </template>
            </Column>
            <Column header="Proxy 地址" style="min-width: 10rem">
              <template #body="{ data }">
                <div
                  v-if="data.proxyAddresses.length"
                  class="permission-tags user-list-tag-summary"
                  :title="managedProxyAddressesTitle(data)"
                  :aria-label="managedProxyAddressesTitle(data)"
                >
                  <Tag
                    v-for="address in data.proxyAddresses.slice(0, 1)"
                    :key="address.id"
                    :value="address.label"
                    severity="info"
                    class="user-list-tag-summary-primary"
                  />
                  <Tag
                    v-if="data.proxyAddresses.length > 1"
                    :value="`+${data.proxyAddresses.length - 1}`"
                    severity="secondary"
                    rounded
                    class="user-list-tag-summary-count"
                  />
                </div>
                <Tag v-else value="未分配" severity="danger" />
              </template>
            </Column>
            <Column header="Agent 权限" style="min-width: 18rem">
              <template #body="{ data }">
                <div
                  v-if="data.account?.role === 'admin'"
                  class="permission-tags user-permission-tags user-list-tag-summary"
                  :title="managedPermissionsTitle(data)"
                  :aria-label="managedPermissionsTitle(data)"
                >
                  <Tag value="Agent 全权限" severity="info" />
                </div>
                <div
                  v-else-if="data.profile"
                  class="permission-tags user-permission-tags user-list-tag-summary"
                  :title="managedPermissionsTitle(data)"
                  :aria-label="managedPermissionsTitle(data)"
                >
                  <Tag
                    v-for="permission in managedAgentPermissions(data).slice(0, 2)"
                    :key="permission.code"
                    :value="permission.label"
                    severity="secondary"
                    class="user-list-tag-summary-primary"
                  />
                  <Tag
                    v-if="managedHiddenPermissionCount(data)"
                    :value="`+${managedHiddenPermissionCount(data)} 项`"
                    severity="secondary"
                    rounded
                    class="user-list-tag-summary-count"
                  />
                  <Tag
                    v-if="
                      !managedAgentPermissions(data).length &&
                      !managedCustomPermissions(data).length
                    "
                    value="Agent 基础功能"
                    severity="secondary"
                  />
                </div>
                <span v-else>—</span>
              </template>
            </Column>
            <Column
              header="操作"
              frozen
              align-frozen="right"
              style="min-width: 8.5rem"
            >
              <template #body="{ data }">
                <div class="row-actions">
                  <Button
                    v-if="canAdminRotateDirectly(data)"
                    v-tooltip.top="'重新生成有效期内的密钥'"
                    icon="pi pi-refresh"
                    severity="warn"
                    text
                    rounded
                    aria-label="重新生成用户密钥"
                    :loading="rotatingUsername === managedUsername(data)"
                    @click="confirmRotateAdminKey(data)"
                  />
                  <Button
                    v-tooltip.top="data.profile?.origin === 'legacy' ? '查看兼容配置' : '编辑'"
                    :icon="data.profile?.origin === 'legacy' ? 'pi pi-eye' : 'pi pi-pencil'"
                    severity="secondary"
                    text
                    rounded
                    aria-label="编辑用户"
                    @click="openEdit(data)"
                  />
                  <span
                    class="row-action-tooltip"
                    v-tooltip.top="deleteBlockedReason(data) || '删除用户'"
                  >
                    <Button
                      icon="pi pi-trash"
                      severity="danger"
                      text
                      rounded
                      :aria-label="
                        deleteBlockedReason(data) || '删除用户'
                      "
                      :loading="deletingUsername === managedUsername(data)"
                      :disabled="Boolean(deleteBlockedReason(data))"
                      @click="confirmDelete(data)"
                    />
                  </span>
                </div>
              </template>
            </Column>
          </DataTable>
        </section>
      </section>
    </main>
  </div>

  <Dialog
    v-model:visible="createVisible"
    modal
    header="新建普通用户"
    class="form-dialog"
    :style="{ width: 'min(92vw, 650px)' }"
  >
    <p class="dialog-lead">
      保存后服务端会生成 RSA 密钥对并加密存储，连接凭据只能由该用户授权的 Agent 领取。
    </p>
    <form id="create-user-form" class="dialog-form" @submit.prevent="submitCreate">
      <div class="form-field">
        <label for="create-username">用户名</label>
        <InputText
          id="create-username"
          v-model="createForm.username"
          autocomplete="off"
          placeholder="例如 alice"
          fluid
        />
      </div>
      <div class="form-field">
        <div class="field-label-row">
          <label for="create-password">初始密码</label>
          <Button
            label="生成强密码"
            icon="pi pi-sparkles"
            severity="secondary"
            text
            size="small"
            type="button"
            @click="generateTemporaryPassword"
          />
        </div>
        <Password
          v-model="createForm.password"
          input-id="create-password"
          :toggle-mask="true"
          :feedback="true"
          :input-props="{
            autocomplete: 'new-password',
            minlength: PASSWORD_MIN_CHARACTERS,
          }"
          :placeholder="`至少 ${PASSWORD_MIN_CHARACTERS} 个字符`"
          fluid
        />
      </div>
      <div class="form-field">
        <label for="create-expiry">代理有效期</label>
        <DatePicker
          id="create-expiry"
          v-model="createForm.expiresAt"
          :min-date="createMinimumExpiry"
          :manual-input="false"
          show-time
          hour-format="24"
          show-icon
          fluid
        />
        <small>必填，且必须晚于当前时间。</small>
      </div>
      <ProxyAddressChecklist
        v-model="createForm.proxyAddressIds"
        :addresses="enabledProxyAddresses"
        input-prefix="create-proxy"
        description="至少选择一个；地址只会下发给 Agent，不在 Agent 界面显示。"
        empty-message="请先在 Proxy 地址目录中新增并启用地址。"
      />
      <section class="fixed-capabilities" aria-labelledby="create-capabilities-title">
        <div class="fixed-capabilities-heading">
          <span class="summary-icon blue"><i class="pi pi-shield" /></span>
          <div>
            <strong id="create-capabilities-title">普通用户基础能力</strong>
            <small>以下能力会自动授予，是普通用户的固定能力，无需单独配置。</small>
          </div>
        </div>
        <ul>
          <li
            v-for="permission in basePermissionOptions"
            :key="permission.code"
          >
            <i class="pi pi-check-circle" />
            <span>
              <strong>{{ permission.label }}</strong>
              <small>{{ permission.description }}</small>
            </span>
          </li>
        </ul>
      </section>
      <section
        class="agent-permission-picker"
        aria-labelledby="create-agent-permissions-title"
      >
        <div class="permission-picker-heading">
          <div>
            <strong id="create-agent-permissions-title">Agent 管理权限</strong>
            <small>按需分配；未勾选时 Agent 隐藏对应功能，并使用内置默认值。</small>
          </div>
        </div>
        <div class="permission-picker-grid">
          <label
            v-for="permission in agentPermissionOptions"
            :key="permission.code"
            class="permission-choice"
            :class="{ selected: createForm.agentPermissions.includes(permission.code) }"
            :for="`create-${permission.code}`"
          >
            <Checkbox
              v-model="createForm.agentPermissions"
              :input-id="`create-${permission.code}`"
              :value="permission.code"
            />
            <span>
              <strong>{{ permission.label }}</strong>
              <small>{{ permission.description }}</small>
            </span>
          </label>
        </div>
      </section>
      <div class="form-field">
        <label for="create-additional-permissions">自定义权限</label>
        <Textarea
          id="create-additional-permissions"
          v-model="createForm.additionalPermissions"
          rows="3"
          placeholder="例如 report.read, tunnel.priority"
          aria-describedby="additional-permissions-help"
          fluid
        />
        <small id="additional-permissions-help">
          可选。使用逗号、空格或换行分隔 permission code；基础能力和上方三项 Agent 权限会自动排除。
        </small>
      </div>
      <div class="form-field">
        <label for="create-audit-reason">创建和权限分配原因</label>
        <Textarea
          id="create-audit-reason"
          v-model="createForm.auditReason"
          rows="3"
          maxlength="500"
          placeholder="说明为什么创建该用户并分配这些权限"
          fluid
        />
        <small>{{ Array.from(createForm.auditReason).length }} / 500，必填。</small>
      </div>
    </form>
    <template #footer>
      <Button label="取消" severity="secondary" text @click="createVisible = false" />
      <Button
        type="submit"
        form="create-user-form"
        label="创建并生成密钥"
        icon="pi pi-key"
        :loading="createSaving"
      />
    </template>
  </Dialog>

  <Dialog
    v-model:visible="editVisible"
    modal
    class="form-dialog user-editor-dialog"
    :style="{ width: 'min(94vw, 760px)' }"
  >
    <template #header>
      <div class="user-editor-header">
        <span class="user-editor-header-icon">
          <i class="pi pi-user-edit" />
        </span>
        <div class="user-editor-header-copy">
          <small>用户配置</small>
          <h2 :title="editingUser ? managedUsername(editingUser) : ''">
            {{ editingUser ? managedUsername(editingUser) : '' }}
          </h2>
        </div>
        <Tag
          v-if="editingUser?.account"
          :value="
            editingRootAdmin
              ? '根管理员'
              : editForm.role === 'admin'
                ? '管理员'
                : '普通用户'
          "
          :severity="editForm.role === 'admin' ? 'info' : 'secondary'"
          rounded
        />
      </div>
    </template>
    <form
      id="edit-user-form"
      class="dialog-form user-editor-form"
      @submit.prevent="submitEdit"
    >
      <section v-if="editingUser?.account" class="user-editor-section">
        <div class="user-editor-section-heading">
          <span><i class="pi pi-id-card" /></span>
          <div>
            <strong>账号与登录</strong>
            <small>设置用户在 Proxy Registry 和 Agent 中的账号身份。</small>
          </div>
        </div>
        <div v-if="!editingRootAdmin" class="form-row user-editor-account-grid">
          <div class="form-field">
            <label for="edit-role">账户角色</label>
            <Select
              id="edit-role"
              v-model="editForm.role"
              :options="roleOptions"
              option-label="label"
              option-value="value"
              fluid
            />
          </div>
          <div class="form-field">
            <label for="edit-status">登录状态</label>
            <Select
              id="edit-status"
              v-model="editForm.status"
              :options="statusOptions"
              option-label="label"
              option-value="value"
              fluid
            />
          </div>
          <small class="user-editor-account-help">
            停用账号后，该用户将无法登录 Proxy Registry 和 Agent；不会自动改变代理连接权限。
          </small>
        </div>
        <div v-else class="protected-account-summary">
          <div>
            <span>账户角色</span>
            <strong><i class="pi pi-shield" /> 管理员</strong>
          </div>
          <div>
            <span>登录状态</span>
            <strong><i class="pi pi-check-circle" /> 已启用</strong>
          </div>
        </div>
        <div v-if="editingRootAdmin" class="root-admin-notice">
          <i class="pi pi-lock" />
          <span>
            <strong>根管理员账号受保护</strong>
            <small>admin 不能停用、降级或删除，代理连接设置仍可正常调整。</small>
          </span>
        </div>
      </section>
      <div v-if="!editingUser?.account" class="legacy-notice">
        <i class="pi pi-info-circle" />
        <span>
          该 legacy 配置没有 Web 登录账号；这里只能允许或暂停代理连接，有效期、权限和密钥保持只读。
        </span>
      </div>
      <template v-if="editingUser?.profile">
        <section class="user-editor-section proxy-access-section">
          <div class="user-editor-section-heading">
            <span><i class="pi pi-clock" /></span>
            <div>
              <strong>代理连接</strong>
              <small>控制流量访问、有效期以及 Agent 可以连接的 Proxy 节点。</small>
            </div>
          </div>
          <div
            v-if="editingProfileReadOnly && editingUser.profile.origin !== 'legacy'"
            class="approval-required-notice"
          >
            <i class="pi pi-lock" />
            <span>
              <strong>密钥生命周期已锁定</strong>
              <small>
                缺失或过期密钥不能在编辑页直接恢复有效期。用户提交申请后，请在待审批列表中设置新的未来有效期。
              </small>
            </span>
          </div>
          <div class="user-editor-runtime-grid">
            <div class="form-field">
              <label for="edit-expiry">代理有效期</label>
              <DatePicker
                id="edit-expiry"
                v-model="editForm.expiresAt"
                :disabled="editingProfileReadOnly"
                show-time
                hour-format="24"
                show-icon
                fluid
              />
              <small v-if="editingProfileReadOnly">
                只读状态，不能从这里延长或恢复。
              </small>
              <small v-else>清空表示永久有效。</small>
            </div>
            <div class="form-field">
              <span class="form-field-label">流量权限</span>
              <label
                class="proxy-toggle-card"
                :class="{ selected: editForm.enabled }"
                for="edit-enabled"
              >
                <Checkbox
                  v-model="editForm.enabled"
                  input-id="edit-enabled"
                  binary
                />
                <span>
                  <strong>允许代理连接</strong>
                </span>
                <Tag
                  :value="editForm.enabled ? '已允许' : '已暂停'"
                  :severity="editForm.enabled ? 'success' : 'secondary'"
                  rounded
                />
              </label>
              <small>关闭后停止 Agent 代理，Web 账户仍可登录。</small>
            </div>
          </div>
          <ProxyAddressChecklist
            v-if="editingUser.account"
            v-model="editForm.proxyAddressIds"
            :addresses="enabledProxyAddresses"
            input-prefix="edit-proxy"
            :description="
              editForm.status === 'disabled' && !editingUser.proxyAddresses.length
                ? '账号停用时可以暂不分配；重新启用前至少选择一个。'
                : '至少保留一个；保存后 Agent 会在定期同步时应用。'
            "
            :required="
              editForm.status !== 'disabled' || editingUser.proxyAddresses.length > 0
            "
            empty-message="请先在 Proxy 地址目录中新增并启用地址。"
            compact
          />
        </section>
      </template>
      <section
        v-if="
          editingUser?.account &&
          (editingUser.profile || editForm.role === 'admin')
        "
        class="user-editor-section user-editor-permission-section"
        aria-labelledby="edit-agent-permissions-title"
      >
          <div class="user-editor-section-heading">
            <span><i class="pi pi-shield" /></span>
            <div>
              <strong id="edit-agent-permissions-title">Agent 权限</strong>
              <small v-if="editForm.role === 'admin'">
                管理员自动拥有以下全部权限，不能单独取消。
              </small>
              <small v-else>基础代理能力固定授予，管理功能可按需开启。</small>
            </div>
          </div>
          <div class="base-capability-strip" aria-label="固定基础能力">
            <span v-for="permission in basePermissionOptions" :key="permission.code">
              <i class="pi pi-check-circle" />
              {{ permission.label }}
            </span>
          </div>
          <div class="permission-picker-grid">
            <label
              v-for="permission in agentPermissionOptions"
              :key="permission.code"
              class="permission-choice"
              :class="{
                selected: displayedEditAgentPermissions.includes(permission.code),
              }"
              :for="`edit-${permission.code}`"
            >
              <Checkbox
                v-model="displayedEditAgentPermissions"
                :input-id="`edit-${permission.code}`"
                :value="permission.code"
                :disabled="
                  editForm.role === 'admin' ||
                  editingUser.profile?.origin === 'legacy'
                "
              />
              <span>
                <strong>{{ permission.label }}</strong>
                <small>{{ permission.description }}</small>
              </span>
            </label>
          </div>
          <div
            v-if="editingCustomPermissions.length"
            class="preserved-permissions"
          >
            <span>
              <strong>保留的自定义权限</strong>
              <small>保存时会原样保留，不会因勾选 Agent 权限而丢失。</small>
            </span>
            <div class="additional-permission-tags">
              <Tag
                v-for="permission in editingCustomPermissions"
                :key="permission"
                :value="permission"
                severity="secondary"
                rounded
              />
            </div>
          </div>
      </section>
      <section v-if="editingRequiresAuditReason" class="user-editor-section audit-reason-section">
        <div class="user-editor-section-heading">
          <span><i class="pi pi-file-edit" /></span>
          <div>
            <strong>本次修改原因</strong>
            <small>管理员敏感操作会写入仅管理员可见的审计记录。</small>
          </div>
        </div>
        <div class="form-field">
          <label for="edit-audit-reason">操作原因</label>
          <Textarea
            id="edit-audit-reason"
            v-model="editForm.auditReason"
            rows="3"
            maxlength="500"
            placeholder="说明为什么需要修改该用户配置"
            fluid
          />
          <small>{{ Array.from(editForm.auditReason).length }} / 500，敏感变更必填。</small>
        </div>
      </section>
    </form>
    <template #footer>
      <Button
        :label="editingHasEditableFields ? '取消' : '关闭'"
        severity="secondary"
        text
        @click="editVisible = false"
      />
      <Button
        v-if="editingHasEditableFields"
        type="submit"
        form="edit-user-form"
        label="保存更改"
        icon="pi pi-check"
        :loading="editSaving"
      />
    </template>
  </Dialog>

  <KeyRequestDialog
    v-model:visible="keyRequestDialogVisible"
    :loading="keyRequestLoading"
    :renewal="keyState === 'expired'"
    @submit="submitKeyRequest"
  />

  <Dialog
    v-model:visible="approvalVisible"
    modal
    header="批准密钥申请"
    class="form-dialog approval-dialog"
    :style="{ width: 'min(92vw, 560px)' }"
  >
    <div v-if="approvalRequest" class="approval-dialog-user">
      <Avatar
        :image="approvalRequest.avatarUrl || undefined"
        :label="approvalRequest.username.slice(0, 1).toUpperCase()"
        shape="circle"
      />
      <div>
        <strong>{{ approvalRequest.displayName || approvalRequest.username }}</strong>
        <span>{{ approvalRequest.username }}</span>
      </div>
      <Tag
        :value="keyRequestKindLabel(approvalRequest)"
        :severity="approvalRequest.kind === 'rotate' ? 'warn' : 'info'"
      />
    </div>
    <RequestMessage
      v-if="approvalRequest"
      class="approval-dialog-message"
      :message="approvalRequest.requestMessage"
      label="用户留言"
    />
    <div class="privacy-notice">
      <i class="pi pi-eye-slash" />
      <span>
        批准后服务端会生成新密钥，连接凭据只能由该用户授权的 Agent 领取。
      </span>
    </div>
    <ProxyAddressChecklist
      v-model="approvalProxyAddressIds"
      :addresses="enabledProxyAddresses"
      input-prefix="approval-proxy"
      title="分配 Proxy 地址"
      description="至少选择一个；轮换申请会预选账号当前的地址。"
      empty-message="请先关闭对话框并新增可用地址。"
    />
    <div class="form-field approval-expiry-field">
      <label for="approval-expiry">新密钥过期时间</label>
      <DatePicker
        id="approval-expiry"
        v-model="approvalExpiresAt"
        :min-date="approvalMinimumExpiry"
        :manual-input="false"
        show-time
        hour-format="24"
        show-icon
        fluid
      />
      <small>必填，且必须晚于当前时间。批准后用户才能查看和使用新密钥。</small>
    </div>
    <div class="form-field">
      <label for="approval-reason">批准原因</label>
      <Textarea
        id="approval-reason"
        v-model="approvalReason"
        rows="3"
        maxlength="500"
        placeholder="说明批准本次密钥申请的原因"
        fluid
      />
      <small>{{ Array.from(approvalReason).length }} / 500，必填，仅管理员可见。</small>
    </div>
    <template #footer>
      <Button
        label="取消"
        severity="secondary"
        text
        :disabled="approvalSaving"
        @click="approvalVisible = false"
      />
      <Button
        label="批准并生成密钥"
        icon="pi pi-check"
        :loading="approvalSaving"
        :disabled="!approvalProxyAddressIds.length"
        @click="submitApproval"
      />
    </template>
  </Dialog>

  <Dialog
    v-model:visible="rejectionVisible"
    modal
    header="拒绝密钥申请"
    class="form-dialog rejection-dialog"
    :style="{ width: 'min(92vw, 520px)' }"
    :closable="!rejectingRequestId"
  >
    <div v-if="rejectionRequest" class="dialog-form">
      <p class="dialog-lead">
        拒绝“{{ rejectionRequest.username }}”的申请后，用户可以看到下面的理由并重新提交。
      </p>
      <div class="form-field">
        <label for="key-request-rejection-reason">拒绝理由（用户可见）</label>
        <Textarea
          id="key-request-rejection-reason"
          v-model="rejectionReason"
          rows="5"
          maxlength="500"
          placeholder="例如：请补充业务用途和需要的有效期后重新申请。"
          :disabled="Boolean(rejectingRequestId)"
          fluid
        />
        <small>{{ Array.from(rejectionReason).length }} / 500，必填。</small>
      </div>
    </div>
    <template #footer>
      <Button
        label="取消"
        severity="secondary"
        text
        :disabled="Boolean(rejectingRequestId)"
        @click="rejectionVisible = false"
      />
      <Button
        label="确认拒绝"
        icon="pi pi-times"
        severity="danger"
        :loading="Boolean(rejectingRequestId)"
        @click="performRejectKeyRequest"
      />
    </template>
  </Dialog>

  <Dialog
    v-model:visible="ownRotationVisible"
    modal
    header="重新生成自己的密钥"
    class="form-dialog"
    :style="{ width: 'min(92vw, 520px)' }"
    :closable="!keyRotationLoading"
  >
    <div class="dialog-form">
      <p class="dialog-lead">
        旧连接凭据会立即失效。管理员操作将写入审计记录，请填写原因。
      </p>
      <div class="form-field">
        <label for="own-rotation-reason">重生成原因</label>
        <Textarea
          id="own-rotation-reason"
          v-model="ownRotationReason"
          rows="4"
          maxlength="500"
          placeholder="说明为什么需要重新生成自己的密钥"
          :disabled="keyRotationLoading"
          fluid
        />
        <small>{{ Array.from(ownRotationReason).length }} / 500，必填。</small>
      </div>
    </div>
    <template #footer>
      <Button
        label="取消"
        severity="secondary"
        text
        :disabled="keyRotationLoading"
        @click="ownRotationVisible = false"
      />
      <Button
        label="生成新密钥"
        icon="pi pi-refresh"
        severity="danger"
        :loading="keyRotationLoading"
        :disabled="!ownRotationReason.trim()"
        @click="rotateOwnKey(ownRotationReason)"
      />
    </template>
  </Dialog>

  <Dialog
    v-model:visible="rotationVisible"
    modal
    header="重新生成用户密钥"
    class="form-dialog"
    :style="{ width: 'min(92vw, 520px)' }"
    :closable="!rotatingUsername"
  >
    <div v-if="rotationUser" class="dialog-form">
      <p class="dialog-lead">
        将为“{{ managedUsername(rotationUser) }}”生成新密钥，旧私钥会立即失效。
      </p>
      <div class="form-field">
        <label for="rotation-reason">重生成原因</label>
        <Textarea
          id="rotation-reason"
          v-model="rotationReason"
          rows="4"
          maxlength="500"
          placeholder="说明为什么需要重新生成该用户的密钥"
          :disabled="Boolean(rotatingUsername)"
          fluid
        />
        <small>{{ Array.from(rotationReason).length }} / 500，必填。</small>
      </div>
    </div>
    <template #footer>
      <Button
        label="取消"
        severity="secondary"
        text
        :disabled="Boolean(rotatingUsername)"
        @click="rotationVisible = false"
      />
      <Button
        label="生成新密钥"
        icon="pi pi-refresh"
        severity="danger"
        :loading="Boolean(rotatingUsername)"
        @click="rotationUser && rotateAdminKey(rotationUser)"
      />
    </template>
  </Dialog>

</template>
