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
import {
  ApiError,
  approveAgentDeviceAuthorization,
  approveKeyRequest,
  clearClientSession,
  createManagedUser,
  deleteManagedUser,
  denyAgentDeviceAuthorization,
  getAccessLogSettings,
  getMe,
  getMyKeyRequest,
  getMyPrivateKey,
  getProviders,
  getSession,
  inspectAgentDeviceAuthorization,
  listPendingKeyRequests,
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
  type AccessRecord,
  type AgentDeviceAuthorizationInspection,
  type AccountRole,
  type AccountStatus,
  type KeyMaterial,
  type KeyRequest,
  type ManagedUser,
  type ProviderAvailability,
  type SelfView,
  type SessionState,
} from './api'

type AuthMode = 'login' | 'register'
type AppPage = 'account' | 'admin'

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

const permissionOptions: PermissionOption[] = [
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
    label: '查看私钥',
    description: '允许用户读取自己的私钥',
  },
  {
    code: 'key.rotate',
    label: '更新密钥',
    description: '允许用户重新生成密钥对',
  },
]

const basePermissionCodes = new Set(
  permissionOptions.map((permission) => permission.code),
)

const roleOptions = [
  { label: '普通用户', value: 'user' },
  { label: '管理员', value: 'admin' },
]

const statusOptions = [
  { label: '正常', value: 'active' },
  { label: '已停用', value: 'disabled' },
]

const toast = useToast()
const confirm = useConfirm()
const currentTime = ref(Date.now())
let clockTimer: ReturnType<typeof setInterval> | undefined

const booting = ref(true)
const initialAuthMode = requestedAuthMode()
const authMode = ref<AuthMode>(initialAuthMode)
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

const ownKey = ref<KeyMaterial | null>(null)
const ownKeyVisible = ref(false)
const ownKeyLoading = ref(false)
const keyRequestLoading = ref(false)
let ownKeyTimer: ReturnType<typeof setTimeout> | undefined
const accessRecords = ref<AccessRecord[]>([])
const accessRecordsLoading = ref(false)
const accessRetentionDays = ref(7)
const accessHostFilter = ref('')
const accessRecordsFirst = ref(0)

const adminUsers = ref<ManagedUser[]>([])
const adminKeyRequests = ref<KeyRequest[]>([])
const adminLoading = ref(false)
const keyRequestsLoading = ref(false)
const adminSearch = ref('')
const createVisible = ref(false)
const createSaving = ref(false)
const createMinimumExpiry = ref(minimumFutureExpiry())
const createForm = reactive({
  username: '',
  password: '',
  expiresAt: defaultExpiry(),
  additionalPermissions: '',
})
const editVisible = ref(false)
const editSaving = ref(false)
const editingUser = ref<ManagedUser | null>(null)
const editForm = reactive({
  role: 'user' as AccountRole,
  status: 'active' as AccountStatus,
  enabled: true,
  expiresAt: null as Date | null,
})
const deletingUsername = ref('')
const rotatingUsername = ref('')
const approvalVisible = ref(false)
const approvalSaving = ref(false)
const approvalRequest = ref<KeyRequest | null>(null)
const approvalMinimumExpiry = ref(minimumFutureExpiry())
const approvalExpiresAt = ref<Date | null>(defaultExpiry())
const rejectingRequestId = ref('')
const retentionDays = ref<number | null>(7)
const retentionSaving = ref(false)

const isAuthenticated = computed(
  () => session.value?.authenticated === true && session.value.account !== null,
)
const isAdmin = computed(() => session.value?.account?.role === 'admin')
const account = computed(() => self.value?.account ?? session.value?.account ?? null)
const profile = computed(() => self.value?.profile ?? null)
const additionalPermissions = computed(() =>
  [
    ...new Set(
      (profile.value?.permissions ?? []).filter(
        (permission) => !basePermissionCodes.has(permission),
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
const hasActiveVisibleKey = computed(
  () => keyState.value === 'active' && Boolean(profile.value?.publicKeyPem),
)
const canReadOwnPrivate = computed(
  () =>
    keyState.value === 'active' &&
    hasActiveVisibleKey.value &&
    Boolean(self.value?.hasPrivateKey) &&
    Boolean(profile.value?.permissions.includes('key.private.read')),
)
const canRotateOwnKey = computed(
  () =>
    keyState.value === 'active' &&
    Boolean(profile.value?.enabled) &&
    !profileExpired.value &&
    Boolean(profile.value?.permissions.includes('key.rotate')),
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
  let active = 0
  let disabled = 0
  for (const user of adminUsers.value) {
    if (managedState(user) === 'active') {
      active += 1
    } else {
      disabled += 1
    }
  }
  return {
    total: adminUsers.value.length,
    active,
    disabled,
    pending: adminKeyRequests.value.length,
  }
})
const editingProfileReadOnly = computed(() => {
  const user = editingUser.value
  return (
    !user?.profile ||
    user.profile.origin === 'legacy' ||
    user.keyState === 'missing' ||
    user.keyState === 'expired'
  )
})
const editingHasEditableFields = computed(
  () =>
    Boolean(editingUser.value?.account) ||
    (Boolean(editingUser.value?.profile) && !editingProfileReadOnly.value),
)
const registrationOnly = computed(
  () => initialAuthMode === 'register' && providers.value.localRegistration,
)

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
  clearOwnKey()
})

watch(activePage, async (page) => {
  clearOwnKey()
  if (page === 'admin' && isAdmin.value) {
    await refreshAdminUsers()
  }
})

watch(createVisible, (visible) => {
  if (!visible) {
    createForm.password = ''
  }
})

watch(keyState, (state) => {
  if (state !== 'active') {
    clearOwnKey()
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
  clearOwnKey()
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
    if (nextSelf.keyState !== 'active') {
      clearOwnKey()
    }
    self.value = nextSelf
    if (nextSelf.account) {
      session.value = {
        authenticated: true,
        account: nextSelf.account,
      }
    }
    if (nextSelf.account.role === 'user') {
      await refreshAccessRecords(false)
    }
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      session.value = null
      self.value = null
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

async function submitKeyRequest(): Promise<void> {
  keyRequestLoading.value = true
  try {
    const request = await submitMyKeyRequest(
      profile.value?.username ?? account.value?.username,
    )
    if (self.value) {
      self.value.pendingKeyRequest = request
    }
    toast.add({
      severity: 'success',
      summary: '密钥申请已提交',
      detail: '管理员批准并设置有效期后，你可以在这里查看新密钥',
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

async function revealOwnKey(): Promise<void> {
  ownKeyLoading.value = true
  try {
    ownKey.value = await getMyPrivateKey()
    ownKeyVisible.value = true
    armOwnKeyTimer()
  } catch (error) {
    showError('无法读取私钥', error)
  } finally {
    ownKeyLoading.value = false
  }
}

function hideOwnKey(): void {
  clearOwnKey()
}

function clearOwnKey(): void {
  if (ownKeyTimer) {
    clearTimeout(ownKeyTimer)
    ownKeyTimer = undefined
  }
  ownKey.value = null
  ownKeyVisible.value = false
}

function armOwnKeyTimer(): void {
  if (ownKeyTimer) {
    clearTimeout(ownKeyTimer)
  }
  ownKeyTimer = setTimeout(clearOwnKey, 5 * 60 * 1000)
}

function downloadOwnPrivateKey(): void {
  if (!ownKey.value || keyState.value !== 'active') {
    return
  }
  const safeUsername = (profile.value?.username ?? account.value?.username ?? 'user')
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'user'
  const blob = new Blob([ownKey.value.privateKeyPem], {
    type: 'application/x-pem-file;charset=utf-8',
  })
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = `${safeUsername}-private-key.pem`
  anchor.rel = 'noopener'
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(objectUrl), 0)
  armOwnKeyTimer()
  toast.add({
    severity: 'success',
    summary: '私钥文件已下载',
    detail: '请将 PEM 文件保存在安全位置，不要通过不可信渠道传输',
    life: 4200,
  })
}

function confirmRotateOwnKey(): void {
  confirm.require({
    header: '重新生成密钥对',
    message:
      '旧私钥会立即失效。已经建立的连接不会被强制断开，但之后的新连接必须使用新私钥。',
    icon: 'pi pi-refresh',
    acceptLabel: '生成新密钥',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: () => {
      void rotateOwnKey()
    },
  })
}

async function rotateOwnKey(): Promise<void> {
  ownKeyLoading.value = true
  try {
    const key = await rotateMyKey()
    await refreshSelf()
    ownKey.value = {
      ...key,
      publicKeyPem: key.publicKeyPem || profile.value?.publicKeyPem || '',
    }
    ownKeyVisible.value = true
    armOwnKeyTimer()
    toast.add({
      severity: 'success',
      summary: '新密钥对已生成',
      detail: '请立即保存新私钥',
      life: 5000,
    })
  } catch (error) {
    showError('密钥更新失败', error)
  } finally {
    ownKeyLoading.value = false
  }
}

async function refreshAdminUsers(): Promise<void> {
  if (!isAdmin.value) {
    return
  }
  adminLoading.value = true
  keyRequestsLoading.value = true
  try {
    const [usersResult, requestsResult, settingsResult] =
      await Promise.allSettled([
        listManagedUsers(),
        listPendingKeyRequests(),
        getAccessLogSettings(),
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
  } finally {
    adminLoading.value = false
    keyRequestsLoading.value = false
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
  createForm.additionalPermissions = ''
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
  )
  if (!additionalPermissions) {
    return
  }
  createSaving.value = true
  try {
    await createManagedUser({
      username,
      password: createForm.password,
      expires_at: createForm.expiresAt.toISOString(),
      permissions: additionalPermissions,
    })
    createVisible.value = false
    createForm.password = ''
    await refreshAdminUsers()
    toast.add({
      severity: 'success',
      summary: '用户和密钥对已创建',
      detail: '密钥已安全生成，公钥仅供服务端认证，只有该用户本人可以查看私钥',
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
  editSaving.value = true
  try {
    await updateManagedUser(managedUsername(user), {
      role: user.account ? editForm.role : undefined,
      status: user.account ? editForm.status : undefined,
      enabled:
        user.profile && !editingProfileReadOnly.value
          ? editForm.enabled
          : undefined,
      expires_at:
        user.profile && !editingProfileReadOnly.value
        ? editForm.expiresAt?.toISOString() ?? null
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
  const username = managedUsername(user)
  confirm.require({
    header: user.hasPrivateKey ? '重新生成用户密钥' : '生成用户密钥',
    message: user.hasPrivateKey
      ? `确定为“${username}”生成新密钥吗？旧私钥会立即失效。`
      : `确定为“${username}”生成密钥吗？生成后只有该用户本人登录才能查看。`,
    icon: 'pi pi-refresh',
    acceptLabel: '生成新密钥',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: () => {
      void rotateAdminKey(user)
    },
  })
}

async function rotateAdminKey(user: ManagedUser): Promise<void> {
  const username = managedUsername(user)
  rotatingUsername.value = username
  try {
    await rotateManagedUserKey(username)
    await refreshAdminUsers()
    toast.add({
      severity: 'success',
      summary: '用户密钥已重新生成',
      detail: '公钥仅供服务端认证，只有该用户本人可以查看新的私钥',
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
  approvalVisible.value = true
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

  approvalSaving.value = true
  try {
    await approveKeyRequest(request.id, expiresAt.toISOString())
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
  confirm.require({
    header: '拒绝密钥申请',
    message: `确定拒绝“${request.username}”的密钥申请吗？用户可以稍后重新提交。`,
    icon: 'pi pi-times-circle',
    acceptLabel: '拒绝申请',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: () => {
      void performRejectKeyRequest(request)
    },
  })
}

async function performRejectKeyRequest(request: KeyRequest): Promise<void> {
  rejectingRequestId.value = request.id
  try {
    await rejectKeyRequest(request.id)
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

async function copyText(value: string, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value)
    toast.add({ severity: 'success', summary: `${label}已复制`, life: 1800 })
  } catch {
    toast.add({
      severity: 'warn',
      summary: '复制失败',
      detail: '请手动选择并复制',
      life: 3200,
    })
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

function managedState(user: ManagedUser): 'active' | 'disabled' | 'expired' {
  if (
    user.account?.status === 'disabled' ||
    user.profile?.enabled === false
  ) {
    return 'disabled'
  }
  if (isExpired(user.profile?.expiresAt ?? null)) {
    return 'expired'
  }
  return 'active'
}

function canAdminRotateDirectly(user: ManagedUser): boolean {
  return (
    Boolean(user.profile) &&
    user.profile?.origin !== 'legacy' &&
    user.keyState === 'active'
  )
}

function managedKeyStateLabel(user: ManagedUser): string {
  if (user.profile?.origin === 'legacy') {
    return '兼容配置'
  }
  if (user.keyState === 'active') {
    return '密钥有效'
  }
  if (user.keyState === 'disabled') {
    return '配置已停用'
  }
  return user.keyState === 'expired' ? '等待续期申请' : '等待密钥申请'
}

function managedKeyStateSeverity(
  user: ManagedUser,
): 'success' | 'warn' | 'secondary' {
  return user.keyState === 'active'
    ? 'success'
    : user.keyState === 'disabled'
      ? 'secondary'
      : user.profile?.origin === 'legacy'
        ? 'secondary'
        : 'warn'
}

function keyRequestKindLabel(request: KeyRequest): string {
  return request.kind === 'rotate' ? '过期重生成' : '首次申请'
}

function stateLabel(user: ManagedUser): string {
  const state = managedState(user)
  return state === 'active' ? '正常' : state === 'expired' ? '已过期' : '已停用'
}

function stateSeverity(
  user: ManagedUser,
): 'success' | 'warn' | 'danger' | 'secondary' {
  const state = managedState(user)
  return state === 'active' ? 'success' : state === 'expired' ? 'warn' : 'danger'
}

function permissionLabel(code: string): string {
  return permissionOptions.find((permission) => permission.code === code)?.label ?? code
}

function parseAdditionalPermissions(value: string): string[] | null {
  const baseCodes = new Set(
    permissionOptions.map((permission) => permission.code),
  )
  const permissions = [
    ...new Set(
      value
        .split(/[\s,，]+/)
        .map((permission) => permission.trim())
        .filter(Boolean),
    ),
  ].filter((permission) => !baseCodes.has(permission))

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
  if (permissions.length > 28) {
    toast.add({
      severity: 'warn',
      summary: '附加权限过多',
      detail: '除四项基础能力外，最多可以分配 28 项附加权限',
      life: 4200,
    })
    return null
  }
  return permissions.sort()
}

function originLabel(origin?: string): string {
  const labels: Record<string, string> = {
    local: '本地账号',
    google: '历史第三方账号',
    wechat: '历史第三方账号',
    admin: '管理员',
    legacy: '历史导入账号',
  }
  return labels[origin ?? ''] ?? origin ?? '未知'
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
        <template v-if="registrationOnly">
          <h1 id="auth-title">创建你的<br />代理账户。</h1>
          <p>
            注册后提交密钥申请；管理员批准并分配有效期后，即可使用代理服务。
          </p>
        </template>
        <template v-else>
          <h1 id="auth-title">你的代理身份，<br />由你掌控。</h1>
          <p>
            登录后查看私钥、有效期与权限。私钥仅在需要时显示，并会自动从页面中清除。
          </p>
        </template>
      </div>
      <div class="intro-security">
        <span><i class="pi pi-database" /> SQLite 加密存储</span>
        <span><i class="pi pi-clock" /> 私钥自动隐藏</span>
        <span><i class="pi pi-lock" /> HttpOnly 安全会话</span>
      </div>
    </section>

    <section
      class="auth-panel"
      :aria-label="registrationOnly ? '用户注册' : '账户登录'"
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
                : '注册后可以提交密钥申请；管理员批准有效期后，密钥仅向你本人显示。'
            }}
          </p>
        </div>

        <div
          v-if="!registrationOnly"
          class="auth-tabs"
          role="tablist"
          aria-label="登录或注册"
        >
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
            :label="(account?.displayName || account?.username || 'U').slice(0, 1).toUpperCase()"
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
          :label="(account?.displayName || account?.username || 'U').slice(0, 1).toUpperCase()"
          shape="circle"
        />
        <span class="account-menu-copy">
          <strong>{{ account?.displayName || account?.username }}</strong>
          <small>{{ account?.role === 'admin' ? '管理员' : '普通用户' }}</small>
        </span>
        <Button
          v-tooltip.bottom="'退出登录'"
          icon="pi pi-sign-out"
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
            <p>查看当前身份状态、连接权限和密钥材料。</p>
          </div>
          <Tag
            :value="account?.status === 'active' ? '账户正常' : '账户已停用'"
            :severity="account?.status === 'active' ? 'success' : 'danger'"
            rounded
          />
        </div>

        <div v-if="pageLoading" class="content-loading">
          <ProgressSpinner stroke-width="4" />
          <span>正在读取账户信息…</span>
        </div>

        <template v-else-if="account?.role === 'user'">
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
              <Tag :value="`${profile.permissions.length} 项`" severity="info" rounded />
            </div>
            <div class="permission-list">
              <div
                v-for="permission in permissionOptions"
                :key="permission.code"
                class="permission-item"
                :class="{ granted: profile.permissions.includes(permission.code) }"
              >
                <i
                  :class="
                    profile.permissions.includes(permission.code)
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
                    profile.permissions.includes(permission.code) ? '已授权' : '未授权'
                  "
                  :severity="
                    profile.permissions.includes(permission.code) ? 'success' : 'secondary'
                  "
                />
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

          <template v-if="hasActiveVisibleKey && profile">
            <section class="key-grid private-only-key-grid">
              <article class="content-card key-card private-card">
                <div class="card-heading">
                  <div>
                    <h2>私钥</h2>
                    <p>请勿分享。显示后会在五分钟内自动清除。</p>
                  </div>
                  <Tag value="敏感信息" severity="warn" rounded />
                </div>
                <div v-if="!ownKeyVisible" class="secret-placeholder">
                  <i class="pi pi-eye-slash" />
                  <strong>私钥当前已隐藏</strong>
                  <span v-if="canReadOwnPrivate">点击后会从加密存储中临时读取。</span>
                  <span v-else>当前账户没有查看私钥的权限或可用私钥。</span>
                  <Button
                    class="secret-reveal-button"
                    label="显示私钥"
                    icon="pi pi-eye"
                    severity="secondary"
                    outlined
                    size="small"
                    :loading="ownKeyLoading"
                    :disabled="!canReadOwnPrivate"
                    :aria-busy="ownKeyLoading"
                    @click="revealOwnKey"
                  />
                </div>
                <template v-else-if="ownKey">
                  <Textarea
                    class="private-key-textarea"
                    :model-value="ownKey.privateKeyPem"
                    readonly
                    wrap="off"
                    aria-label="代理私钥"
                  />
                  <div class="secret-actions">
                    <span><i class="pi pi-clock" /> 五分钟后自动隐藏</span>
                    <Button
                      label="复制私钥"
                      icon="pi pi-copy"
                      severity="secondary"
                      outlined
                      size="small"
                      @click="copyText(ownKey.privateKeyPem, '私钥')"
                    />
                    <Button
                      label="下载私钥"
                      icon="pi pi-download"
                      severity="secondary"
                      outlined
                      size="small"
                      @click="downloadOwnPrivateKey"
                    />
                    <Button
                      label="立即隐藏"
                      icon="pi pi-eye-slash"
                      severity="secondary"
                      text
                      size="small"
                      @click="hideOwnKey"
                    />
                  </div>
                </template>
              </article>
            </section>

            <section class="rotate-banner" :class="{ unavailable: !canRotateOwnKey }">
              <div class="rotate-icon"><i class="pi pi-refresh" /></div>
              <div>
                <h2>重新生成密钥对</h2>
                <p v-if="canRotateOwnKey">
                  在有效期内可以直接更新。更新后，旧私钥将不能用于建立新连接。
                </p>
                <p v-else>
                  当前账户没有更新密钥的权限，或代理配置已被停用。
                </p>
              </div>
              <Button
                label="生成新密钥"
                icon="pi pi-refresh"
                severity="danger"
                outlined
                :loading="ownKeyLoading"
                :disabled="!canRotateOwnKey"
                @click="confirmRotateOwnKey"
              />
            </section>
          </template>

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
              <h2 v-else-if="keyState === 'expired'">密钥已过期，请申请续期</h2>
              <h2 v-else-if="keyState === 'missing'">申请你的第一组代理密钥</h2>
              <h2 v-else-if="keyState === 'disabled'">代理配置已被停用</h2>
              <h2 v-else>密钥信息暂不可用</h2>
              <p
                v-if="
                  keyState !== 'disabled' &&
                  pendingKeyRequest?.status === 'pending'
                "
              >
                申请于
                {{ pendingKeyRequest.createdAt ? formatExpiry(pendingKeyRequest.createdAt) : '刚刚' }}
                提交。管理员批准并设置新的有效期后，私钥只会向你本人显示。
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
                  @click="submitKeyRequest"
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

        <section v-else class="empty-state content-card">
          <i class="pi pi-shield" />
          <h2>此管理员没有代理身份</h2>
          <p>管理员账户可以管理用户，但不会自动拥有代理密钥。</p>
          <Button
            v-if="isAdmin"
            label="前往用户管理"
            icon="pi pi-arrow-right"
            icon-pos="right"
            @click="activePage = 'admin'"
          />
        </section>
      </section>

      <section v-else-if="activePage === 'admin' && isAdmin" class="page-section">
        <div class="page-heading admin-heading">
          <div>
            <p class="eyebrow">ADMIN CONSOLE</p>
            <h1>用户管理</h1>
            <p>管理账户、代理配置和有效期，并可触发密钥生成；密钥内容仅用户本人可见。</p>
          </div>
          <Button label="新建普通用户" icon="pi pi-user-plus" @click="openCreate" />
        </div>

        <div class="summary-grid admin-summary">
          <article class="summary-card">
            <span class="summary-icon blue"><i class="pi pi-users" /></span>
            <div><small>全部用户</small><strong>{{ adminMetrics.total }}</strong></div>
          </article>
          <article class="summary-card">
            <span class="summary-icon green"><i class="pi pi-check" /></span>
            <div><small>正常可用</small><strong>{{ adminMetrics.active }}</strong></div>
          </article>
          <article class="summary-card">
            <span class="summary-icon red"><i class="pi pi-ban" /></span>
            <div><small>停用或过期</small><strong>{{ adminMetrics.disabled }}</strong></div>
          </article>
          <article class="summary-card pending-metric">
            <span class="summary-icon orange"><i class="pi pi-bell" /></span>
            <div><small>待审批申请</small><strong>{{ adminMetrics.pending }}</strong></div>
          </article>
        </div>

        <section class="content-card approval-card">
          <div class="approval-card-heading">
            <div class="approval-title">
              <span class="approval-title-icon"><i class="pi pi-key" /></span>
              <div>
                <h2>密钥申请审批</h2>
                <p>批准时只设置有效期并触发生成，公钥仅供服务端认证，管理员不会看到私钥 PEM。</p>
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
                :label="request.username.slice(0, 1).toUpperCase()"
                shape="circle"
              />
              <div class="approval-user">
                <strong>{{ request.displayName || request.username }}</strong>
                <span>
                  {{ request.username }}
                  <template v-if="request.email"> · {{ request.email }}</template>
                </span>
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

        <section class="content-card retention-card">
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

        <section class="content-card users-card">
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
            table-style="min-width: 68rem"
            paginator-template="FirstPageLink PrevPageLink PageLinks NextPageLink LastPageLink RowsPerPageDropdown"
            current-page-report-template="第 {first}–{last} 条，共 {totalRecords} 条"
          >
            <template #empty>
              <div class="table-empty">
                <i class="pi pi-users" />
                <span>{{ adminSearch ? '没有匹配的用户' : '还没有用户' }}</span>
              </div>
            </template>
            <Column header="用户" frozen style="min-width: 13rem">
              <template #body="{ data }">
                <div class="user-cell">
                  <Avatar :label="managedUsername(data).slice(0, 1).toUpperCase()" shape="circle" />
                  <span>
                    <strong>{{ managedUsername(data) }}</strong>
                    <small>{{ data.account?.email || originLabel(data.profile?.origin) }}</small>
                  </span>
                </div>
              </template>
            </Column>
            <Column header="角色 / 来源" style="min-width: 10rem">
              <template #body="{ data }">
                <div class="tag-stack">
                  <Tag
                    :value="data.account?.role === 'admin' ? '管理员' : '普通用户'"
                    :severity="data.account?.role === 'admin' ? 'info' : 'secondary'"
                  />
                  <small>{{ originLabel(data.profile?.origin) }}</small>
                </div>
              </template>
            </Column>
            <Column header="状态" style="min-width: 7rem">
              <template #body="{ data }">
                <Tag :value="stateLabel(data)" :severity="stateSeverity(data)" rounded />
              </template>
            </Column>
            <Column header="有效期" style="min-width: 12rem">
              <template #body="{ data }">
                <span>{{ data.profile ? formatExpiry(data.profile.expiresAt) : '—' }}</span>
              </template>
            </Column>
            <Column header="权限" style="min-width: 14rem">
              <template #body="{ data }">
                <div v-if="data.profile?.permissions.length" class="permission-tags">
                  <Tag
                    v-for="permission in data.profile.permissions.slice(0, 2)"
                    :key="permission"
                    :value="permissionLabel(permission)"
                    severity="secondary"
                  />
                  <small v-if="data.profile.permissions.length > 2">
                    +{{ data.profile.permissions.length - 2 }}
                  </small>
                </div>
                <span v-else>—</span>
              </template>
            </Column>
            <Column header="密钥" style="min-width: 8rem">
              <template #body="{ data }">
                <Tag
                  :value="managedKeyStateLabel(data)"
                  :severity="managedKeyStateSeverity(data)"
                />
              </template>
            </Column>
            <Column header="操作" frozen align-frozen="right" style="min-width: 10rem">
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
                  <Button
                    v-tooltip.top="'删除'"
                    icon="pi pi-trash"
                    severity="danger"
                    text
                    rounded
                    aria-label="删除用户"
                    :loading="deletingUsername === managedUsername(data)"
                    @click="confirmDelete(data)"
                  />
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
      保存后服务端会生成 RSA 密钥对并加密存储。公钥仅供服务端认证，私钥只有用户本人登录后可以查看。
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
            v-for="permission in permissionOptions"
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
      <div class="form-field">
        <label for="create-additional-permissions">附加权限</label>
        <Textarea
          id="create-additional-permissions"
          v-model="createForm.additionalPermissions"
          rows="3"
          placeholder="例如 report.read, tunnel.priority"
          aria-describedby="additional-permissions-help"
          fluid
        />
        <small id="additional-permissions-help">
          可选。使用逗号、空格或换行分隔 permission code；重复项和上方四项基础能力会自动排除，服务端会自动合并基础能力。
        </small>
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
    :header="`编辑 ${editingUser ? managedUsername(editingUser) : ''}`"
    class="form-dialog"
    :style="{ width: 'min(92vw, 650px)' }"
  >
    <form id="edit-user-form" class="dialog-form" @submit.prevent="submitEdit">
      <div v-if="editingUser?.account" class="form-row">
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
      </div>
      <div v-else class="legacy-notice">
        <i class="pi pi-info-circle" />
        <span>这是历史导入的只读配置，Web 控制台不会修改其有效期、权限或密钥。</span>
      </div>
      <template v-if="editingUser?.profile">
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
            当前为只读状态，不能从这里延长或恢复有效期。
          </small>
          <small v-else>清空表示永久有效。</small>
        </div>
        <label class="switch-line" for="edit-enabled">
          <Checkbox
            v-model="editForm.enabled"
            input-id="edit-enabled"
            binary
            :disabled="editingProfileReadOnly"
          />
          <span><strong>允许代理连接</strong><small>关闭后会拒绝该用户建立新连接。</small></span>
        </label>
        <section
          v-if="editingUser?.account"
          class="fixed-capabilities"
          aria-labelledby="edit-capabilities-title"
        >
          <div class="fixed-capabilities-heading">
            <span class="summary-icon blue"><i class="pi pi-shield" /></span>
            <div>
              <strong id="edit-capabilities-title">普通用户基础能力</strong>
              <small>这些能力不可单独撤销；可通过上方开关整体停用代理连接。</small>
            </div>
          </div>
          <ul>
            <li
              v-for="permission in permissionOptions"
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
      </template>
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

  <Dialog
    v-model:visible="approvalVisible"
    modal
    header="批准密钥申请"
    class="form-dialog approval-dialog"
    :style="{ width: 'min(92vw, 560px)' }"
  >
    <div v-if="approvalRequest" class="approval-dialog-user">
      <Avatar
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
    <div class="privacy-notice">
      <i class="pi pi-eye-slash" />
      <span>
        批准后服务端会生成新密钥。公钥仅供服务端认证，私钥仅用户本人登录后可见。
      </span>
    </div>
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
        @click="submitApproval"
      />
    </template>
  </Dialog>

</template>
