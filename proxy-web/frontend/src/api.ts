export type AccountRole = 'admin' | 'user'
export type AccountStatus = 'active' | 'disabled'
export type KeyState = 'missing' | 'active' | 'expired' | 'disabled'
export type KeyRequestStatus = 'pending' | 'approved' | 'rejected'
export type KeyRequestKind = 'initial' | 'rotate'

export interface ProviderAvailability {
  localRegistration: boolean
}

export interface AccountSummary {
  id?: string
  username: string
  linkedUsername?: string | null
  displayName?: string | null
  email?: string | null
  avatarUrl?: string | null
  role: AccountRole
  status: AccountStatus
  providers: string[]
}

export interface ProfileSummary {
  username: string
  expiresAt: string | null
  permissions: string[]
  enabled: boolean
  origin: string
  keyVersion: number
  createdAt?: string
  updatedAt?: string
}

export interface ProxyProfile extends ProfileSummary {
  publicKeyPem?: string
}

export type ManagedProxyProfile = ProfileSummary

export interface SessionState {
  authenticated: boolean
  account: AccountSummary | null
}

export interface SelfView {
  account: AccountSummary
  profile: ProxyProfile | null
  hasPrivateKey: boolean
  keyState: KeyState
  pendingKeyRequest: KeyRequest | null
}

export interface ManagedUser {
  account: AccountSummary | null
  profile: ManagedProxyProfile | null
  hasPrivateKey: boolean
  keyState: KeyState
}

export interface KeyMaterial {
  publicKeyPem: string
  privateKeyPem: string
  keyVersion?: number
}

export interface KeyRequest {
  id: string
  username: string
  status: KeyRequestStatus
  kind: KeyRequestKind
  createdAt: string | null
  updatedAt: string | null
  expiresAt: string | null
  displayName?: string | null
  email?: string | null
}

export interface AccessRecord {
  id?: string
  accessedAt: string
  targetHost: string
  targetPort: number
  transport: 'tcp' | 'udp'
  accessCount: number
}

export interface AccessLogSettings {
  retentionDays: number
}

export interface AccessRecordsResult {
  records: AccessRecord[]
  retentionDays: number
}

export type AgentDeviceAuthorizationStatus =
  | 'pending'
  | 'authorized'
  | 'denied'
  | 'consumed'

export interface AgentDeviceAuthorizationInspection {
  clientName: string
  platform: 'android' | 'windows'
  expiresAt: number
  status: AgentDeviceAuthorizationStatus
}

export interface RegisterPayload {
  username: string
  password: string
}

export interface CreateManagedUserPayload extends RegisterPayload {
  expires_at: string
  permissions?: string[]
}

export interface UpdateManagedUserPayload {
  role?: AccountRole
  status?: AccountStatus
  enabled?: boolean
  expires_at?: string | null
  permissions?: string[]
}

export class ApiError extends Error {
  readonly status: number
  readonly code?: string

  constructor(message: string, status: number, code?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

let csrfToken = ''

export function clearClientSession(): void {
  csrfToken = ''
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')

  if (init.body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }
  if (csrfToken && isMutation(init.method)) {
    headers.set('X-CSRF-Token', csrfToken)
  }

  const response = await fetch(path, {
    ...init,
    credentials: 'same-origin',
    headers,
  })

  const body = await parseResponse(response)
  adoptCsrf(body)

  if (!response.ok) {
    const record = asRecord(body)
    const nested = asRecord(record?.error)
    const message =
      stringValue(record?.message) ??
      stringValue(nested?.message) ??
      stringValue(record?.detail) ??
      stringValue(record?.error) ??
      `请求失败（HTTP ${response.status}）`
    const code = stringValue(record?.code) ?? stringValue(nested?.code)
    throw new ApiError(message, response.status, code)
  }

  return body as T
}

async function parseResponse(response: Response): Promise<unknown> {
  if (response.status === 204) {
    return undefined
  }

  const text = await response.text()
  if (!text) {
    return undefined
  }

  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(text) as unknown
    } catch {
      throw new ApiError('服务器返回了无效的 JSON', 502)
    }
  }
  return text
}

function isMutation(method?: string): boolean {
  return !['GET', 'HEAD', 'OPTIONS'].includes((method ?? 'GET').toUpperCase())
}

function adoptCsrf(value: unknown): void {
  const record = asRecord(value)
  const session = asRecord(record?.session)
  const token =
    stringValue(record?.csrf_token) ??
    stringValue(record?.csrfToken) ??
    stringValue(session?.csrf_token)
  if (token) {
    csrfToken = token
  }
}

export async function getProviders(): Promise<ProviderAvailability> {
  const body = await request<unknown>('/api/v1/auth/providers')
  const root = asRecord(body) ?? {}

  return {
    localRegistration:
      boolValue(root.local_registration) ??
      boolValue(root.localRegistration) ??
      true,
  }
}

export async function getSession(): Promise<SessionState> {
  const body = await request<unknown>('/api/v1/session')
  return decodeSession(body)
}

export async function login(payload: RegisterPayload): Promise<SessionState> {
  const body = await request<unknown>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
  return decodeSession(body, true)
}

export async function register(
  payload: RegisterPayload,
): Promise<SessionState> {
  const body = await request<unknown>('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
  return decodeSession(body, true)
}

export async function logout(): Promise<void> {
  try {
    await request<unknown>('/api/v1/auth/logout', { method: 'POST' })
  } finally {
    clearClientSession()
  }
}

export async function inspectAgentDeviceAuthorization(
  userCode: string,
): Promise<AgentDeviceAuthorizationInspection> {
  const body = await request<unknown>(
    '/api/v1/agent/device-authorizations/inspect',
    {
      method: 'POST',
      body: JSON.stringify({ user_code: userCode }),
    },
  )
  return decodeAgentDeviceAuthorization(body)
}

export async function approveAgentDeviceAuthorization(
  userCode: string,
): Promise<void> {
  await request<unknown>('/api/v1/agent/device-authorizations/approve', {
    method: 'POST',
    body: JSON.stringify({ user_code: userCode }),
  })
}

export async function denyAgentDeviceAuthorization(
  userCode: string,
): Promise<void> {
  await request<unknown>('/api/v1/agent/device-authorizations/deny', {
    method: 'POST',
    body: JSON.stringify({ user_code: userCode }),
  })
}

export async function getMe(): Promise<SelfView> {
  const body = await request<unknown>('/api/v1/me')
  return decodeSelf(body)
}

export async function getMyKeyRequest(
  username?: string,
): Promise<KeyRequest | null> {
  try {
    const body = await request<unknown>('/api/v1/me/key-request')
    return decodeNullableKeyRequest(body, username)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null
    }
    throw error
  }
}

export async function submitMyKeyRequest(
  username?: string,
): Promise<KeyRequest> {
  const body = await request<unknown>('/api/v1/me/key-requests', {
    method: 'POST',
  })
  const requestRecord = decodeNullableKeyRequest(body, username)
  if (!requestRecord) {
    throw new ApiError('服务器没有返回密钥申请', 502)
  }
  return requestRecord
}

export async function getMyPrivateKey(): Promise<KeyMaterial> {
  const body = await request<unknown>('/api/v1/me/private-key')
  return decodeKeyMaterial(body)
}

export async function rotateMyKey(): Promise<KeyMaterial> {
  const body = await request<unknown>('/api/v1/me/rotate-key', {
    method: 'POST',
  })
  return decodeKeyMaterial(body)
}

export async function listMyAccessRecords(): Promise<AccessRecordsResult> {
  const body = await request<unknown>('/api/v1/me/access-records')
  const root = asRecord(body)
  const values = Array.isArray(body)
    ? body
    : Array.isArray(root?.access_records)
      ? root.access_records
      : Array.isArray(root?.accessRecords)
        ? root.accessRecords
        : Array.isArray(root?.records)
          ? root.records
          : Array.isArray(root?.items)
            ? root.items
            : null
  if (!values) {
    throw new ApiError('服务器返回的访问记录格式无效', 502)
  }
  return {
    records: values.map(decodeAccessRecord),
    retentionDays:
      numberValue(root?.retention_days) ??
      numberValue(root?.retentionDays) ??
      7,
  }
}

export async function listManagedUsers(): Promise<ManagedUser[]> {
  const body = await request<unknown>('/api/v1/admin/users')
  const record = asRecord(body)
  const values = Array.isArray(body)
    ? body
    : Array.isArray(record?.users)
      ? record.users
      : Array.isArray(record?.items)
        ? record.items
        : null

  if (!values) {
    throw new ApiError('服务器返回的用户列表格式无效', 502)
  }
  return values.map(decodeManagedUser)
}

export async function createManagedUser(
  payload: CreateManagedUserPayload,
): Promise<ManagedUser> {
  const body = await request<unknown>('/api/v1/admin/users', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
  const root = asRecord(body) ?? {}
  const candidate = root.user ?? root.managed_user ?? body
  return decodeManagedUser(candidate)
}

export async function updateManagedUser(
  username: string,
  payload: UpdateManagedUserPayload,
): Promise<ManagedUser> {
  const body = await request<unknown>(
    `/api/v1/admin/users/${encodeURIComponent(username)}`,
    {
      method: 'PATCH',
      body: JSON.stringify(payload),
    },
  )
  const record = asRecord(body)
  return decodeManagedUser(record?.user ?? record?.managed_user ?? body)
}

export function deleteManagedUser(username: string): Promise<void> {
  return request<void>(
    `/api/v1/admin/users/${encodeURIComponent(username)}`,
    { method: 'DELETE' },
  )
}

export async function rotateManagedUserKey(
  username: string,
): Promise<ManagedUser> {
  const body = await request<unknown>(
    `/api/v1/admin/users/${encodeURIComponent(username)}/rotate-key`,
    { method: 'POST' },
  )
  const root = asRecord(body) ?? {}
  return decodeManagedUser(root.user ?? root.managed_user ?? body)
}

export async function listPendingKeyRequests(): Promise<KeyRequest[]> {
  const body = await request<unknown>('/api/v1/admin/key-requests')
  const root = asRecord(body)
  const values = Array.isArray(body)
    ? body
    : Array.isArray(root?.key_requests)
      ? root.key_requests
      : Array.isArray(root?.keyRequests)
        ? root.keyRequests
        : Array.isArray(root?.requests)
          ? root.requests
          : Array.isArray(root?.items)
            ? root.items
            : null
  if (!values) {
    throw new ApiError('服务器返回的密钥申请列表格式无效', 502)
  }
  return values.map((value) => decodeKeyRequest(value))
}

export async function approveKeyRequest(
  requestId: string,
  expiresAt: string,
): Promise<void> {
  await request<unknown>(
    `/api/v1/admin/key-requests/${encodeURIComponent(requestId)}/approve`,
    {
      method: 'POST',
      body: JSON.stringify({ expires_at: expiresAt }),
    },
  )
}

export async function rejectKeyRequest(requestId: string): Promise<void> {
  await request<unknown>(
    `/api/v1/admin/key-requests/${encodeURIComponent(requestId)}/reject`,
    { method: 'POST' },
  )
}

export async function getAccessLogSettings(): Promise<AccessLogSettings> {
  const body = await request<unknown>('/api/v1/admin/access-log-settings')
  return decodeAccessLogSettings(body)
}

export async function updateAccessLogSettings(
  retentionDays: number,
): Promise<AccessLogSettings> {
  const body = await request<unknown>('/api/v1/admin/access-log-settings', {
    method: 'PATCH',
    body: JSON.stringify({ retention_days: retentionDays }),
  })
  return decodeAccessLogSettings(body, retentionDays)
}

function decodeSession(
  value: unknown,
  assumeAuthenticated = false,
): SessionState {
  const root = asRecord(value) ?? {}
  const source = asRecord(root.session) ?? root
  const accountValue = source.account ?? root.account ?? root.user
  const account = accountValue ? decodeAccount(accountValue) : null
  const authenticated =
    boolValue(source.authenticated) ??
    boolValue(root.authenticated) ??
    (assumeAuthenticated || account !== null)

  return { authenticated, account }
}

function decodeAgentDeviceAuthorization(
  value: unknown,
): AgentDeviceAuthorizationInspection {
  const root = asRecord(value)
  const clientName =
    stringValue(root?.client_name) ?? stringValue(root?.clientName)
  const platform = stringValue(root?.platform)?.toLowerCase()
  const expiresAt =
    numberValue(root?.expires_at) ?? numberValue(root?.expiresAt)
  const status =
    stringValue(root?.status)?.toLowerCase() as
      | AgentDeviceAuthorizationStatus
      | undefined
  if (
    !clientName ||
    (platform !== 'android' && platform !== 'windows') ||
    expiresAt === undefined ||
    !status ||
    !['pending', 'authorized', 'denied', 'consumed'].includes(status)
  ) {
    throw new ApiError('服务器返回的设备授权信息格式无效', 502)
  }
  return {
    clientName,
    platform,
    expiresAt,
    status,
  }
}

function decodeSelf(value: unknown): SelfView {
  const root = asRecord(value)
  if (!root) {
    throw new ApiError('服务器返回的账户信息格式无效', 502)
  }
  const account = decodeAccount(root.account ?? root.user ?? root)
  const profileValue = root.profile ?? root.proxy_profile
  const profile = profileValue
    ? decodeSelfProfile(profileValue)
    : hasProfile(root)
      ? decodeSelfProfile(root)
      : null
  const hasPrivateKey =
    boolValue(root.has_private_key) ??
    boolValue(root.hasPrivateKey) ??
    (profile !== null && profile.origin !== 'legacy')
  const keyState = decodeKeyState(
    root.key_state ?? root.keyState,
    profile,
    hasPrivateKey,
  )
  const pendingValue =
    root.pending_request ??
    root.pendingRequest ??
    root.pending_key_request ??
    root.pendingKeyRequest ??
    root.key_request
  return {
    account,
    profile,
    hasPrivateKey,
    keyState,
    pendingKeyRequest: decodeNullableKeyRequest(
      pendingValue,
      profile?.username ?? account.username,
    ),
  }
}

function decodeManagedUser(value: unknown): ManagedUser {
  const root = asRecord(value)
  if (!root) {
    throw new ApiError('服务器返回了无效的用户记录', 502)
  }

  const accountValue = root.account ?? root.web_account
  const profileValue = root.profile ?? root.proxy_profile ?? root.user
  const account = accountValue
    ? decodeAccount(accountValue)
    : hasAccount(root)
      ? decodeAccount(root)
      : null
  const profile = profileValue
    ? decodeManagedProfile(profileValue)
    : hasProfile(root)
      ? decodeManagedProfile(root)
      : null

  if (!account && !profile) {
    throw new ApiError('服务器返回了无效的用户记录', 502)
  }

  const hasPrivateKey =
    boolValue(root.has_private_key) ??
    boolValue(root.hasPrivateKey) ??
    false
  return {
    account,
    profile,
    hasPrivateKey,
    keyState: decodeKeyState(
      root.key_state ?? root.keyState,
      profile,
      hasPrivateKey,
    ),
  }
}

function decodeAccount(value: unknown): AccountSummary {
  const root = asRecord(value)
  if (!root) {
    throw new ApiError('服务器返回了无效的账户记录', 502)
  }
  const username =
    stringValue(root.login_name) ??
    stringValue(root.username) ??
    stringValue(root.name) ??
    stringValue(root.email)
  if (!username) {
    throw new ApiError('账户记录缺少用户名', 502)
  }

  const rawRole = (stringValue(root.role) ?? 'user').toLowerCase()
  const rawStatus = (stringValue(root.status) ?? 'active').toLowerCase()
  const identities = Array.isArray(root.providers)
    ? root.providers
    : Array.isArray(root.identities)
      ? root.identities
      : []
  const providers = identities
    .map((entry) =>
      typeof entry === 'string'
        ? entry
        : stringValue(asRecord(entry)?.provider),
    )
    .filter((entry): entry is string => Boolean(entry))

  return {
    id: stringValue(root.id) ?? stringValue(root.account_id),
    username,
    linkedUsername:
      nullableString(root.linked_username) ??
      nullableString(root.profile_username),
    displayName:
      nullableString(root.display_name) ?? nullableString(root.nickname),
    email: nullableString(root.email),
    avatarUrl:
      nullableString(root.avatar_url) ?? nullableString(root.avatar),
    role: rawRole === 'admin' ? 'admin' : 'user',
    status: rawStatus === 'disabled' ? 'disabled' : 'active',
    providers,
  }
}

function decodeProfileSummary(value: unknown): ProfileSummary {
  const root = asRecord(value)
  if (!root) {
    throw new ApiError('服务器返回了无效的代理配置', 502)
  }
  const username =
    stringValue(root.username) ??
    stringValue(root.login_name) ??
    stringValue(root.profile_username)
  if (!username) {
    throw new ApiError('代理配置缺少用户名', 502)
  }

  return {
    username,
    expiresAt:
      nullableTimestamp(root.expires_at) ??
      nullableTimestamp(root.expiresAt) ??
      null,
    permissions: stringArray(root.permissions),
    enabled: boolValue(root.enabled) ?? true,
    origin: stringValue(root.origin) ?? 'local',
    keyVersion:
      numberValue(root.key_version) ?? numberValue(root.keyVersion) ?? 1,
    createdAt:
      stringValue(root.created_at) ?? stringValue(root.createdAt),
    updatedAt:
      stringValue(root.updated_at) ?? stringValue(root.updatedAt),
  }
}

function decodeSelfProfile(value: unknown): ProxyProfile {
  const root = asRecord(value)
  const publicKeyPem =
    stringValue(root?.public_key_pem) ?? stringValue(root?.publicKeyPem)
  return {
    ...decodeProfileSummary(value),
    ...(publicKeyPem ? { publicKeyPem } : {}),
  }
}

function decodeManagedProfile(value: unknown): ManagedProxyProfile {
  // 管理员响应即使误带公钥也不会被保留在前端状态中。
  return decodeProfileSummary(value)
}

function decodeNullableKeyRequest(
  value: unknown,
  fallbackUsername?: string,
): KeyRequest | null {
  if (value === null || value === undefined || value === false) {
    return null
  }
  const root = asRecord(value)
  if (!root) {
    return null
  }
  const candidate =
    root.key_request ??
    root.keyRequest ??
    root.pending_request ??
    root.pendingRequest ??
    root.pending_key_request ??
    root.pendingKeyRequest ??
    root.request ??
    value
  if (candidate === null || candidate === false) {
    return null
  }
  const candidateRecord = asRecord(candidate)
  if (
    candidateRecord &&
    boolValue(candidateRecord.pending) === false &&
    !candidateRecord.id &&
    !candidateRecord.request_id
  ) {
    return null
  }
  return decodeKeyRequest(candidate, fallbackUsername)
}

function decodeKeyRequest(
  value: unknown,
  fallbackUsername?: string,
): KeyRequest {
  const root = asRecord(value)
  if (!root) {
    throw new ApiError('服务器返回了无效的密钥申请', 502)
  }
  const account = asRecord(root.account) ?? asRecord(root.user)
  const profile = asRecord(root.profile)
  const id =
    identifierValue(root.id) ??
    identifierValue(root.request_id) ??
    identifierValue(root.key_request_id)
  const username =
    stringValue(root.username) ??
    stringValue(root.login_name) ??
    stringValue(root.profile_username) ??
    stringValue(profile?.username) ??
    stringValue(account?.login_name) ??
    stringValue(account?.username) ??
    fallbackUsername
  if (!id || !username) {
    throw new ApiError('密钥申请缺少编号或用户名', 502)
  }
  const rawStatus = (
    stringValue(root.status) ??
    stringValue(root.request_status) ??
    'pending'
  ).toLowerCase()
  const status: KeyRequestStatus =
    rawStatus === 'approved'
      ? 'approved'
      : rawStatus === 'rejected'
        ? 'rejected'
        : 'pending'
  const rawKind = (
    stringValue(root.kind) ??
    stringValue(root.request_kind) ??
    stringValue(root.requestKind) ??
    'initial'
  ).toLowerCase()

  return {
    id,
    username,
    status,
    kind: rawKind === 'rotate' ? 'rotate' : 'initial',
    createdAt:
      nullableTimestamp(root.created_at) ??
      nullableTimestamp(root.createdAt) ??
      nullableTimestamp(root.requested_at) ??
      nullableTimestamp(root.requestedAt) ??
      null,
    updatedAt:
      nullableTimestamp(root.updated_at) ??
      nullableTimestamp(root.updatedAt) ??
      nullableTimestamp(root.decided_at) ??
      nullableTimestamp(root.decidedAt) ??
      nullableTimestamp(root.reviewed_at) ??
      nullableTimestamp(root.reviewedAt) ??
      null,
    expiresAt:
      nullableTimestamp(root.expires_at) ??
      nullableTimestamp(root.expiresAt) ??
      nullableTimestamp(root.approved_expires_at) ??
      nullableTimestamp(root.approvedExpiresAt) ??
      null,
    displayName:
      nullableString(root.display_name) ??
      nullableString(root.displayName) ??
      nullableString(account?.display_name),
    email: nullableString(root.email) ?? nullableString(account?.email),
  }
}

function decodeKeyState(
  value: unknown,
  profile: ProfileSummary | null,
  hasPrivateKey: boolean,
): KeyState {
  const normalized = stringValue(value)?.toLowerCase()
  if (
    normalized === 'missing' ||
    normalized === 'active' ||
    normalized === 'expired' ||
    normalized === 'disabled'
  ) {
    return normalized
  }
  if (profile?.enabled === false) {
    return 'disabled'
  }
  if (!hasPrivateKey) {
    return 'missing'
  }
  const expiry = profile?.expiresAt
  if (expiry) {
    const numeric = /^-?\d+$/.test(expiry) ? Number(expiry) : Number.NaN
    const milliseconds = Number.isFinite(numeric)
      ? Math.abs(numeric) < 100_000_000_000
        ? numeric * 1000
        : numeric
      : Date.parse(expiry)
    if (Number.isFinite(milliseconds) && milliseconds <= Date.now()) {
      return 'expired'
    }
  }
  return 'active'
}

function decodeAccessRecord(value: unknown): AccessRecord {
  const root = asRecord(value)
  if (!root) {
    throw new ApiError('服务器返回了无效的访问记录', 502)
  }
  const accessedAt =
    nullableTimestamp(root.accessed_at) ??
    nullableTimestamp(root.accessedAt) ??
    nullableTimestamp(root.created_at) ??
    nullableTimestamp(root.timestamp)
  const targetHost =
    stringValue(root.target_host) ??
    stringValue(root.targetHost) ??
    stringValue(root.host) ??
    stringValue(root.domain) ??
    stringValue(root.target)
  const targetPort =
    numberValue(root.target_port) ??
    numberValue(root.targetPort) ??
    numberValue(root.port)
  if (!accessedAt || !targetHost || targetPort === undefined) {
    throw new ApiError('访问记录缺少时间或目标地址', 502)
  }
  const rawTransport = (
    stringValue(root.transport) ??
    stringValue(root.protocol) ??
    'tcp'
  ).toLowerCase()
  const accessCount =
    numberValue(root.access_count) ??
    numberValue(root.accessCount) ??
    numberValue(root.count) ??
    1
  if (!Number.isInteger(accessCount) || accessCount < 1) {
    throw new ApiError('访问记录的访问次数无效', 502)
  }
  return {
    id:
      identifierValue(root.id) ??
      identifierValue(root.record_id) ??
      undefined,
    accessedAt,
    targetHost,
    targetPort,
    transport: rawTransport === 'udp' ? 'udp' : 'tcp',
    accessCount,
  }
}

function decodeAccessLogSettings(
  value: unknown,
  fallback = 7,
): AccessLogSettings {
  const root = asRecord(value) ?? {}
  const nested = asRecord(root.settings)
  const retentionDays =
    numberValue(root.retention_days) ??
    numberValue(root.retentionDays) ??
    numberValue(nested?.retention_days) ??
    numberValue(nested?.retentionDays) ??
    fallback
  if (
    !Number.isInteger(retentionDays) ||
    retentionDays < 1 ||
    retentionDays > 365
  ) {
    throw new ApiError('服务器返回的访问记录保留天数无效', 502)
  }
  return { retentionDays }
}

function decodeKeyMaterial(value: unknown): KeyMaterial {
  const root = asRecord(value)
  if (!root) {
    throw new ApiError('服务器没有返回密钥内容', 502)
  }
  const nested =
    asRecord(root.credentials) ??
    asRecord(root.key) ??
    asRecord(root.keys) ??
    root
  const profile = asRecord(root.profile) ?? asRecord(root.user)
  const privateKeyPem =
    stringValue(nested.private_key_pem) ??
    stringValue(nested.privateKeyPem) ??
    stringValue(root.private_key)
  const publicKeyPem =
    stringValue(nested.public_key_pem) ??
    stringValue(nested.publicKeyPem) ??
    stringValue(profile?.public_key_pem) ??
    ''

  if (!privateKeyPem) {
    throw new ApiError('服务器没有返回私钥内容', 502)
  }

  return {
    privateKeyPem,
    publicKeyPem,
    keyVersion:
      numberValue(nested.key_version) ?? numberValue(nested.keyVersion),
  }
}

function hasAccount(value: Record<string, unknown>): boolean {
  return (
    'role' in value ||
    'login_name' in value ||
    'account_status' in value ||
    'status' in value
  )
}

function hasProfile(value: Record<string, unknown>): boolean {
  return (
    'public_key_pem' in value ||
    'expires_at' in value ||
    'permissions' in value ||
    'origin' in value
  )
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value : undefined
}

function nullableString(value: unknown): string | null | undefined {
  return value === null ? null : stringValue(value)
}

function nullableTimestamp(value: unknown): string | null | undefined {
  if (value === null) {
    return null
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value)
  }
  return stringValue(value)
}

function boolValue(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value
  }
  if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) {
    return Number(value)
  }
  return undefined
}

function identifierValue(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim()) {
    return value
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value)
  }
  return undefined
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === 'string')
    : []
}
