import { ApiError } from '../types'
import type {
  AccountSummary,
  ManagedProxyProfile,
  ManagedUser,
  ProfileSummary,
  ProxyProfile,
  SelfView,
} from '../types'
import {
  asRecord,
  boolValue,
  nullableString,
  nullableTimestamp,
  numberValue,
  stringArray,
  stringValue,
} from '../values'
import {
  decodeKeyState,
  decodeNullableKeyRequest,
} from './keys'

export function decodeSelf(value: unknown): SelfView {
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

export function decodeManagedUser(value: unknown): ManagedUser {
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

export function decodeAccount(value: unknown): AccountSummary {
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
