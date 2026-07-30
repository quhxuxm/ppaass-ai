export type AccountRole = 'admin' | 'user'
export type AccountStatus = 'active' | 'disabled'
export type KeyState = 'missing' | 'active' | 'expired' | 'disabled'
export type KeyRequestStatus = 'pending' | 'approved' | 'rejected'
export type KeyRequestKind = 'initial' | 'rotate'
export type AuditAction =
  | 'key_request_approved'
  | 'key_request_rejected'
  | 'key_regenerated'
  | 'proxy_access_enabled'
  | 'proxy_access_disabled'
  | 'web_login_enabled'
  | 'web_login_disabled'
  | 'proxy_server_enabled'
  | 'proxy_server_disabled'
  | 'permissions_updated'
export const KEY_REQUEST_MESSAGE_MAX_LENGTH = 500
export const KEY_REQUEST_REJECTION_REASON_MAX_LENGTH = 500

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
  agentHandoff: boolean
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
  proxyAddresses: ProxyAddress[]
}

export interface ProxyAddress {
  id: string
  label: string
  address: string
  enabled: boolean
}

export interface KeyRequest {
  id: string
  username: string
  status: KeyRequestStatus
  kind: KeyRequestKind
  createdAt: string | null
  updatedAt: string | null
  expiresAt: string | null
  requestMessage: string | null
  rejectionReason: string | null
  reviewerLoginName: string | null
  displayName?: string | null
  avatarUrl?: string | null
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

export interface AuditEvent {
  id: number
  action: AuditAction
  actorAccountId: string
  actorLoginName: string
  targetKind: 'user' | 'proxy_server'
  targetId: string
  targetName: string
  contextId: string | null
  reason: string | null
  previousValue: string | null
  newValue: string | null
  createdAt: string
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

export interface ChangePasswordPayload {
  current_password: string
  new_password: string
}

export interface UpdateMyProfilePayload {
  display_name: string | null
  avatar_data_url?: string | null
}

export interface CreateManagedUserPayload extends RegisterPayload {
  expires_at: string
  permissions?: string[]
  proxy_address_ids: string[]
  audit_reason: string
}

export interface UpdateManagedUserPayload {
  role?: AccountRole
  status?: AccountStatus
  enabled?: boolean
  expires_at?: string | null
  permissions?: string[]
  proxy_address_ids?: string[]
  audit_reason?: string
}

export interface CreateProxyAddressPayload {
  label?: string
  address: string
  enabled?: boolean
}

export interface UpdateProxyAddressPayload {
  label?: string
  address?: string
  enabled?: boolean
  audit_reason?: string
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
