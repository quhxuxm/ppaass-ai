import {
  decodeAccessLogSettings,
  decodeAccessRecord,
} from './decoders/access'
import {
  decodeKeyRequest,
  decodeNullableKeyRequest,
} from './decoders/keys'
import {
  decodeAgentDeviceAuthorization,
  decodeSession,
} from './decoders/session'
import {
  decodeManagedUser,
  decodeSelf,
} from './decoders/users'
import { clearClientSession, request } from './transport'
import {
  ApiError,
  KEY_REQUEST_MESSAGE_MAX_LENGTH,
} from './types'
import type {
  AccessLogSettings,
  AccessRecordsResult,
  AgentDeviceAuthorizationInspection,
  ChangePasswordPayload,
  CreateManagedUserPayload,
  KeyRequest,
  ManagedUser,
  ProviderAvailability,
  RegisterPayload,
  SelfView,
  SessionState,
  UpdateManagedUserPayload,
} from './types'
import { asRecord, boolValue, numberValue } from './values'

export { clearClientSession }

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
  return decodeSession(await request<unknown>('/api/v1/session'))
}

export async function login(
  payload: RegisterPayload,
): Promise<SessionState> {
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
  return decodeSelf(await request<unknown>('/api/v1/me'))
}

export async function changeMyPassword(
  payload: ChangePasswordPayload,
): Promise<void> {
  await request<unknown>('/api/v1/me/password', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
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
  message: string | null = null,
): Promise<KeyRequest> {
  const normalizedMessage = message?.trim() || null
  if (
    normalizedMessage &&
    Array.from(normalizedMessage).length > KEY_REQUEST_MESSAGE_MAX_LENGTH
  ) {
    throw new ApiError(
      `申请留言不能超过 ${KEY_REQUEST_MESSAGE_MAX_LENGTH} 字`,
      400,
    )
  }
  const body = await request<unknown>('/api/v1/me/key-requests', {
    method: 'POST',
    body: JSON.stringify({ message: normalizedMessage }),
  })
  const keyRequest = decodeNullableKeyRequest(body, username)
  if (!keyRequest) {
    throw new ApiError('服务器没有返回密钥申请', 502)
  }
  return keyRequest
}

export async function rotateMyKey(): Promise<void> {
  await request<unknown>('/api/v1/me/rotate-key', {
    method: 'POST',
  })
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
  return decodeManagedUser(root.user ?? root.managed_user ?? body)
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
  const root = asRecord(body)
  return decodeManagedUser(root?.user ?? root?.managed_user ?? body)
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

export async function rejectKeyRequest(
  requestId: string,
): Promise<void> {
  await request<unknown>(
    `/api/v1/admin/key-requests/${encodeURIComponent(requestId)}/reject`,
    { method: 'POST' },
  )
}

export async function getAccessLogSettings(): Promise<AccessLogSettings> {
  const body = await request<unknown>(
    '/api/v1/admin/access-log-settings',
  )
  return decodeAccessLogSettings(body)
}

export async function updateAccessLogSettings(
  retentionDays: number,
): Promise<AccessLogSettings> {
  const body = await request<unknown>(
    '/api/v1/admin/access-log-settings',
    {
      method: 'PATCH',
      body: JSON.stringify({ retention_days: retentionDays }),
    },
  )
  return decodeAccessLogSettings(body, retentionDays)
}
