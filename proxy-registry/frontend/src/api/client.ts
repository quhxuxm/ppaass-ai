import { decodeAccessRecord } from './decoders/access'
import { decodeNullableKeyRequest } from './decoders/keys'
import {
  decodeAgentDeviceAuthorization,
  decodeSession,
} from './decoders/session'
import { decodeSelf } from './decoders/users'
import { clearClientSession, request } from './transport'
import {
  ApiError,
  KEY_REQUEST_MESSAGE_MAX_LENGTH,
} from './types'
import type {
  AccessRecordsResult,
  AgentDeviceAuthorizationInspection,
  ChangePasswordPayload,
  KeyRequest,
  ProviderAvailability,
  RegisterPayload,
  SelfView,
  SessionState,
  UpdateMyProfilePayload,
} from './types'
import { asRecord, boolValue, numberValue } from './values'

export { clearClientSession }
export * from './adminClient'

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

export async function updateMyProfile(
  payload: UpdateMyProfilePayload,
): Promise<void> {
  await request<unknown>('/api/v1/me/profile', {
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

export async function rotateMyKey(reason?: string): Promise<void> {
  await request<unknown>('/api/v1/me/rotate-key', {
    method: 'POST',
    ...(reason
      ? { body: JSON.stringify({ reason: reason.trim() }) }
      : {}),
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
