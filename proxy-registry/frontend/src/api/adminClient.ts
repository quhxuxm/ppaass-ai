import { decodeAccessLogSettings } from './decoders/access'
import { decodeAuditEvent } from './decoders/audits'
import { decodeKeyRequest } from './decoders/keys'
import { decodeProxyAddress } from './decoders/proxyAddresses'
import { decodeManagedUser } from './decoders/users'
import { request } from './transport'
import {
  ApiError,
  KEY_REQUEST_REJECTION_REASON_MAX_LENGTH,
} from './types'
import type {
  AccessLogSettings,
  AuditEventQuery,
  AuditEventsPage,
  CreateManagedUserPayload,
  CreateProxyAddressPayload,
  KeyRequest,
  ManagedUser,
  ProxyAddress,
  UpdateManagedUserPayload,
  UpdateProxyAddressPayload,
} from './types'
import { asRecord } from './values'

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
  reason: string,
): Promise<ManagedUser> {
  const body = await request<unknown>(
    `/api/v1/admin/users/${encodeURIComponent(username)}/rotate-key`,
    { method: 'POST', body: JSON.stringify({ reason }) },
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
  proxyAddressIds: string[],
  reason: string,
): Promise<void> {
  await request<unknown>(
    `/api/v1/admin/key-requests/${encodeURIComponent(requestId)}/approve`,
    {
      method: 'POST',
      body: JSON.stringify({
        expires_at: expiresAt,
        proxy_address_ids: proxyAddressIds,
        reason,
      }),
    },
  )
}

export async function rejectKeyRequest(
  requestId: string,
  reason: string | null = null,
): Promise<void> {
  const normalizedReason = reason?.trim() || null
  if (
    normalizedReason &&
    Array.from(normalizedReason).length >
      KEY_REQUEST_REJECTION_REASON_MAX_LENGTH
  ) {
    throw new ApiError(
      `拒绝理由不能超过 ${KEY_REQUEST_REJECTION_REASON_MAX_LENGTH} 字`,
      400,
    )
  }
  await request<unknown>(
    `/api/v1/admin/key-requests/${encodeURIComponent(requestId)}/reject`,
    {
      method: 'POST',
      body: JSON.stringify({ reason: normalizedReason }),
    },
  )
}

export async function getAccessLogSettings(): Promise<AccessLogSettings> {
  return decodeAccessLogSettings(
    await request<unknown>('/api/v1/admin/access-log-settings'),
  )
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

export async function listProxyAddresses(): Promise<ProxyAddress[]> {
  const body = await request<unknown>('/api/v1/admin/proxy-addresses')
  const root = asRecord(body)
  const values = Array.isArray(root?.proxy_addresses)
    ? root.proxy_addresses
    : Array.isArray(body)
      ? body
      : null
  if (!values) {
    throw new ApiError('服务器返回的 Proxy 地址目录格式无效', 502)
  }
  return values.map(decodeProxyAddress)
}

export async function listAuditEvents(
  query: AuditEventQuery = {},
): Promise<AuditEventsPage> {
  const limit = Math.min(100, Math.max(1, query.limit ?? 50))
  const params = new URLSearchParams({ limit: String(limit) })
  if (query.beforeId) params.set('before_audit_id', String(query.beforeId))
  if (query.action) params.set('action', query.action)
  const search = query.search?.trim()
  if (search) params.set('search', search)
  const body = await request<unknown>(
    `/api/v1/admin/audit-events?${params.toString()}`,
  )
  const root = asRecord(body)
  const values = Array.isArray(root?.events) ? root.events : null
  if (!values) {
    throw new ApiError('服务器返回的审计记录列表格式无效', 502)
  }
  const events = values.map(decodeAuditEvent)
  return { events, hasMore: events.length >= limit }
}

export async function createProxyAddress(
  payload: CreateProxyAddressPayload,
): Promise<ProxyAddress> {
  return decodeProxyAddress(
    await request<unknown>('/api/v1/admin/proxy-addresses', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  )
}

export async function updateProxyAddress(
  id: string,
  payload: UpdateProxyAddressPayload,
): Promise<ProxyAddress> {
  return decodeProxyAddress(
    await request<unknown>(
      `/api/v1/admin/proxy-addresses/${encodeURIComponent(id)}`,
      { method: 'PATCH', body: JSON.stringify(payload) },
    ),
  )
}

export function deleteProxyAddress(id: string): Promise<void> {
  return request<void>(
    `/api/v1/admin/proxy-addresses/${encodeURIComponent(id)}`,
    { method: 'DELETE' },
  )
}
