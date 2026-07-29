import { ApiError } from '../types'
import type {
  KeyRequest,
  KeyRequestStatus,
  KeyState,
  ProfileSummary,
} from '../types'
import {
  asRecord,
  boolValue,
  identifierValue,
  nullableString,
  nullableTimestamp,
  stringValue,
} from '../values'

export function decodeNullableKeyRequest(
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

export function decodeKeyRequest(
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
    requestMessage:
      nullableString(root.request_message) ??
      nullableString(root.requestMessage) ??
      null,
    displayName:
      nullableString(root.display_name) ??
      nullableString(root.displayName) ??
      nullableString(account?.display_name),
    email: nullableString(root.email) ?? nullableString(account?.email),
  }
}

export function decodeKeyState(
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
