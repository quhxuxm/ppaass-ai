import type { AuditAction, AuditEvent } from '../types'
import { ApiError } from '../types'
import { asRecord, nullableString, numberValue, stringValue } from '../values'

const actions = new Set<AuditAction>([
  'key_request_approved',
  'key_request_rejected',
  'key_regenerated',
  'proxy_access_enabled',
  'proxy_access_disabled',
  'web_login_enabled',
  'web_login_disabled',
  'proxy_server_enabled',
  'proxy_server_disabled',
  'permissions_updated',
])

export function decodeAuditEvent(value: unknown): AuditEvent {
  const root = asRecord(value)
  const action = stringValue(root?.action) as AuditAction | undefined
  const targetKind = stringValue(root?.target_kind)
  const createdAt = numberValue(root?.created_at)
  if (
    !root ||
    !action ||
    !actions.has(action) ||
    (targetKind !== 'user' && targetKind !== 'proxy_server') ||
    createdAt === undefined
  ) {
    throw new ApiError('服务器返回的审计记录格式无效', 502)
  }
  const id = numberValue(root.audit_id)
  const actorAccountId = stringValue(root.actor_account_id)
  const actorLoginName = stringValue(root.actor_login_name)
  const targetId = stringValue(root.target_id)
  const targetName = stringValue(root.target_name)
  if (
    id === undefined ||
    !actorAccountId ||
    !actorLoginName ||
    !targetId ||
    !targetName
  ) {
    throw new ApiError('服务器返回的审计记录字段不完整', 502)
  }
  return {
    id,
    action,
    actorAccountId,
    actorLoginName,
    targetKind,
    targetId,
    targetName,
    contextId: nullableString(root.context_id) ?? null,
    reason: nullableString(root.reason) ?? null,
    previousValue: nullableString(root.previous_value) ?? null,
    newValue: nullableString(root.new_value) ?? null,
    createdAt: new Date(createdAt * 1000).toISOString(),
  }
}
