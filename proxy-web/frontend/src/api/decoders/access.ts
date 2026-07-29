import { ApiError } from '../types'
import type { AccessLogSettings, AccessRecord } from '../types'
import {
  asRecord,
  identifierValue,
  nullableTimestamp,
  numberValue,
  stringValue,
} from '../values'

export function decodeAccessRecord(value: unknown): AccessRecord {
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

export function decodeAccessLogSettings(
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
