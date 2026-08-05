import { ApiError } from '../types'
import type {
  AgentDeviceAuthorizationInspection,
  AgentDeviceAuthorizationStatus,
  SessionState,
} from '../types'
import { asRecord, boolValue, numberValue, stringValue } from '../values'
import { decodeAccount } from './users'

export function decodeSession(
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
  const agentHandoff =
    boolValue(source.agent_handoff) ??
    boolValue(source.agentHandoff) ??
    boolValue(root.agent_handoff) ??
    boolValue(root.agentHandoff) ??
    false
  const registryInstanceId =
    stringValue(source.registry_instance_id) ??
    stringValue(source.registryInstanceId) ??
    stringValue(root.registry_instance_id) ??
    stringValue(root.registryInstanceId) ??
    'unknown'

  return { registryInstanceId, authenticated, account, agentHandoff }
}

export function decodeAgentDeviceAuthorization(
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
  return { clientName, platform, expiresAt, status }
}
