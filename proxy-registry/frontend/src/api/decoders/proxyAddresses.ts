import { ApiError, type ProxyAddress } from '../types'
import { asRecord, boolValue, numberValue, stringValue } from '../values'

export function decodeProxyAddress(value: unknown): ProxyAddress {
  const root = asRecord(value)
  const id =
    stringValue(root?.proxy_address_id) ??
    stringValue(root?.proxyAddressId) ??
    stringValue(root?.id)
  const address = stringValue(root?.address)
  if (!id || !address) {
    throw new ApiError('服务器返回的 Proxy 地址格式无效', 502)
  }
  return {
    id,
    address,
    label: stringValue(root?.label) ?? address,
    enabled: boolValue(root?.enabled) ?? true,
    entryId:
      stringValue(root?.entry_id) ?? stringValue(root?.entryId) ?? null,
    entryVersion:
      stringValue(root?.entry_version) ??
      stringValue(root?.entryVersion) ??
      null,
    entryFirstRegisteredAt:
      numberValue(root?.entry_first_registered_at) ??
      numberValue(root?.entryFirstRegisteredAt) ??
      null,
    entryLastHeartbeatAt:
      numberValue(root?.entry_last_heartbeat_at) ??
      numberValue(root?.entryLastHeartbeatAt) ??
      null,
    entryOnline:
      boolValue(root?.entry_online) ?? boolValue(root?.entryOnline) ?? null,
  }
}
