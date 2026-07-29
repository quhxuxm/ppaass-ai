import { ApiError, type ProxyAddress } from '../types'
import { asRecord, boolValue, stringValue } from '../values'

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
  }
}
