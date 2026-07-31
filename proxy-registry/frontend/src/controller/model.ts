import type { KeyRequest, ManagedUser } from '../api'

export type AuthMode = 'login' | 'register'
export type AppPage = 'account' | 'admin'
export type AdminSection = 'users' | 'approvals' | 'proxies' | 'audit'

export interface PermissionOption {
  code: string
  label: string
  description: string
}

export const PASSWORD_MIN_CHARACTERS = 8
export const AGENT_AUTHORIZATION_STORAGE_KEY = 'ppaass-agent-authorization'

export function requestedAuthMode(): AuthMode {
  return new URLSearchParams(window.location.search).get('mode') === 'register'
    ? 'register'
    : 'login'
}

export const basePermissionOptions: PermissionOption[] = [
  {
    code: 'proxy.connect.tcp',
    label: 'TCP 代理',
    description: '允许建立 TCP 隧道',
  },
  {
    code: 'proxy.connect.udp',
    label: 'UDP 代理',
    description: '允许建立 UDP 隧道',
  },
  {
    code: 'key.private.read',
    label: 'Agent 凭据领取',
    description: '允许本人授权的 Agent 安全领取连接凭据',
  },
  {
    code: 'key.rotate',
    label: '更新密钥',
    description: '允许用户重新生成密钥对',
  },
]

export const basePermissionCodes = new Set(
  basePermissionOptions.map((permission) => permission.code),
)

export const agentPermissionOptions: PermissionOption[] = [
  {
    code: 'agent.packet_capture',
    label: '抓包',
    description: '允许使用抓包页面；无权限时 Agent 不显示抓包功能',
  },
  {
    code: 'agent.egress.edit',
    label: '修改出口配置',
    description: '允许显示并修改出口；无权限时隐藏出口并使用内置默认值',
  },
  {
    code: 'agent.runtime_threads.edit',
    label: '修改系统运行参数',
    description: '允许显示并修改运行参数；无权限时隐藏面板并使用内置默认值',
  },
]

export const allAgentPermissionCodes = agentPermissionOptions.map(
  (permission) => permission.code,
)
export const agentPermissionCodes = new Set(allAgentPermissionCodes)
export const retiredPermissionCodes = new Set(['agent.config.view'])
export const roleOptions = [
  { label: '普通用户', value: 'user' },
  { label: '管理员', value: 'admin' },
]
export const statusOptions = [
  { label: '启用账号（允许登录）', value: 'active' },
  { label: '停用账号（禁止登录）', value: 'disabled' },
]

export function managedUsername(user: ManagedUser): string {
  return (
    user.profile?.username ??
    user.account?.linkedUsername ??
    user.account?.username ??
    '未知用户'
  )
}

export function isRootAdmin(user: ManagedUser | null): boolean {
  return user?.account?.username === 'admin'
}

export function deleteBlockedReason(user: ManagedUser): string | null {
  if (isRootAdmin(user)) return '根管理员 admin 不能停用、降级或删除'
  if (user.account) {
    return user.account.status === 'disabled' ? null : '请先停用账号'
  }
  if (user.profile?.origin === 'legacy') {
    return user.profile.enabled ? '请先暂停代理连接' : null
  }
  return '该用户没有可删除的 Web 账号或 legacy 配置'
}

export function accountStatusLabel(user: ManagedUser): string {
  if (!user.account) return '无 Web 账号'
  return user.account.status === 'active' ? '账号已启用' : '账号已停用'
}

export function canAdminRotateDirectly(user: ManagedUser): boolean {
  return (
    Boolean(user.profile) &&
    user.profile?.origin !== 'legacy' &&
    user.keyState === 'active'
  )
}

export function keyRequestKindLabel(request: KeyRequest): string {
  return request.kind === 'rotate' ? '过期重生成' : '首次申请'
}

export function managedAgentPermissions(user: ManagedUser): PermissionOption[] {
  const permissions = new Set(user.profile?.permissions ?? [])
  return agentPermissionOptions.filter((permission) =>
    permissions.has(permission.code),
  )
}

export function managedCustomPermissions(user: ManagedUser): string[] {
  return (user.profile?.permissions ?? []).filter(
    (permission) =>
      !basePermissionCodes.has(permission) &&
      !agentPermissionCodes.has(permission) &&
      !retiredPermissionCodes.has(permission),
  )
}

export function managedPermissionsTitle(user: ManagedUser): string {
  if (user.account?.role === 'admin') return '管理员拥有全部 Agent 权限'
  const permissions = [
    ...managedAgentPermissions(user).map((permission) => permission.label),
    ...managedCustomPermissions(user),
  ]
  return permissions.length
    ? permissions.join('、')
    : '仅包含固定授予的 Agent 基础功能'
}

export function managedHiddenPermissionCount(user: ManagedUser): number {
  const visible = Math.min(managedAgentPermissions(user).length, 2)
  return Math.max(
    0,
    managedAgentPermissions(user).length +
      managedCustomPermissions(user).length -
      visible,
  )
}

export function managedProxyAddressesTitle(user: ManagedUser): string {
  return user.proxyAddresses
    .map((address) => `${address.label}（${address.address}）`)
    .join('\n')
}

export function parseDate(value: string | null): Date | null {
  if (!value) return null
  if (/^-?\d+$/.test(value)) {
    const numeric = Number(value)
    const milliseconds =
      Math.abs(numeric) < 100_000_000_000 ? numeric * 1000 : numeric
    const date = new Date(milliseconds)
    return Number.isNaN(date.getTime()) ? null : date
  }
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

export function isExpired(
  value: string | null,
  now = Date.now(),
): boolean {
  const date = parseDate(value)
  return date !== null && date.getTime() <= now
}

export function formatExpiry(value: string | null | undefined): string {
  if (!value) return '永久有效'
  const date = parseDate(value)
  if (!date) return value
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date)
}

export function defaultExpiry(): Date {
  const value = new Date()
  value.setFullYear(value.getFullYear() + 1)
  value.setSeconds(0, 0)
  return value
}

export function minimumFutureExpiry(): Date {
  return new Date(Date.now() + 60_000)
}

export function restoreAgentAuthorization(): {
  active: boolean
  code: string
} {
  const hash = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash
  if (hash === 'agent-authorize') return { active: true, code: '' }
  if (hash.startsWith('agent-authorize=')) {
    const code = decodeURIComponent(hash.slice('agent-authorize='.length)).trim()
    storeAgentAuthorization(code)
    return { active: true, code }
  }
  try {
    const stored = window.sessionStorage.getItem(
      AGENT_AUTHORIZATION_STORAGE_KEY,
    )
    if (stored) {
      const value = JSON.parse(stored) as {
        active?: unknown
        code?: unknown
      }
      if (value.active === true) {
        return {
          active: true,
          code: typeof value.code === 'string' ? value.code : '',
        }
      }
    }
  } catch {
    // 忽略损坏或不可用的浏览器临时存储。
  }
  return { active: false, code: '' }
}

export function storeAgentAuthorization(code: string): void {
  try {
    window.sessionStorage.setItem(
      AGENT_AUTHORIZATION_STORAGE_KEY,
      JSON.stringify({ active: true, code }),
    )
  } catch {
    // 页面当前生命周期内仍会保留授权状态。
  }
}

export function clearStoredAgentAuthorization(): void {
  try {
    window.sessionStorage.removeItem(AGENT_AUTHORIZATION_STORAGE_KEY)
  } catch {
    // 无需阻止用户离开授权页面。
  }
}

export function clearAgentAuthorizationLocation(): void {
  window.history.replaceState(
    {},
    document.title,
    `${window.location.pathname}${window.location.search}`,
  )
}
