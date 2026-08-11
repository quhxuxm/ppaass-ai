import type { AgentAuthAccount } from "./types";

export const AGENT_PERMISSION_CODES = {
  packetCapture: "agent.packet_capture",
  egressEdit: "agent.egress.edit",
  runtimeThreadsEdit: "agent.runtime_threads.edit",
  proxyEntrySelect: "agent.proxy_entry.select"
} as const;

export type AgentPermissionCode =
  (typeof AGENT_PERMISSION_CODES)[keyof typeof AGENT_PERMISSION_CODES];

export type AgentCapabilities = {
  canCapturePackets: boolean;
  canViewRawConfig: boolean;
  canEditEgress: boolean;
  canEditRuntimeThreads: boolean;
  canSelectProxyEntry: boolean;
};

export function hasAgentPermission(
  account: Pick<AgentAuthAccount, "role" | "permissions">,
  permission: AgentPermissionCode
) {
  return (
    account.role === "admin" ||
    (Array.isArray(account.permissions) &&
      account.permissions.includes(permission))
  );
}

export function resolveAgentCapabilities(
  account: Pick<AgentAuthAccount, "role" | "permissions">
): AgentCapabilities {
  return {
    canCapturePackets: hasAgentPermission(
      account,
      AGENT_PERMISSION_CODES.packetCapture
    ),
    // 原始 TOML 不是可分配的普通用户功能，只对管理员开放。
    canViewRawConfig: account.role === "admin",
    canEditEgress: hasAgentPermission(
      account,
      AGENT_PERMISSION_CODES.egressEdit
    ),
    canEditRuntimeThreads: hasAgentPermission(
      account,
      AGENT_PERMISSION_CODES.runtimeThreadsEdit
    ),
    canSelectProxyEntry: hasAgentPermission(
      account,
      AGENT_PERMISSION_CODES.proxyEntrySelect
    )
  };
}
