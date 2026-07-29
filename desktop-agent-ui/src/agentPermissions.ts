import type { AgentAuthAccount } from "./types";

export const AGENT_PERMISSION_CODES = {
  packetCapture: "agent.packet_capture",
  configView: "agent.config.view",
  egressEdit: "agent.egress.edit",
  runtimeThreadsEdit: "agent.runtime_threads.edit"
} as const;

export type AgentPermissionCode =
  (typeof AGENT_PERMISSION_CODES)[keyof typeof AGENT_PERMISSION_CODES];

export type AgentCapabilities = {
  canCapturePackets: boolean;
  canViewRawConfig: boolean;
  canEditEgress: boolean;
  canEditRuntimeThreads: boolean;
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
    canViewRawConfig: hasAgentPermission(
      account,
      AGENT_PERMISSION_CODES.configView
    ),
    canEditEgress: hasAgentPermission(
      account,
      AGENT_PERMISSION_CODES.egressEdit
    ),
    canEditRuntimeThreads: hasAgentPermission(
      account,
      AGENT_PERMISSION_CODES.runtimeThreadsEdit
    )
  };
}
