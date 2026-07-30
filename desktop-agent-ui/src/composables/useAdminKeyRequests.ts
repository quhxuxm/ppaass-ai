import {
  computed,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
  type ComputedRef
} from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AgentAdminKeyRequestApproval,
  AgentAdminKeyRequestInbox,
  AgentAdminKeyRequestRejection,
  AgentAdminKeyRequestUpdate,
  AgentAuthAccount,
  AgentAuthState
} from "../types";

type AdminKeyRequestDependencies = {
  account: ComputedRef<AgentAuthAccount | null>;
  accountStatus: ComputedRef<AgentAuthState["account_status"]>;
};

const emptyInbox = (): AgentAdminKeyRequestInbox => ({
  requests: [],
  proxy_addresses: []
});

export function useAdminKeyRequests(
  dependencies: AdminKeyRequestDependencies
) {
  const inbox = ref<AgentAdminKeyRequestInbox>(emptyInbox());
  const loading = ref(false);
  const busyRequestId = ref<string | null>(null);
  const error = ref("");
  const notice = ref("");
  const canManage = computed(
    () =>
      dependencies.account.value?.role === "admin" &&
      dependencies.accountStatus.value === "active"
  );
  let knownRequestIds = new Set<string>();
  let unlisten: UnlistenFn | null = null;
  let listenerReady = false;
  let noticeTimer: number | null = null;

  onMounted(async () => {
    unlisten = await listen<AgentAdminKeyRequestUpdate>(
      "agent-admin-key-requests-updated",
      (event) => applyUpdate(event.payload)
    );
    listenerReady = true;
    if (canManage.value) {
      await refresh();
    }
  });

  onBeforeUnmount(() => {
    unlisten?.();
    unlisten = null;
    if (noticeTimer !== null) {
      window.clearTimeout(noticeTimer);
    }
  });

  watch(canManage, (active) => {
    if (!active) {
      reset();
    } else if (listenerReady) {
      void refresh();
    }
  });

  async function refresh() {
    if (!canManage.value || loading.value) {
      return false;
    }
    loading.value = true;
    error.value = "";
    try {
      applyInbox(
        await invoke<AgentAdminKeyRequestInbox>(
          "refresh_agent_admin_key_requests"
        )
      );
      return true;
    } catch (reason) {
      error.value = errorMessage(reason, "无法刷新密钥申请");
      await loadCachedInbox();
      return false;
    } finally {
      loading.value = false;
    }
  }

  async function approve(request: AgentAdminKeyRequestApproval) {
    return decide(
      request.requestId,
      "approve_agent_admin_key_request_command",
      { request },
      "密钥申请已批准"
    );
  }

  async function reject(request: AgentAdminKeyRequestRejection) {
    return decide(
      request.requestId,
      "reject_agent_admin_key_request_command",
      { request },
      "密钥申请已拒绝"
    );
  }

  async function decide(
    requestId: string,
    command: string,
    args: Record<string, unknown>,
    successMessage: string
  ) {
    if (!canManage.value || busyRequestId.value) {
      return false;
    }
    busyRequestId.value = requestId;
    error.value = "";
    try {
      applyInbox(
        await invoke<AgentAdminKeyRequestInbox>(command, args),
        false
      );
      showNotice(successMessage);
      return true;
    } catch (reason) {
      error.value = errorMessage(reason, "处理密钥申请失败");
      await loadCachedInbox();
      return false;
    } finally {
      busyRequestId.value = null;
    }
  }

  async function loadCachedInbox() {
    if (!canManage.value) {
      return;
    }
    try {
      applyInbox(
        await invoke<AgentAdminKeyRequestInbox>(
          "get_agent_admin_key_request_inbox"
        ),
        false
      );
    } catch {
      // 保留最近一次成功同步的列表；后台轮询会继续重试。
    }
  }

  function applyUpdate(update: AgentAdminKeyRequestUpdate) {
    if (!canManage.value) {
      reset();
      return;
    }
    applyInbox(update.inbox);
    error.value = update.error ?? "";
  }

  function applyInbox(
    next: AgentAdminKeyRequestInbox,
    notifyNew = true
  ) {
    const nextIds = new Set(
      next.requests.map((request) => request.request_id)
    );
    const newCount = notifyNew
      ? [...nextIds].filter((requestId) => !knownRequestIds.has(requestId))
          .length
      : 0;
    knownRequestIds = nextIds;
    inbox.value = next;
    if (newCount > 0) {
      showNotice(`收到 ${newCount} 个新的待审批密钥申请`);
    }
  }

  function showNotice(message: string) {
    notice.value = message;
    if (noticeTimer !== null) {
      window.clearTimeout(noticeTimer);
    }
    noticeTimer = window.setTimeout(() => {
      notice.value = "";
      noticeTimer = null;
    }, 5_000);
  }

  function reset() {
    inbox.value = emptyInbox();
    knownRequestIds.clear();
    loading.value = false;
    busyRequestId.value = null;
    error.value = "";
    notice.value = "";
  }

  return {
    approve,
    busyRequestId,
    canManage,
    error,
    inbox,
    loading,
    notice,
    refresh,
    reject
  };
}

function errorMessage(reason: unknown, fallback: string) {
  if (typeof reason === "string" && reason.trim()) {
    return reason;
  }
  if (reason instanceof Error && reason.message.trim()) {
    return reason.message;
  }
  return fallback;
}
