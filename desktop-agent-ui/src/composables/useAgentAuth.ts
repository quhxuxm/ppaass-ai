import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AgentAuthAccount,
  AgentAuthPhase,
  AgentAuthState,
  AgentLoginRequest
} from "../types";

const EXPIRED_ACCOUNT_MESSAGE =
  "Proxy 已确认账号已过期；登录状态和本机凭据已保留，Agent 将自动重试";
const DISABLED_ACCOUNT_MESSAGE =
  "Proxy 已确认账号已停用；登录状态和本机凭据已保留，Agent 将自动重试";

export function useAgentAuth() {
  const phase = ref<AgentAuthPhase>("checking");
  const error = ref("");
  const accountManagementLoading = ref(false);
  const keyRotationLoading = ref(false);
  const auth = reactive<AgentAuthState>(emptyAuthState());
  let unlistenAuthStatus: UnlistenFn | null = null;
  let unlistenAuthState: UnlistenFn | null = null;

  const account = computed<AgentAuthAccount | null>(() => auth.account);
  const authenticated = computed(() => auth.authenticated && auth.account !== null);
  const checking = computed(() => phase.value === "checking");
  const loggingIn = computed(() => phase.value === "authenticating");
  const loggingOut = computed(() => phase.value === "logging-out");

  onMounted(() => {
    void listen<AgentAuthState>("agent-auth-state-updated", (event) => {
      applyAuthState(event.payload);
      phase.value = authenticated.value ? "authenticated" : "anonymous";
    }).then((unlisten) => {
      unlistenAuthState = unlisten;
    });
    void listen<string>("agent-auth-status", (event) => {
      const status =
        event.payload === "user_disabled"
          ? "disabled"
          : event.payload === "user_expired"
            ? "expired"
            : "active";
      auth.account_status = status;
      applyAccountStatusMessage(status);
    })
      .then((unlisten) => {
        unlistenAuthStatus = unlisten;
      })
      .finally(() => {
        void refresh();
      });
  });

  onBeforeUnmount(() => {
    unlistenAuthStatus?.();
    unlistenAuthStatus = null;
    unlistenAuthState?.();
    unlistenAuthState = null;
  });

  async function refresh() {
    phase.value = "checking";
    error.value = "";
    try {
      applyAuthState(await invoke<AgentAuthState>("get_agent_auth_state"));
      phase.value = authenticated.value ? "authenticated" : "anonymous";
    } catch (reason) {
      // 普通刷新失败（例如配置文件暂时不可读或后端 IPC 抖动）不具备注销
      // 已认证会话的权威性。保留当前账号和状态，只有显式退出才清理它们。
      phase.value = authenticated.value ? "authenticated" : "anonymous";
      error.value = authErrorMessage(reason, "无法检查 Agent 登录状态");
    }
  }

  async function login(request: AgentLoginRequest) {
    if (loggingIn.value || loggingOut.value) {
      return false;
    }

    phase.value = "authenticating";
    error.value = "";
    try {
      const next = await invoke<AgentAuthState>("login_and_provision_agent", {
        request: {
          username: request.username.trim(),
          password: request.password
        }
      });
      applyAuthState(next);
      if (!authenticated.value) {
        throw new Error("Proxy Web 未建立有效的 Agent 登录会话");
      }
      phase.value = "authenticated";
      return true;
    } catch (reason) {
      resetSession();
      phase.value = "anonymous";
      error.value = authErrorMessage(reason, "登录或应用 Agent 凭据失败");
      return false;
    }
  }

  async function openAccountManagement() {
    if (accountManagementLoading.value || loggingIn.value || loggingOut.value) {
      return;
    }

    accountManagementLoading.value = true;
    error.value = "";
    try {
      await invoke("open_user_account_management");
    } catch (reason) {
      error.value = authErrorMessage(reason, "无法打开注册和账户管理页面");
    } finally {
      accountManagementLoading.value = false;
    }
  }

  async function rotateKey(password: string) {
    if (keyRotationLoading.value || loggingIn.value || loggingOut.value) {
      return false;
    }
    keyRotationLoading.value = true;
    error.value = "";
    try {
      const next = await invoke<AgentAuthState>("rotate_agent_key", {
        request: { password }
      });
      applyAuthState(next);
      phase.value = "authenticated";
      return true;
    } catch (reason) {
      const message = authErrorMessage(reason, "生成和应用新密钥失败");
      try {
        applyAuthState(await invoke<AgentAuthState>("get_agent_auth_state"));
      } catch {
        // 密钥可能已经在服务端完成轮换；刷新失败时仍保留当前本机会话。
      }
      phase.value = authenticated.value ? "authenticated" : "anonymous";
      error.value = message;
      return false;
    } finally {
      keyRotationLoading.value = false;
    }
  }

  async function logout() {
    if (!authenticated.value || loggingOut.value) {
      return;
    }

    phase.value = "logging-out";
    error.value = "";
    try {
      const next = await invoke<AgentAuthState>("logout_agent");
      applyAuthState(next);
      if (authenticated.value) {
        throw new Error("Agent 退出后仍返回了已登录状态");
      }
      phase.value = "anonymous";
    } catch (reason) {
      phase.value = "authenticated";
      error.value = authErrorMessage(reason, "退出 Agent 失败");
    }
  }

  function applyAuthState(next: AgentAuthState) {
    const previousSyncError = auth.permission_sync_error;
    auth.authenticated = Boolean(next.authenticated);
    auth.account = next.account ?? null;
    auth.account_status = next.account_status ?? null;
    auth.permission_sync_error = next.permission_sync_error ?? null;
    auth.config = next.config ?? null;
    applyAccountStatusMessage(auth.account_status);
    if (
      previousSyncError &&
      !auth.permission_sync_error &&
      error.value === previousSyncError
    ) {
      error.value = "";
    }
  }

  function resetSession() {
    auth.authenticated = false;
    auth.account = null;
    auth.account_status = null;
    auth.permission_sync_error = null;
    auth.config = null;
  }

  function applyAccountStatusMessage(
    status: AgentAuthState["account_status"] | "active"
  ) {
    if (auth.permission_sync_error) {
      error.value = auth.permission_sync_error;
    } else if (status === "expired") {
      error.value = EXPIRED_ACCOUNT_MESSAGE;
    } else if (status === "disabled") {
      error.value = DISABLED_ACCOUNT_MESSAGE;
    } else if (
      [EXPIRED_ACCOUNT_MESSAGE, DISABLED_ACCOUNT_MESSAGE].includes(error.value)
    ) {
      error.value = "";
    }
  }

  return {
    account,
    accountManagementLoading,
    auth,
    authenticated,
    checking,
    clearError: () => {
      error.value = "";
    },
    error,
    keyRotationLoading,
    login,
    loggingIn,
    loggingOut,
    logout,
    openAccountManagement,
    phase,
    refresh,
    rotateKey,
  };
}

function emptyAuthState(): AgentAuthState {
  return {
    authenticated: false,
    account: null,
    account_status: null,
    permission_sync_error: null,
    config: null
  };
}

function authErrorMessage(reason: unknown, fallback: string) {
  if (reason instanceof Error && reason.message.trim()) {
    return reason.message;
  }
  if (typeof reason === "string" && reason.trim()) {
    return reason;
  }
  if (reason && typeof reason === "object") {
    const record = reason as Record<string, unknown>;
    for (const key of ["message", "detail", "error"]) {
      const value = record[key];
      if (typeof value === "string" && value.trim()) {
        return value;
      }
    }
  }
  return fallback;
}
