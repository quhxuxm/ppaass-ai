import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import {
  deviceLoginRemainingSeconds,
  devicePollDelayMilliseconds
} from "../deviceLogin";
import type {
  AgentAuthAccount,
  AgentAuthPhase,
  AgentAuthState,
  AgentDeviceLoginProgress,
  AgentDeviceLoginViewState,
  AgentLoginRequest
} from "../types";

export function useAgentAuth() {
  const phase = ref<AgentAuthPhase>("checking");
  const error = ref("");
  const registrationLoading = ref(false);
  const deviceLogin = ref<AgentDeviceLoginViewState | null>(null);
  const deviceLoginRemaining = ref(0);
  const auth = reactive<AgentAuthState>(emptyAuthState());
  let deviceLoginGeneration = 0;
  let devicePollTimer: ReturnType<typeof setTimeout> | null = null;
  let deviceCountdownTimer: ReturnType<typeof setInterval> | null = null;

  const account = computed<AgentAuthAccount | null>(() => auth.account);
  const authenticated = computed(() => auth.authenticated && auth.account !== null);
  const checking = computed(() => phase.value === "checking");
  const loggingIn = computed(() => phase.value === "authenticating");
  const deviceLoginStarting = computed(
    () => phase.value === "starting-device-login"
  );
  const deviceLoginActive = computed(
    () =>
      phase.value === "starting-device-login" ||
      phase.value === "device-authorizing"
  );
  const loggingOut = computed(() => phase.value === "logging-out");

  onMounted(() => {
    void refresh();
  });

  onBeforeUnmount(() => {
    const shouldCancel = deviceLoginActive.value;
    deviceLoginGeneration += 1;
    clearDeviceLoginTimers();
    if (shouldCancel) {
      void invoke("cancel_agent_device_login");
    }
  });

  async function refresh() {
    phase.value = "checking";
    error.value = "";
    try {
      applyAuthState(await invoke<AgentAuthState>("get_agent_auth_state"));
      phase.value = authenticated.value ? "authenticated" : "anonymous";
    } catch (reason) {
      resetSession();
      phase.value = "anonymous";
      error.value = authErrorMessage(reason, "无法检查 Agent 登录状态");
    }
  }

  async function login(request: AgentLoginRequest) {
    if (loggingIn.value || deviceLoginActive.value || loggingOut.value) {
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

  async function startDeviceLogin() {
    if (loggingIn.value || deviceLoginActive.value || loggingOut.value) {
      return false;
    }

    const generation = ++deviceLoginGeneration;
    clearDeviceLoginTimers();
    deviceLogin.value = null;
    deviceLoginRemaining.value = 0;
    phase.value = "starting-device-login";
    error.value = "";
    try {
      const next = await invoke<AgentDeviceLoginProgress>(
        "start_agent_device_login"
      );
      if (generation !== deviceLoginGeneration) {
        void invoke("cancel_agent_device_login");
        return false;
      }
      requirePendingDeviceLogin(next);
      deviceLogin.value = { ...next };
      updateDeviceLoginRemaining();
      if (deviceLoginRemaining.value === 0) {
        throw new Error("设备登录已过期，请重新开始");
      }
      phase.value = "device-authorizing";
      startDeviceLoginCountdown(generation);
      scheduleDeviceLoginPoll(generation, next.retry_after_seconds);
      return true;
    } catch (reason) {
      if (generation !== deviceLoginGeneration) {
        return false;
      }
      clearDeviceLoginState();
      phase.value = "anonymous";
      error.value = authErrorMessage(reason, "无法开始浏览器设备登录");
      void invoke("cancel_agent_device_login");
      return false;
    }
  }

  async function cancelDeviceLogin() {
    if (!deviceLoginActive.value) {
      return;
    }
    deviceLoginGeneration += 1;
    clearDeviceLoginTimers();
    clearDeviceLoginState();
    phase.value = "anonymous";
    error.value = "";
    try {
      await invoke("cancel_agent_device_login");
    } catch (reason) {
      error.value = authErrorMessage(reason, "取消设备登录失败");
    }
  }

  async function pollDeviceLogin(generation: number) {
    if (
      generation !== deviceLoginGeneration ||
      phase.value !== "device-authorizing" ||
      !deviceLogin.value
    ) {
      return;
    }
    try {
      const next = await invoke<AgentDeviceLoginProgress>(
        "poll_agent_device_login"
      );
      if (generation !== deviceLoginGeneration) {
        return;
      }
      if (next.status === "authenticated") {
        if (!next.auth_state) {
          throw new Error("认证服务没有返回 Agent 登录状态");
        }
        applyAuthState(next.auth_state);
        if (!authenticated.value) {
          throw new Error("Proxy Web 未建立有效的 Agent 登录会话");
        }
        deviceLoginGeneration += 1;
        clearDeviceLoginTimers();
        clearDeviceLoginState();
        phase.value = "authenticated";
        return;
      }
      requirePendingDeviceLogin(next);
      deviceLogin.value = { ...next };
      updateDeviceLoginRemaining();
      scheduleDeviceLoginPoll(generation, next.retry_after_seconds);
    } catch (reason) {
      if (generation !== deviceLoginGeneration) {
        return;
      }
      deviceLoginGeneration += 1;
      clearDeviceLoginTimers();
      clearDeviceLoginState();
      resetSession();
      phase.value = "anonymous";
      error.value = authErrorMessage(reason, "浏览器设备登录失败");
      void invoke("cancel_agent_device_login");
    }
  }

  function scheduleDeviceLoginPoll(generation: number, seconds: number) {
    if (devicePollTimer !== null) {
      clearTimeout(devicePollTimer);
    }
    devicePollTimer = setTimeout(() => {
      devicePollTimer = null;
      void pollDeviceLogin(generation);
    }, devicePollDelayMilliseconds(seconds));
  }

  function startDeviceLoginCountdown(generation: number) {
    if (deviceCountdownTimer !== null) {
      clearInterval(deviceCountdownTimer);
    }
    deviceCountdownTimer = setInterval(() => {
      if (generation !== deviceLoginGeneration || !deviceLogin.value) {
        return;
      }
      updateDeviceLoginRemaining();
      if (deviceLoginRemaining.value === 0) {
        deviceLoginGeneration += 1;
        clearDeviceLoginTimers();
        clearDeviceLoginState();
        phase.value = "anonymous";
        error.value = "设备登录已过期，请重新开始";
        void invoke("cancel_agent_device_login");
      }
    }, 1000);
  }

  function updateDeviceLoginRemaining() {
    deviceLoginRemaining.value = deviceLogin.value
      ? deviceLoginRemainingSeconds(deviceLogin.value.expires_at)
      : 0;
  }

  function clearDeviceLoginTimers() {
    if (devicePollTimer !== null) {
      clearTimeout(devicePollTimer);
      devicePollTimer = null;
    }
    if (deviceCountdownTimer !== null) {
      clearInterval(deviceCountdownTimer);
      deviceCountdownTimer = null;
    }
  }

  function clearDeviceLoginState() {
    deviceLogin.value = null;
    deviceLoginRemaining.value = 0;
  }

  async function openRegistration() {
    if (
      registrationLoading.value ||
      loggingIn.value ||
      deviceLoginActive.value ||
      loggingOut.value
    ) {
      return;
    }

    registrationLoading.value = true;
    error.value = "";
    try {
      await invoke("open_user_registration");
    } catch (reason) {
      error.value = authErrorMessage(reason, "无法打开新用户注册页面");
    } finally {
      registrationLoading.value = false;
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
    auth.authenticated = Boolean(next.authenticated);
    auth.account = next.account ?? null;
    auth.config = next.config ?? null;
  }

  function resetSession() {
    auth.authenticated = false;
    auth.account = null;
    auth.config = null;
  }

  return {
    account,
    auth,
    authenticated,
    checking,
    cancelDeviceLogin,
    deviceLogin,
    deviceLoginActive,
    deviceLoginRemaining,
    deviceLoginStarting,
    error,
    login,
    loggingIn,
    loggingOut,
    logout,
    openRegistration,
    phase,
    refresh,
    registrationLoading,
    startDeviceLogin
  };
}

function emptyAuthState(): AgentAuthState {
  return {
    authenticated: false,
    account: null,
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

function requirePendingDeviceLogin(next: AgentDeviceLoginProgress) {
  if (
    !["authorization_pending", "slow_down"].includes(next.status) ||
    !next.user_code.trim() ||
    !Number.isFinite(next.expires_at) ||
    !Number.isFinite(next.retry_after_seconds) ||
    next.retry_after_seconds <= 0 ||
    next.auth_state !== null
  ) {
    throw new Error("Proxy Web 返回的设备登录状态无效");
  }
}
