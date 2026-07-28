<script setup lang="ts">
import ProgressSpinner from "primevue/progressspinner";
import AgentWorkspace from "./AgentWorkspace.vue";
import ToastHost from "./components/ToastHost.vue";
import { useAgentAuth } from "./composables/useAgentAuth";
import LoginView from "./views/LoginView.vue";
import {
  clearRememberedAgentLogin,
  saveRememberedAgentLogin
} from "./rememberedLogin";
import type { AgentLoginRequest } from "./types";

const {
  account,
  authenticated,
  cancelDeviceLogin,
  checking,
  deviceLogin,
  deviceLoginRemaining,
  deviceLoginStarting,
  error,
  login,
  loggingIn,
  loggingOut,
  logout,
  openRegistration,
  registrationLoading,
  startDeviceLogin
} = useAgentAuth();

async function handleLogin(request: AgentLoginRequest) {
  if (!(await login(request))) {
    return;
  }
  if (request.rememberCredentials) {
    saveRememberedAgentLogin({
      username: request.username.trim(),
      password: request.password
    });
  } else {
    clearRememberedAgentLogin();
  }
}
</script>

<template>
  <main v-if="checking" class="auth-gate auth-checking" aria-live="polite">
    <div class="auth-loading-mark">
      <img src="/app-icon.png" alt="" aria-hidden="true" />
    </div>
    <ProgressSpinner />
    <strong>正在检查登录状态</strong>
    <span>准备本机 Agent 配置</span>
  </main>

  <AgentWorkspace
    v-else-if="authenticated && account"
    :account="account"
    :logout-busy="loggingOut"
    @logout="logout"
  />

  <LoginView
    v-else
    :loading="loggingIn"
    :registration-loading="registrationLoading"
    :device-login="deviceLogin"
    :device-login-remaining="deviceLoginRemaining"
    :device-login-starting="deviceLoginStarting"
    :error="error"
    @cancel-device-login="cancelDeviceLogin"
    @device-login="startDeviceLogin"
    @register="openRegistration"
    @submit="handleLogin"
  />

  <ToastHost
    v-if="authenticated"
    :toast="error ? { kind: 'error', message: error } : null"
  />
</template>
