<script setup lang="ts">
import { computed, ref } from "vue";
import ProgressSpinner from "primevue/progressspinner";
import AgentWorkspace from "./AgentWorkspace.vue";
import RotateKeyDialog from "./components/RotateKeyDialog.vue";
import ToastHost from "./components/ToastHost.vue";
import { useAgentAuth } from "./composables/useAgentAuth";
import LoginView from "./views/LoginView.vue";
import {
  clearRememberedAgentLogin,
  loadRememberedAgentLogin,
  saveRememberedAgentLogin
} from "./rememberedLogin";
import type { AgentLoginRequest } from "./types";

const {
  account,
  accountManagementLoading,
  auth,
  authenticated,
  checking,
  clearError,
  error,
  keyRotationLoading,
  login,
  loggingIn,
  loggingOut,
  logout,
  openAccountManagement,
  rotateKey
} = useAgentAuth();

const rotateKeyDialogVisible = ref(false);
const rotateKeyInitialPassword = ref("");
const rotationNotice = ref("");
const canRotateKey = computed(
  () =>
    auth.account_status === "active" &&
    Boolean(account.value?.permissions.includes("key.rotate"))
);

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

function openRotateKeyDialog() {
  clearError();
  rotationNotice.value = "";
  const remembered = loadRememberedAgentLogin();
  rotateKeyInitialPassword.value =
    remembered?.username.trim() === account.value?.username
      ? remembered.password
      : "";
  rotateKeyDialogVisible.value = true;
}

function closeRotateKeyDialog() {
  if (!keyRotationLoading.value) {
    rotateKeyDialogVisible.value = false;
    rotateKeyInitialPassword.value = "";
    clearError();
  }
}

async function confirmKeyRotation(password: string) {
  if (!(await rotateKey(password))) {
    return;
  }
  rotateKeyDialogVisible.value = false;
  rotateKeyInitialPassword.value = "";
  rotationNotice.value = "新密钥已生成并应用到 Agent";
  window.setTimeout(() => {
    rotationNotice.value = "";
  }, 4500);
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
    :key="
      [
        account.username,
        account.key_version,
        account.role,
        ...account.permissions
      ].join(':')
    "
    :account="account"
    :account-management-busy="accountManagementLoading"
    :can-rotate-key="canRotateKey"
    :key-rotation-busy="keyRotationLoading"
    :logout-busy="loggingOut"
    @manage-account="openAccountManagement"
    @rotate-key="openRotateKeyDialog"
    @logout="logout"
  />

  <LoginView
    v-else
    :account-management-loading="accountManagementLoading"
    :loading="loggingIn"
    :error="error"
    @manage-account="openAccountManagement"
    @submit="handleLogin"
  />

  <ToastHost
    v-if="authenticated"
    :toast="
      rotateKeyDialogVisible
        ? null
        : error
          ? { kind: 'error', message: error }
          : rotationNotice
            ? { kind: 'success', message: rotationNotice }
            : null
    "
  />

  <RotateKeyDialog
    :visible="rotateKeyDialogVisible"
    :busy="keyRotationLoading"
    :error="error"
    :initial-password="rotateKeyInitialPassword"
    @close="closeRotateKeyDialog"
    @confirm="confirmKeyRotation"
  />
</template>
