<script setup lang="ts">
import { computed, ref } from "vue";
import ProgressSpinner from "primevue/progressspinner";
import AgentWorkspace from "./AgentWorkspace.vue";
import RotateKeyDialog from "./components/RotateKeyDialog.vue";
import ToastHost from "./components/ToastHost.vue";
import { useAgentAuth } from "./composables/useAgentAuth";
import { useAdminKeyRequests } from "./composables/useAdminKeyRequests";
import LoginView from "./views/LoginView.vue";
import {
  clearRememberedAgentLogin,
  loadRememberedAgentLogin,
  saveRememberedAgentLogin
} from "./rememberedLogin";
import type {
  AgentAdminKeyRequestApproval,
  AgentLoginRequest
} from "./types";

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

const accountStatus = computed(() => auth.account_status);
const adminRequests = useAdminKeyRequests({
  account,
  accountStatus
});
const rotateKeyDialogVisible = ref(false);
const rotateKeyInitialPassword = ref("");
const rotationNotice = ref("");
const canRotateKey = computed(
  () =>
    auth.account_status === "active" &&
    Boolean(account.value?.permissions.includes("key.rotate"))
);
const visibleToast = computed(() => {
  if (rotateKeyDialogVisible.value) {
    return null;
  }
  if (error.value) {
    return { kind: "error" as const, message: error.value };
  }
  if (rotationNotice.value) {
    return {
      kind: "success" as const,
      message: rotationNotice.value
    };
  }
  if (adminRequests.error.value) {
    return {
      kind: "error" as const,
      message: adminRequests.error.value
    };
  }
  if (adminRequests.notice.value) {
    return {
      kind: "info" as const,
      message: adminRequests.notice.value
    };
  }
  return null;
});

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

function approveAdminRequest(request: AgentAdminKeyRequestApproval) {
  void adminRequests.approve(request);
}

function rejectAdminRequest(requestId: string) {
  void adminRequests.reject(requestId);
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
    :account-status="auth.account_status"
    :account-management-busy="accountManagementLoading"
    :admin-key-requests="adminRequests.inbox.value.requests"
    :admin-proxy-addresses="adminRequests.inbox.value.proxy_addresses"
    :admin-requests-loading="adminRequests.loading.value"
    :admin-request-busy-id="adminRequests.busyRequestId.value"
    :admin-request-error="adminRequests.error.value"
    :can-rotate-key="canRotateKey"
    :key-rotation-busy="keyRotationLoading"
    :logout-busy="loggingOut"
    @manage-account="openAccountManagement"
    @refresh-admin-requests="adminRequests.refresh"
    @approve-admin-request="approveAdminRequest"
    @reject-admin-request="rejectAdminRequest"
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
    :toast="visibleToast"
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
