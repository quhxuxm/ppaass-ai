<script setup lang="ts">
import { computed, reactive } from "vue";
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import Password from "primevue/password";
import AppIcon from "../components/AppIcon";
import { loadRememberedAgentLogin } from "../rememberedLogin";
import type { AgentLoginRequest } from "../types";

const props = defineProps<{
  loading: boolean;
  accountManagementLoading: boolean;
  error: string;
}>();

const emit = defineEmits<{
  manageAccount: [];
  submit: [request: AgentLoginRequest];
}>();

const rememberedLogin = loadRememberedAgentLogin();
const form = reactive({
  username: rememberedLogin?.username ?? "",
  password: rememberedLogin?.password ?? "",
  rememberCredentials: rememberedLogin !== null
});

const canSubmit = computed(
  () =>
    !props.loading &&
    Boolean(form.username.trim()) &&
    form.password.length >= 8
);
function submit() {
  if (!canSubmit.value) {
    return;
  }
  emit("submit", {
    username: form.username,
    password: form.password,
    rememberCredentials: form.rememberCredentials
  });
}
</script>

<template>
  <main class="auth-gate">
    <div class="auth-orb auth-orb-primary" aria-hidden="true"></div>
    <div class="auth-orb auth-orb-secondary" aria-hidden="true"></div>

    <section class="auth-card" aria-labelledby="agent-login-title">
      <header class="auth-brand">
        <span class="auth-brand-mark">
          <img src="/app-icon.png" alt="" aria-hidden="true" />
        </span>
        <span>
          <strong>PPAASS</strong>
          <small>桌面代理</small>
        </span>
      </header>

      <div class="auth-heading">
        <span class="auth-eyebrow">Agent 登录</span>
        <h1 id="agent-login-title">连接你的代理账户</h1>
        <p>登录后才能进入桌面 Agent，并使用为当前账户批准的代理凭据。</p>
      </div>

      <Message v-if="error" class="auth-error" severity="error" :closable="false">
        {{ error }}
      </Message>

      <form class="auth-form" @submit.prevent="submit">
        <label class="auth-field" for="agent-login-username">
          <span>用户名</span>
          <InputText
            id="agent-login-username"
            v-model="form.username"
            autocomplete="username"
            autofocus
            placeholder="输入 Proxy Web 用户名"
            :disabled="loading"
          />
        </label>

        <label class="auth-field" for="agent-login-password">
          <span>密码</span>
          <Password
            input-id="agent-login-password"
            v-model="form.password"
            autocomplete="current-password"
            placeholder="至少 8 位"
            :feedback="false"
            :minlength="8"
            :disabled="loading"
            toggle-mask
            fluid
          />
        </label>

        <div class="auth-login-options">
          <Checkbox
            input-id="agent-login-remember"
            v-model="form.rememberCredentials"
            :disabled="loading"
            binary
          />
          <label for="agent-login-remember">记住用户名和密码</label>
        </div>

        <Button
          class="auth-submit"
          type="submit"
          label="登录并配置 Agent"
          :loading="loading"
          :disabled="!canSubmit"
        >
          <template #icon="slotProps">
            <AppIcon :class="slotProps.class" name="key" />
          </template>
        </Button>

        <Button
          class="auth-register"
          type="button"
          label="注册和账户管理"
          severity="secondary"
          outlined
          :loading="accountManagementLoading"
          :disabled="loading"
          @click="emit('manageAccount')"
        >
          <template #icon="slotProps">
            <AppIcon :class="slotProps.class" name="user" />
          </template>
        </Button>
      </form>

      <aside class="auth-security-note">
        <AppIcon name="shield-check" />
        <p>
          <strong>凭据由本机安全处理</strong>
          <span>私钥会从 Proxy Web 自动下载并应用到 Agent，不会显示在界面中。</span>
        </p>
      </aside>
    </section>
  </main>
</template>
