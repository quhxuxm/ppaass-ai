<script setup lang="ts">
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Password from 'primevue/password'
import { useAppControllerContext } from '../../appController'

const {
  agentAuthorizationActive,
  agentAuthorizationCode,
  authForm,
  authLoading,
  authMode,
  PASSWORD_MIN_CHARACTERS,
  providers,
  submitAuth,
} = useAppControllerContext()
</script>

<template>
<main class="auth-page">
  <section class="auth-intro" aria-labelledby="auth-title">
    <a class="brand" href="/" aria-label="PPAASS 首页">
      <span class="brand-mark"><i class="pi pi-shield" /></span>
      <span>PPAASS</span>
    </a>
    <div class="intro-copy">
      <p class="eyebrow">SECURE ACCESS</p>
      <h1 id="auth-title">你的代理身份，<br />由你掌控。</h1>
      <p>
        登录后管理账户密码，并查看代理有效期、权限与密钥状态。
      </p>
    </div>
    <div class="intro-security">
      <span><i class="pi pi-database" /> SQLite 加密存储</span>
      <span><i class="pi pi-desktop" /> Agent 安全领取凭据</span>
      <span><i class="pi pi-lock" /> HttpOnly 安全会话</span>
    </div>
  </section>

  <section
    class="auth-panel"
    aria-label="账户登录和注册"
  >
    <div class="auth-card">
      <div
        v-if="agentAuthorizationActive"
        class="agent-authorization-context"
        role="status"
      >
        <i class="pi pi-desktop" />
        <span>
          <strong>正在登录 Agent</strong>
          <small v-if="agentAuthorizationCode">
            设备授权短码：{{ agentAuthorizationCode }}
          </small>
          <small v-else>登录后输入 Agent 显示的设备授权短码。</small>
        </span>
      </div>
      <div class="auth-heading">
        <p class="eyebrow">{{ authMode === 'login' ? '欢迎回来' : '创建账户' }}</p>
        <h2>{{ authMode === 'login' ? '登录 PPAASS' : '注册普通用户' }}</h2>
        <p>
          {{
            authMode === 'login'
              ? '使用用户名和密码继续。'
              : '注册后可以提交密钥申请；管理员批准有效期后，即可通过 Agent 使用代理。'
          }}
        </p>
      </div>

      <div class="auth-tabs" role="tablist" aria-label="登录或注册">
        <button
          type="button"
          role="tab"
          :aria-selected="authMode === 'login'"
          :class="{ active: authMode === 'login' }"
          @click="authMode = 'login'"
        >
          登录
        </button>
        <button
          v-if="providers.localRegistration"
          type="button"
          role="tab"
          :aria-selected="authMode === 'register'"
          :class="{ active: authMode === 'register' }"
          @click="authMode = 'register'"
        >
          注册
        </button>
      </div>

      <form class="auth-form" @submit.prevent="submitAuth">
        <label for="auth-username">用户名</label>
        <InputText
          id="auth-username"
          v-model="authForm.username"
          autocomplete="username"
          placeholder="输入用户名"
          fluid
        />
        <div class="field-label-row">
          <label for="auth-password">密码</label>
          <small v-if="authMode === 'register'">
            至少 {{ PASSWORD_MIN_CHARACTERS }} 个字符
          </small>
        </div>
        <Password
          v-model="authForm.password"
          input-id="auth-password"
          :feedback="authMode === 'register'"
          :toggle-mask="true"
          :input-props="{
            autocomplete:
              authMode === 'register' ? 'new-password' : 'current-password',
            minlength:
              authMode === 'register' ? PASSWORD_MIN_CHARACTERS : undefined,
          }"
          placeholder="输入密码"
          fluid
        />
        <template v-if="authMode === 'register'">
          <label for="auth-confirm-password">确认密码</label>
          <Password
            v-model="authForm.confirmPassword"
            input-id="auth-confirm-password"
            :feedback="false"
            :toggle-mask="true"
            :input-props="{
              autocomplete: 'new-password',
              minlength: PASSWORD_MIN_CHARACTERS,
            }"
            placeholder="再次输入密码"
            fluid
          />
        </template>
        <Button
          type="submit"
          :label="authMode === 'login' ? '登录' : '注册账户'"
          :icon="authMode === 'login' ? 'pi pi-sign-in' : 'pi pi-user-plus'"
          :loading="authLoading"
          fluid
        />
      </form>

      <p v-if="!providers.localRegistration && authMode === 'login'" class="registration-note">
        当前未开放自主注册，请联系管理员创建账号。
      </p>
    </div>
  </section>
</main>
</template>
