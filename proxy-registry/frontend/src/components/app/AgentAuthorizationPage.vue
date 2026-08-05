<script setup lang="ts">
import Avatar from 'primevue/avatar'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { useAppControllerContext } from '../../appController'

const {
  account,
  agentAuthorization,
  agentAuthorizationCode,
  agentAuthorizationDecisionLoading,
  agentAuthorizationError,
  agentAuthorizationInput,
  agentAuthorizationLoading,
  agentAuthorizationOutcome,
  decideAgentAuthorization,
  formatExpiry,
  leaveAgentAuthorization,
  performLogout,
  refreshAgentAuthorization,
} = useAppControllerContext()
</script>

<template>
<main class="agent-authorization-page">
  <section class="agent-authorization-card" aria-labelledby="agent-authorization-title">
    <a class="brand" href="/" aria-label="PPAASS 首页" @click.prevent="leaveAgentAuthorization">
      <span class="brand-mark"><i class="pi pi-shield" /></span>
      <span>PPAASS</span>
    </a>

    <template v-if="agentAuthorizationOutcome">
      <div
        class="agent-authorization-outcome"
        :class="agentAuthorizationOutcome"
        role="status"
      >
        <span class="outcome-icon">
          <i
            :class="
              agentAuthorizationOutcome === 'authorized'
                ? 'pi pi-check'
                : 'pi pi-times'
            "
          />
        </span>
        <h1>
          {{
            agentAuthorizationOutcome === 'authorized'
              ? 'Agent 登录已授权'
              : 'Agent 登录已拒绝'
          }}
        </h1>
        <p>
          {{
            agentAuthorizationOutcome === 'authorized'
              ? '你可以返回 Agent，它会自动领取账户配置和私钥。设备码只能使用一次。'
              : 'Agent 无法使用这次设备码登录。如需登录，请从 Agent 重新发起。'
          }}
        </p>
        <Button
          label="返回用户中心"
          icon="pi pi-arrow-left"
          @click="leaveAgentAuthorization"
        />
      </div>
    </template>

    <template v-else>
      <div class="agent-authorization-heading">
        <p class="eyebrow">AGENT SIGN-IN</p>
        <h1 id="agent-authorization-title">确认 Agent 登录</h1>
        <p>只有你正在操作自己的 Agent 时才批准。我们不会在此页面展示或传输私钥。</p>
      </div>

      <div class="agent-authorization-account">
      <Avatar
          :image="account?.avatarUrl || undefined"
          :label="
            account?.avatarUrl
              ? undefined
              : (account?.displayName || account?.username || 'U')
                  .slice(0, 1)
                  .toUpperCase()
          "
          shape="circle"
        />
        <span>
          <small>当前登录账户</small>
          <strong>{{ account?.displayName || account?.username }}</strong>
        </span>
        <Button
          label="切换账户"
          severity="secondary"
          text
          size="small"
          @click="performLogout"
        />
      </div>

      <form
        v-if="!agentAuthorization"
        class="agent-authorization-code-form"
        @submit.prevent="refreshAgentAuthorization"
      >
        <label for="agent-authorization-code">设备授权短码</label>
        <InputText
          id="agent-authorization-code"
          v-model="agentAuthorizationInput"
          autocomplete="one-time-code"
          autocapitalize="characters"
          placeholder="例如 ABCD-EFGH-JKLM"
          :disabled="agentAuthorizationLoading"
          fluid
        />
        <Button
          type="submit"
          label="继续"
          icon="pi pi-arrow-right"
          :loading="agentAuthorizationLoading"
          fluid
        />
      </form>

      <template v-else>
        <div class="agent-device-summary">
          <span class="summary-icon blue">
            <i
              :class="
                agentAuthorization.platform === 'android'
                  ? 'pi pi-mobile'
                  : 'pi pi-desktop'
              "
            />
          </span>
          <span>
            <small>申请登录的设备</small>
            <strong>{{ agentAuthorization.clientName }}</strong>
            <small>
              {{
                agentAuthorization.platform === 'android' ? 'Android' : 'Windows'
              }}
              · 授权码 {{ agentAuthorizationCode }}
            </small>
          </span>
        </div>

        <div class="agent-authorization-warning">
          <i class="pi pi-exclamation-triangle" />
          <span>
            <strong>请核对 Agent 上显示的短码</strong>
            <small>
              此请求将在
              {{ formatExpiry(String(agentAuthorization.expiresAt)) }}
              失效。批准后，Agent 可一次性领取你的代理配置和私钥。
            </small>
          </span>
        </div>

        <div class="agent-authorization-actions">
          <Button
            label="拒绝"
            icon="pi pi-times"
            severity="secondary"
            outlined
            :loading="agentAuthorizationDecisionLoading === 'deny'"
            :disabled="
              agentAuthorizationDecisionLoading !== null &&
              agentAuthorizationDecisionLoading !== 'deny'
            "
            @click="decideAgentAuthorization('deny')"
          />
          <Button
            label="批准登录"
            icon="pi pi-check"
            :loading="agentAuthorizationDecisionLoading === 'approve'"
            :disabled="
              agentAuthorizationDecisionLoading !== null &&
              agentAuthorizationDecisionLoading !== 'approve'
            "
            @click="decideAgentAuthorization('approve')"
          />
        </div>
      </template>

      <p
        v-if="agentAuthorizationError"
        class="agent-authorization-error"
        role="alert"
      >
        <i class="pi pi-exclamation-circle" />
        {{ agentAuthorizationError }}
      </p>
    </template>
  </section>
</main>
</template>
