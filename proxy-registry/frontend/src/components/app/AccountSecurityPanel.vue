<script setup lang="ts">
import Button from 'primevue/button'
import Password from 'primevue/password'
import Tag from 'primevue/tag'
import RequestMessage from '../RequestMessage.vue'
import { useAppControllerContext } from '../../appController'

const {
  account,
  canRotateOwnKey,
  confirmRotateOwnKey,
  formatExpiry,
  keyRequestLoading,
  keyRotationLoading,
  keyState,
  openKeyRequestDialog,
  PASSWORD_MIN_CHARACTERS,
  passwordForm,
  passwordSaving,
  pendingKeyRequest,
  profile,
  refreshKeyRequest,
  submitPasswordChange,
} = useAppControllerContext()
</script>

<template>
<section class="content-card account-security-card">
  <div class="card-heading">
    <div>
      <h2>登录安全</h2>
      <p>修改用于登录 Proxy Registry 和 Agent 的账户密码。</p>
    </div>
    <Tag value="密码保护" severity="success" rounded />
  </div>
  <form class="password-change-form" @submit.prevent="submitPasswordChange">
    <div class="password-fields">
      <div class="form-field">
        <label for="account-current-password">当前密码</label>
        <Password
          v-model="passwordForm.currentPassword"
          input-id="account-current-password"
          :feedback="false"
          :toggle-mask="true"
          :input-props="{ autocomplete: 'current-password' }"
          placeholder="输入当前密码"
          fluid
        />
      </div>
      <div class="form-field">
        <label for="account-new-password">新密码</label>
        <Password
          v-model="passwordForm.newPassword"
          input-id="account-new-password"
          :feedback="true"
          :toggle-mask="true"
          :input-props="{
            autocomplete: 'new-password',
            minlength: PASSWORD_MIN_CHARACTERS,
          }"
          :placeholder="`至少 ${PASSWORD_MIN_CHARACTERS} 个字符`"
          fluid
        />
      </div>
      <div class="form-field">
        <label for="account-confirm-password">确认新密码</label>
        <Password
          v-model="passwordForm.confirmPassword"
          input-id="account-confirm-password"
          :feedback="false"
          :toggle-mask="true"
          :input-props="{
            autocomplete: 'new-password',
            minlength: PASSWORD_MIN_CHARACTERS,
          }"
          placeholder="再次输入新密码"
          fluid
        />
      </div>
    </div>
    <div class="password-change-actions">
      <small>
        修改后会退出全部 Web 会话，请使用新密码重新登录。
      </small>
      <Button
        type="submit"
        label="更新登录密码"
        icon="pi pi-lock"
        :loading="passwordSaving"
      />
    </div>
  </form>
</section>

<section
  v-if="keyState === 'active' && profile"
  class="rotate-banner"
  :class="{ unavailable: !canRotateOwnKey }"
>
  <div class="rotate-icon"><i class="pi pi-refresh" /></div>
  <div>
    <h2>重新生成密钥对</h2>
    <p v-if="canRotateOwnKey">
      在有效期内可以直接更新。更新后，已授权 Agent 会自动领取新的连接凭据。
    </p>
    <p v-else>
      当前账户没有更新密钥的权限，或代理连接已被暂停。
    </p>
  </div>
  <Button
    label="生成新密钥"
    icon="pi pi-refresh"
    severity="danger"
    outlined
    :loading="keyRotationLoading"
    :disabled="!canRotateOwnKey"
    @click="confirmRotateOwnKey"
  />
</section>

<section
  v-else
  class="content-card key-request-card"
  :class="`state-${keyState}`"
>
  <div class="key-request-icon">
    <i
      :class="
        keyState !== 'disabled' && pendingKeyRequest?.status === 'pending'
          ? 'pi pi-clock'
          : pendingKeyRequest?.status === 'rejected'
            ? 'pi pi-times-circle'
          : keyState === 'expired'
            ? 'pi pi-calendar-times'
            : keyState === 'disabled'
              ? 'pi pi-lock'
            : keyState === 'active'
              ? 'pi pi-exclamation-circle'
              : 'pi pi-key'
      "
    />
  </div>
  <div class="key-request-copy">
    <p class="eyebrow">KEY ACCESS</p>
    <h2
      v-if="
        keyState !== 'disabled' &&
        pendingKeyRequest?.status === 'pending'
      "
    >
      {{
        pendingKeyRequest.kind === 'rotate'
          ? '密钥重生成申请正在等待审批'
          : '首次密钥申请正在等待审批'
      }}
    </h2>
    <h2 v-else-if="pendingKeyRequest?.status === 'rejected'">
      密钥申请已被拒绝
    </h2>
    <h2 v-else-if="keyState === 'expired'">密钥已过期，请申请续期</h2>
    <h2 v-else-if="keyState === 'missing'">申请你的第一组代理密钥</h2>
    <h2 v-else-if="keyState === 'disabled'">代理连接已被暂停</h2>
    <h2 v-else>密钥信息暂不可用</h2>
    <p
      v-if="
        keyState !== 'disabled' &&
        pendingKeyRequest?.status === 'pending'
      "
    >
      申请于
      {{ pendingKeyRequest.createdAt ? formatExpiry(pendingKeyRequest.createdAt) : '刚刚' }}
      提交。管理员批准并设置新的有效期后，已授权 Agent 会领取新的连接凭据。
    </p>
    <p v-else-if="pendingKeyRequest?.status === 'rejected'">
      {{
        pendingKeyRequest.reviewerLoginName
          ? `管理员 ${pendingKeyRequest.reviewerLoginName} 已处理这项申请。`
          : '管理员已处理这项申请。'
      }}
      你可以根据拒绝理由修改说明后重新提交。
    </p>
    <p v-else-if="keyState === 'expired'">
      旧密钥已失效，不能继续用于新连接。提交申请后，管理员将审核并设置新的有效期。
    </p>
    <p v-else-if="keyState === 'missing'">
      管理员批准并设置有效期后，系统才会生成密钥。管理员无法查看生成的 PEM 内容。
    </p>
    <p v-else-if="keyState === 'disabled'">
      停用状态下不能申请、查看或更新密钥，也不能建立新的代理连接。请联系管理员重新启用账户配置。
    </p>
    <p v-else>
      当前状态显示密钥有效，但未返回完整的密钥状态。请刷新后重试。
    </p>
    <RequestMessage
      v-if="
        keyState !== 'disabled' &&
        pendingKeyRequest?.status === 'pending'
      "
      :message="pendingKeyRequest.requestMessage"
      label="我的留言"
    />
    <RequestMessage
      v-if="pendingKeyRequest?.status === 'rejected'"
      :message="pendingKeyRequest.rejectionReason"
      label="拒绝理由"
      empty-text="管理员未填写拒绝理由。"
    />
    <div class="key-request-actions">
      <Button
        v-if="
          (keyState === 'missing' || keyState === 'expired') &&
          pendingKeyRequest?.status !== 'pending'
        "
        :label="keyState === 'expired' ? '申请续期并生成新密钥' : '申请生成密钥'"
        icon="pi pi-send"
        :loading="keyRequestLoading"
        :disabled="account?.status !== 'active' || profile?.enabled === false"
        @click="openKeyRequestDialog"
      />
      <Button
        label="刷新状态"
        icon="pi pi-refresh"
        severity="secondary"
        outlined
        :loading="keyRequestLoading"
        @click="refreshKeyRequest"
      />
    </div>
  </div>
  <Tag
    :value="
      keyState !== 'disabled' && pendingKeyRequest?.status === 'pending'
        ? '待管理员审批'
        : pendingKeyRequest?.status === 'rejected'
          ? '申请被拒绝'
        : keyState === 'expired'
          ? '已过期'
          : keyState === 'disabled'
            ? '已停用'
          : keyState === 'missing'
            ? '未生成'
            : '信息不完整'
    "
    :severity="
      keyState !== 'disabled' && pendingKeyRequest?.status === 'pending'
        ? 'info'
        : pendingKeyRequest?.status === 'rejected'
          ? 'danger'
        : keyState === 'expired'
          ? 'danger'
          : keyState === 'disabled'
            ? 'secondary'
          : 'warn'
    "
    rounded
  />
</section>
</template>
