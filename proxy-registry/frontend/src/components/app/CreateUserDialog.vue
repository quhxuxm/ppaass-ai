<script setup lang="ts">
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import DatePicker from 'primevue/datepicker'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Password from 'primevue/password'
import Textarea from 'primevue/textarea'
import ProxyAddressChecklist from '../ProxyAddressChecklist.vue'
import { useAppControllerContext } from '../../appController'

const {
  agentPermissionOptions,
  basePermissionOptions,
  createForm,
  createMinimumExpiry,
  createSaving,
  createVisible,
  enabledProxyAddresses,
  generateTemporaryPassword,
  PASSWORD_MIN_CHARACTERS,
  submitCreate,
} = useAppControllerContext()
</script>

<template>
<Dialog
  v-model:visible="createVisible"
  modal
  header="新建普通用户"
  class="form-dialog"
  :style="{ width: 'min(92vw, 650px)' }"
>
  <p class="dialog-lead">
    保存后服务端会生成 RSA 密钥对并加密存储，连接凭据只能由该用户授权的 Agent 领取。
  </p>
  <form id="create-user-form" class="dialog-form" @submit.prevent="submitCreate">
    <div class="form-field">
      <label for="create-username">用户名</label>
      <InputText
        id="create-username"
        v-model="createForm.username"
        autocomplete="off"
        placeholder="例如 alice"
        fluid
      />
    </div>
    <div class="form-field">
      <div class="field-label-row">
        <label for="create-password">初始密码</label>
        <Button
          label="生成强密码"
          icon="pi pi-sparkles"
          severity="secondary"
          text
          size="small"
          type="button"
          @click="generateTemporaryPassword"
        />
      </div>
      <Password
        v-model="createForm.password"
        input-id="create-password"
        :toggle-mask="true"
        :feedback="true"
        :input-props="{
          autocomplete: 'new-password',
          minlength: PASSWORD_MIN_CHARACTERS,
        }"
        :placeholder="`至少 ${PASSWORD_MIN_CHARACTERS} 个字符`"
        fluid
      />
    </div>
    <div class="form-field">
      <label for="create-expiry">代理有效期</label>
      <DatePicker
        id="create-expiry"
        v-model="createForm.expiresAt"
        :min-date="createMinimumExpiry"
        :manual-input="false"
        show-time
        hour-format="24"
        show-icon
        fluid
      />
      <small>必填，且必须晚于当前时间。</small>
    </div>
    <ProxyAddressChecklist
      v-model="createForm.proxyAddressIds"
      :addresses="enabledProxyAddresses"
      input-prefix="create-proxy"
      description="至少选择一个；地址只会下发给 Agent，不在 Agent 界面显示。"
      empty-message="请先在 Proxy 地址目录中新增并启用地址。"
    />
    <section class="fixed-capabilities" aria-labelledby="create-capabilities-title">
      <div class="fixed-capabilities-heading">
        <span class="summary-icon blue"><i class="pi pi-shield" /></span>
        <div>
          <strong id="create-capabilities-title">普通用户基础能力</strong>
          <small>以下能力会自动授予，是普通用户的固定能力，无需单独配置。</small>
        </div>
      </div>
      <ul>
        <li
          v-for="permission in basePermissionOptions"
          :key="permission.code"
        >
          <i class="pi pi-check-circle" />
          <span>
            <strong>{{ permission.label }}</strong>
            <small>{{ permission.description }}</small>
          </span>
        </li>
      </ul>
    </section>
    <section
      class="agent-permission-picker"
      aria-labelledby="create-agent-permissions-title"
    >
      <div class="permission-picker-heading">
        <div>
          <strong id="create-agent-permissions-title">Agent 管理权限</strong>
          <small>按需分配；未勾选时 Agent 隐藏对应功能，并使用内置默认值。</small>
        </div>
      </div>
      <div class="permission-picker-grid">
        <label
          v-for="permission in agentPermissionOptions"
          :key="permission.code"
          class="permission-choice"
          :class="{ selected: createForm.agentPermissions.includes(permission.code) }"
          :for="`create-${permission.code}`"
        >
          <Checkbox
            v-model="createForm.agentPermissions"
            :input-id="`create-${permission.code}`"
            :value="permission.code"
          />
          <span>
            <strong>{{ permission.label }}</strong>
            <small>{{ permission.description }}</small>
          </span>
        </label>
      </div>
    </section>
    <div class="form-field">
      <label for="create-additional-permissions">自定义权限</label>
      <Textarea
        id="create-additional-permissions"
        v-model="createForm.additionalPermissions"
        rows="3"
        placeholder="例如 report.read, tunnel.priority"
        aria-describedby="additional-permissions-help"
        fluid
      />
      <small id="additional-permissions-help">
        可选。使用逗号、空格或换行分隔 permission code；基础能力和上方 Agent 权限会自动排除。
      </small>
    </div>
    <div class="form-field">
      <label for="create-audit-reason">创建和权限分配原因</label>
      <Textarea
        id="create-audit-reason"
        v-model="createForm.auditReason"
        rows="3"
        maxlength="500"
        placeholder="说明为什么创建该用户并分配这些权限"
        fluid
      />
      <small>{{ Array.from(createForm.auditReason).length }} / 500，必填。</small>
    </div>
  </form>
  <template #footer>
    <Button label="取消" severity="secondary" text @click="createVisible = false" />
    <Button
      type="submit"
      form="create-user-form"
      label="创建并生成密钥"
      icon="pi pi-key"
      :loading="createSaving"
    />
  </template>
</Dialog>
</template>
