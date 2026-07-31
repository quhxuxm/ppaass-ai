<script setup lang="ts">
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import DatePicker from 'primevue/datepicker'
import Dialog from 'primevue/dialog'
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import ProxyAddressChecklist from '../ProxyAddressChecklist.vue'
import { useAppControllerContext } from '../../appController'

const {
  agentPermissionOptions,
  basePermissionOptions,
  displayedEditAgentPermissions,
  editForm,
  editSaving,
  editVisible,
  editingCustomPermissions,
  editingHasEditableFields,
  editingProfileReadOnly,
  editingRequiresAuditReason,
  editingRootAdmin,
  editingUser,
  enabledProxyAddresses,
  managedUsername,
  roleOptions,
  statusOptions,
  submitEdit,
} = useAppControllerContext()
</script>

<template>
<Dialog
  v-model:visible="editVisible"
  modal
  class="form-dialog user-editor-dialog"
  :style="{ width: 'min(94vw, 760px)' }"
>
  <template #header>
    <div class="user-editor-header">
      <span class="user-editor-header-icon">
        <i class="pi pi-user-edit" />
      </span>
      <div class="user-editor-header-copy">
        <small>用户配置</small>
        <h2 :title="editingUser ? managedUsername(editingUser) : ''">
          {{ editingUser ? managedUsername(editingUser) : '' }}
        </h2>
      </div>
      <Tag
        v-if="editingUser?.account"
        :value="
          editingRootAdmin
            ? '根管理员'
            : editForm.role === 'admin'
              ? '管理员'
              : '普通用户'
        "
        :severity="editForm.role === 'admin' ? 'info' : 'secondary'"
        rounded
      />
    </div>
  </template>
  <form
    id="edit-user-form"
    class="dialog-form user-editor-form"
    @submit.prevent="submitEdit"
  >
    <section v-if="editingUser?.account" class="user-editor-section">
      <div class="user-editor-section-heading">
        <span><i class="pi pi-id-card" /></span>
        <div>
          <strong>账号与登录</strong>
          <small>设置用户在 Proxy Registry 和 Agent 中的账号身份。</small>
        </div>
      </div>
      <div v-if="!editingRootAdmin" class="form-row user-editor-account-grid">
        <div class="form-field">
          <label for="edit-role">账户角色</label>
          <Select
            id="edit-role"
            v-model="editForm.role"
            :options="roleOptions"
            option-label="label"
            option-value="value"
            fluid
          />
        </div>
        <div class="form-field">
          <label for="edit-status">登录状态</label>
          <Select
            id="edit-status"
            v-model="editForm.status"
            :options="statusOptions"
            option-label="label"
            option-value="value"
            fluid
          />
        </div>
        <small class="user-editor-account-help">
          停用账号后，该用户将无法登录 Proxy Registry 和 Agent；不会自动改变代理连接权限。
        </small>
      </div>
      <div v-else class="protected-account-summary">
        <div>
          <span>账户角色</span>
          <strong><i class="pi pi-shield" /> 管理员</strong>
        </div>
        <div>
          <span>登录状态</span>
          <strong><i class="pi pi-check-circle" /> 已启用</strong>
        </div>
      </div>
      <div v-if="editingRootAdmin" class="root-admin-notice">
        <i class="pi pi-lock" />
        <span>
          <strong>根管理员账号受保护</strong>
          <small>admin 不能停用、降级或删除，代理连接设置仍可正常调整。</small>
        </span>
      </div>
    </section>
    <div v-if="!editingUser?.account" class="legacy-notice">
      <i class="pi pi-info-circle" />
      <span>
        该 legacy 配置没有 Web 登录账号；这里只能允许或暂停代理连接，有效期、权限和密钥保持只读。
      </span>
    </div>
    <template v-if="editingUser?.profile">
      <section class="user-editor-section proxy-access-section">
        <div class="user-editor-section-heading">
          <span><i class="pi pi-clock" /></span>
          <div>
            <strong>代理连接</strong>
            <small>控制流量访问、有效期以及 Agent 可以连接的 Proxy 节点。</small>
          </div>
        </div>
        <div
          v-if="editingProfileReadOnly && editingUser.profile.origin !== 'legacy'"
          class="approval-required-notice"
        >
          <i class="pi pi-lock" />
          <span>
            <strong>密钥生命周期已锁定</strong>
            <small>
              缺失或过期密钥不能在编辑页直接恢复有效期。用户提交申请后，请在待审批列表中设置新的未来有效期。
            </small>
          </span>
        </div>
        <div class="user-editor-runtime-grid">
          <div class="form-field">
            <label for="edit-expiry">代理有效期</label>
            <DatePicker
              id="edit-expiry"
              v-model="editForm.expiresAt"
              :disabled="editingProfileReadOnly"
              show-time
              hour-format="24"
              show-icon
              fluid
            />
            <small v-if="editingProfileReadOnly">
              只读状态，不能从这里延长或恢复。
            </small>
            <small v-else>清空表示永久有效。</small>
          </div>
          <div class="form-field">
            <span class="form-field-label">流量权限</span>
            <label
              class="proxy-toggle-card"
              :class="{ selected: editForm.enabled }"
              for="edit-enabled"
            >
              <Checkbox
                v-model="editForm.enabled"
                input-id="edit-enabled"
                binary
              />
              <span>
                <strong>允许代理连接</strong>
              </span>
              <Tag
                :value="editForm.enabled ? '已允许' : '已暂停'"
                :severity="editForm.enabled ? 'success' : 'secondary'"
                rounded
              />
            </label>
            <small>关闭后停止 Agent 代理，Web 账户仍可登录。</small>
          </div>
        </div>
        <ProxyAddressChecklist
          v-if="editingUser.account"
          v-model="editForm.proxyAddressIds"
          :addresses="enabledProxyAddresses"
          input-prefix="edit-proxy"
          :description="
            editForm.status === 'disabled' && !editingUser.proxyAddresses.length
              ? '账号停用时可以暂不分配；重新启用前至少选择一个。'
              : '至少保留一个；保存后 Agent 会在定期同步时应用。'
          "
          :required="
            editForm.status !== 'disabled' || editingUser.proxyAddresses.length > 0
          "
          empty-message="请先在 Proxy 地址目录中新增并启用地址。"
          compact
        />
      </section>
    </template>
    <section
      v-if="
        editingUser?.account &&
        (editingUser.profile || editForm.role === 'admin')
      "
      class="user-editor-section user-editor-permission-section"
      aria-labelledby="edit-agent-permissions-title"
    >
        <div class="user-editor-section-heading">
          <span><i class="pi pi-shield" /></span>
          <div>
            <strong id="edit-agent-permissions-title">Agent 权限</strong>
            <small v-if="editForm.role === 'admin'">
              管理员自动拥有以下全部权限，不能单独取消。
            </small>
            <small v-else>基础代理能力固定授予，管理功能可按需开启。</small>
          </div>
        </div>
        <div class="base-capability-strip" aria-label="固定基础能力">
          <span v-for="permission in basePermissionOptions" :key="permission.code">
            <i class="pi pi-check-circle" />
            {{ permission.label }}
          </span>
        </div>
        <div class="permission-picker-grid">
          <label
            v-for="permission in agentPermissionOptions"
            :key="permission.code"
            class="permission-choice"
            :class="{
              selected: displayedEditAgentPermissions.includes(permission.code),
            }"
            :for="`edit-${permission.code}`"
          >
            <Checkbox
              v-model="displayedEditAgentPermissions"
              :input-id="`edit-${permission.code}`"
              :value="permission.code"
              :disabled="
                editForm.role === 'admin' ||
                editingUser.profile?.origin === 'legacy'
              "
            />
            <span>
              <strong>{{ permission.label }}</strong>
              <small>{{ permission.description }}</small>
            </span>
          </label>
        </div>
        <div
          v-if="editingCustomPermissions.length"
          class="preserved-permissions"
        >
          <span>
            <strong>保留的自定义权限</strong>
            <small>保存时会原样保留，不会因勾选 Agent 权限而丢失。</small>
          </span>
          <div class="additional-permission-tags">
            <Tag
              v-for="permission in editingCustomPermissions"
              :key="permission"
              :value="permission"
              severity="secondary"
              rounded
            />
          </div>
        </div>
    </section>
    <section v-if="editingRequiresAuditReason" class="user-editor-section audit-reason-section">
      <div class="user-editor-section-heading">
        <span><i class="pi pi-file-edit" /></span>
        <div>
          <strong>本次修改原因</strong>
          <small>管理员敏感操作会写入仅管理员可见的审计记录。</small>
        </div>
      </div>
      <div class="form-field">
        <label for="edit-audit-reason">操作原因</label>
        <Textarea
          id="edit-audit-reason"
          v-model="editForm.auditReason"
          rows="3"
          maxlength="500"
          placeholder="说明为什么需要修改该用户配置"
          fluid
        />
        <small>{{ Array.from(editForm.auditReason).length }} / 500，敏感变更必填。</small>
      </div>
    </section>
  </form>
  <template #footer>
    <Button
      :label="editingHasEditableFields ? '取消' : '关闭'"
      severity="secondary"
      text
      @click="editVisible = false"
    />
    <Button
      v-if="editingHasEditableFields"
      type="submit"
      form="edit-user-form"
      label="保存更改"
      icon="pi pi-check"
      :loading="editSaving"
    />
  </template>
</Dialog>
</template>
