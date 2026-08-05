<script setup lang="ts">
import Avatar from 'primevue/avatar'
import Button from 'primevue/button'
import DatePicker from 'primevue/datepicker'
import Dialog from 'primevue/dialog'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import ProxyAddressChecklist from '../ProxyAddressChecklist.vue'
import RequestMessage from '../RequestMessage.vue'
import { useAppControllerContext } from '../../appController'

const {
  approvalExpiresAt,
  approvalMinimumExpiry,
  approvalProxyAddressIds,
  approvalReason,
  approvalRequest,
  approvalSaving,
  approvalVisible,
  enabledProxyAddresses,
  keyRequestKindLabel,
  performRejectKeyRequest,
  rejectingRequestId,
  rejectionReason,
  rejectionRequest,
  rejectionVisible,
  submitApproval,
} = useAppControllerContext()
</script>

<template>
<Dialog
  v-model:visible="approvalVisible"
  modal
  header="批准密钥申请"
  class="form-dialog approval-dialog"
  :style="{ width: 'min(92vw, 560px)' }"
>
  <div v-if="approvalRequest" class="approval-dialog-user">
    <Avatar
      :image="approvalRequest.avatarUrl || undefined"
      :label="approvalRequest.username.slice(0, 1).toUpperCase()"
      shape="circle"
    />
    <div>
      <strong>{{ approvalRequest.displayName || approvalRequest.username }}</strong>
      <span>{{ approvalRequest.username }}</span>
    </div>
    <Tag
      :value="keyRequestKindLabel(approvalRequest)"
      :severity="approvalRequest.kind === 'rotate' ? 'warn' : 'info'"
    />
  </div>
  <RequestMessage
    v-if="approvalRequest"
    class="approval-dialog-message"
    :message="approvalRequest.requestMessage"
    label="用户留言"
  />
  <div class="privacy-notice">
    <i class="pi pi-eye-slash" />
    <span>
      批准后服务端会生成新密钥，连接凭据只能由该用户授权的 Agent 领取。
    </span>
  </div>
  <ProxyAddressChecklist
    v-model="approvalProxyAddressIds"
    :addresses="enabledProxyAddresses"
    input-prefix="approval-proxy"
    title="分配 Proxy 地址"
    description="至少选择一个；轮换申请会预选账号当前的地址。"
    empty-message="请先关闭对话框并新增可用地址。"
  />
  <div class="form-field approval-expiry-field">
    <label for="approval-expiry">新密钥过期时间</label>
    <DatePicker
      id="approval-expiry"
      v-model="approvalExpiresAt"
      :min-date="approvalMinimumExpiry"
      :manual-input="false"
      show-time
      hour-format="24"
      show-icon
      fluid
    />
    <small>必填，且必须晚于当前时间。批准后用户才能查看和使用新密钥。</small>
  </div>
  <div class="form-field">
    <label for="approval-reason">批准原因</label>
    <Textarea
      id="approval-reason"
      v-model="approvalReason"
      rows="3"
      maxlength="500"
      placeholder="说明批准本次密钥申请的原因"
      fluid
    />
    <small>{{ Array.from(approvalReason).length }} / 500，必填，仅管理员可见。</small>
  </div>
  <template #footer>
    <Button
      label="取消"
      severity="secondary"
      text
      :disabled="approvalSaving"
      @click="approvalVisible = false"
    />
    <Button
      label="批准并生成密钥"
      icon="pi pi-check"
      :loading="approvalSaving"
      :disabled="!approvalProxyAddressIds.length"
      @click="submitApproval"
    />
  </template>
</Dialog>

<Dialog
  v-model:visible="rejectionVisible"
  modal
  header="拒绝密钥申请"
  class="form-dialog rejection-dialog"
  :style="{ width: 'min(92vw, 520px)' }"
  :closable="!rejectingRequestId"
>
  <div v-if="rejectionRequest" class="dialog-form">
    <p class="dialog-lead">
      拒绝“{{ rejectionRequest.username }}”的申请后，用户可以看到下面的理由并重新提交。
    </p>
    <div class="form-field">
      <label for="key-request-rejection-reason">拒绝理由（用户可见）</label>
      <Textarea
        id="key-request-rejection-reason"
        v-model="rejectionReason"
        rows="5"
        maxlength="500"
        placeholder="例如：请补充业务用途和需要的有效期后重新申请。"
        :disabled="Boolean(rejectingRequestId)"
        fluid
      />
      <small>{{ Array.from(rejectionReason).length }} / 500，必填。</small>
    </div>
  </div>
  <template #footer>
    <Button
      label="取消"
      severity="secondary"
      text
      :disabled="Boolean(rejectingRequestId)"
      @click="rejectionVisible = false"
    />
    <Button
      label="确认拒绝"
      icon="pi pi-times"
      severity="danger"
      :loading="Boolean(rejectingRequestId)"
      @click="performRejectKeyRequest"
    />
  </template>
</Dialog>
</template>
