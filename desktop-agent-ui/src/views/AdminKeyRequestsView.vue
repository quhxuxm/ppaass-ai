<script setup lang="ts">
import { computed, ref, watch } from "vue";
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import DatePicker from "primevue/datepicker";
import Dialog from "primevue/dialog";
import ProgressSpinner from "primevue/progressspinner";
import Textarea from "primevue/textarea";
import AppIcon from "../components/AppIcon";
import type {
  AgentAdminKeyRequest,
  AgentAdminKeyRequestApproval,
  AgentAdminKeyRequestRejection,
  AgentAdminProxyAddress
} from "../types";

const props = defineProps<{
  requests: AgentAdminKeyRequest[];
  proxyAddresses: AgentAdminProxyAddress[];
  loading: boolean;
  busyRequestId: string | null;
  error: string;
}>();

const emit = defineEmits<{
  refresh: [];
  approve: [request: AgentAdminKeyRequestApproval];
  reject: [request: AgentAdminKeyRequestRejection];
}>();

const approvalRequest = ref<AgentAdminKeyRequest | null>(null);
const approvalExpiresAt = ref<Date | null>(null);
const approvalProxyAddressIds = ref<string[]>([]);
const approvalReason = ref("");
const rejectionRequest = ref<AgentAdminKeyRequest | null>(null);
const rejectionReason = ref("");
const enabledProxyAddresses = computed(() =>
  props.proxyAddresses.filter((address) => address.enabled)
);
const approvalBusy = computed(
  () =>
    approvalRequest.value !== null &&
    props.busyRequestId === approvalRequest.value.request_id
);
const rejectionBusy = computed(
  () =>
    rejectionRequest.value !== null &&
    props.busyRequestId === rejectionRequest.value.request_id
);
const approvalValid = computed(
  () =>
    approvalExpiresAt.value !== null &&
    approvalExpiresAt.value.getTime() > Date.now() &&
    approvalProxyAddressIds.value.length > 0 &&
    approvalReason.value.trim().length > 0
);

watch(
  () => props.requests.map((request) => request.request_id),
  (requestIds) => {
    if (
      approvalRequest.value &&
      !requestIds.includes(approvalRequest.value.request_id)
    ) {
      approvalRequest.value = null;
    }
    if (
      rejectionRequest.value &&
      !requestIds.includes(rejectionRequest.value.request_id)
    ) {
      rejectionRequest.value = null;
      rejectionReason.value = "";
    }
  }
);

function openApproval(request: AgentAdminKeyRequest) {
  const enabledIds = new Set(
    enabledProxyAddresses.value.map((address) => address.proxy_address_id)
  );
  approvalRequest.value = request;
  approvalProxyAddressIds.value = request.proxy_address_ids.filter((id) =>
    enabledIds.has(id)
  );
  approvalExpiresAt.value = defaultExpiry();
  approvalReason.value = "";
}

function openRejection(request: AgentAdminKeyRequest) {
  rejectionRequest.value = request;
  rejectionReason.value = "";
}

function submitRejection() {
  if (
    !rejectionRequest.value ||
    rejectionBusy.value ||
    !rejectionReason.value.trim()
  ) {
    return;
  }
  emit("reject", {
    requestId: rejectionRequest.value.request_id,
    reason: rejectionReason.value.trim()
  });
}

function submitApproval() {
  if (
    !approvalRequest.value ||
    !approvalExpiresAt.value ||
    !approvalValid.value
  ) {
    return;
  }
  emit("approve", {
    requestId: approvalRequest.value.request_id,
    expiresAt: Math.floor(approvalExpiresAt.value.getTime() / 1000),
    proxyAddressIds: [...approvalProxyAddressIds.value],
    reason: approvalReason.value.trim()
  });
}

function formatRequestTime(timestamp: number) {
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    return "时间未知";
  }
  return new Date(timestamp * 1000).toLocaleString("zh-CN", {
    hour12: false
  });
}

function requestKindLabel(request: AgentAdminKeyRequest) {
  return request.kind === "rotate" ? "更新密钥" : "首次生成";
}

function defaultExpiry() {
  const value = new Date();
  value.setDate(value.getDate() + 30);
  value.setSeconds(0, 0);
  return value;
}
</script>

<template>
  <section class="admin-request-page">
    <header class="admin-request-heading">
      <div>
        <span class="eyebrow">管理员待办</span>
        <h2>密钥申请</h2>
        <p>直接审批用户的首次生成和过期更新申请。</p>
      </div>
      <Button
        label="刷新"
        icon="pi pi-refresh"
        severity="secondary"
        outlined
        :loading="loading"
        :disabled="Boolean(busyRequestId)"
        @click="emit('refresh')"
      />
    </header>

    <div v-if="error" class="admin-request-error" role="alert">
      <AppIcon name="triangle-alert" />
      <span>{{ error }}</span>
    </div>

    <div v-if="loading && !requests.length" class="admin-request-loading">
      <ProgressSpinner />
      <span>正在读取待审批申请</span>
    </div>

    <div v-else-if="requests.length" class="admin-request-list">
      <article
        v-for="request in requests"
        :key="request.request_id"
        class="admin-request-card"
      >
        <div class="admin-request-identity">
          <img v-if="request.avatar_url" class="admin-request-avatar" :src="request.avatar_url" alt="" />
          <span v-else class="admin-request-avatar" aria-hidden="true">
            {{ request.username.slice(0, 1).toUpperCase() }}
          </span>
          <div>
            <strong :title="request.username">
              {{ request.display_name || request.username }}
            </strong>
            <span v-if="request.display_name">{{ request.username }}</span>
            <small v-if="request.email">{{ request.email }}</small>
          </div>
          <span
            :class="[
              'admin-request-kind',
              request.kind === 'rotate' ? 'rotate' : 'initial'
            ]"
          >
            {{ requestKindLabel(request) }}
          </span>
        </div>

        <div class="admin-request-meta">
          <AppIcon name="clock" />
          <span>{{ formatRequestTime(request.requested_at) }}</span>
        </div>

        <div class="admin-request-message">
          <small>申请留言</small>
          <p v-if="request.request_message">
            {{ request.request_message }}
          </p>
          <p v-else class="muted">用户没有填写留言。</p>
        </div>

        <div class="admin-request-actions">
          <Button
            label="拒绝"
            severity="danger"
            text
            :disabled="Boolean(busyRequestId)"
            @click="openRejection(request)"
          />
          <Button
            label="批准"
            icon="pi pi-check"
            :loading="busyRequestId === request.request_id"
            :disabled="Boolean(busyRequestId)"
            @click="openApproval(request)"
          />
        </div>
      </article>
    </div>

    <div v-else class="admin-request-empty">
      <AppIcon name="check-circle" />
      <strong>没有待审批的密钥申请</strong>
      <span>收到新申请后，这里会自动更新并显示通知。</span>
    </div>
  </section>

  <Dialog
    :visible="Boolean(approvalRequest)"
    modal
    header="批准密钥申请"
    :style="{ width: 'min(92vw, 620px)' }"
    :closable="!approvalBusy"
    @update:visible="$event || (approvalRequest = null)"
  >
    <div v-if="approvalRequest" class="approval-dialog-content">
      <div class="approval-user-summary">
        <img v-if="approvalRequest.avatar_url" class="admin-request-avatar" :src="approvalRequest.avatar_url" alt="" />
        <strong>{{ approvalRequest.display_name || approvalRequest.username }}</strong>
        <span>{{ requestKindLabel(approvalRequest) }}</span>
      </div>

      <fieldset class="approval-proxy-list">
        <legend>分配 Proxy 地址</legend>
        <small>至少选择一个；更新申请已预选该用户当前可用的地址。</small>
        <label
          v-for="address in enabledProxyAddresses"
          :key="address.proxy_address_id"
          :for="`admin-proxy-${address.proxy_address_id}`"
          class="approval-proxy-row"
        >
          <Checkbox
            :input-id="`admin-proxy-${address.proxy_address_id}`"
            v-model="approvalProxyAddressIds"
            :value="address.proxy_address_id"
            :disabled="approvalBusy"
          />
          <span>
            <strong>{{ address.label || "未命名 Proxy" }}</strong>
            <small>{{ address.address }}</small>
          </span>
        </label>
        <div v-if="!enabledProxyAddresses.length" class="approval-proxy-empty">
          当前没有启用的 Proxy 地址，请先在 Proxy Registry 中配置。
        </div>
      </fieldset>

      <label class="approval-expiry">
        <span>新密钥有效期</span>
        <DatePicker
          v-model="approvalExpiresAt"
          :min-date="new Date(Date.now() + 60_000)"
          :manual-input="false"
          show-time
          hour-format="24"
          show-icon
          fluid
          :disabled="approvalBusy"
        />
      </label>
      <label class="approval-expiry">
        <span>批准原因</span>
        <Textarea
          v-model="approvalReason"
          rows="4"
          maxlength="500"
          placeholder="说明批准本次密钥申请的原因"
          :disabled="approvalBusy"
          fluid
        />
        <small>{{ Array.from(approvalReason).length }} / 500，必填，仅管理员可见</small>
      </label>
    </div>
    <template #footer>
      <Button
        label="取消"
        severity="secondary"
        text
        :disabled="approvalBusy"
        @click="approvalRequest = null"
      />
      <Button
        label="批准并生成密钥"
        icon="pi pi-check"
        :loading="approvalBusy"
        :disabled="!approvalValid || approvalBusy"
        @click="submitApproval"
      />
    </template>
  </Dialog>

  <Dialog
    :visible="Boolean(rejectionRequest)"
    modal
    header="拒绝密钥申请"
    :style="{ width: 'min(92vw, 460px)' }"
    :closable="!rejectionBusy"
    @update:visible="$event || (rejectionRequest = null)"
  >
    <div v-if="rejectionRequest" class="rejection-dialog-content">
      <p class="rejection-copy">
        拒绝 <strong>{{ rejectionRequest.username }}</strong> 的{{
          requestKindLabel(rejectionRequest)
        }}申请后，用户可以查看理由并重新提交。
      </p>
      <label class="rejection-reason">
        <span>拒绝理由（用户可见）</span>
        <Textarea
          v-model="rejectionReason"
          rows="5"
          maxlength="500"
          placeholder="例如：请补充业务用途和需要的有效期后重新申请。"
          :disabled="rejectionBusy"
          fluid
        />
        <small>{{ Array.from(rejectionReason).length }} / 500，必填</small>
      </label>
    </div>
    <template #footer>
      <Button
        label="取消"
        severity="secondary"
        text
        :disabled="rejectionBusy || !rejectionReason.trim()"
        @click="rejectionRequest = null"
      />
      <Button
        label="确认拒绝"
        severity="danger"
        :loading="rejectionBusy"
        :disabled="rejectionBusy"
        @click="submitRejection"
      />
    </template>
  </Dialog>
</template>

<style scoped src="../styles/admin-key-requests.css"></style>
