<script setup lang="ts">
import Avatar from 'primevue/avatar'
import Button from 'primevue/button'
import ProgressSpinner from 'primevue/progressspinner'
import Tag from 'primevue/tag'
import RequestMessage from '../RequestMessage.vue'
import { useAppControllerContext } from '../../appController'

const {
  adminKeyRequests,
  approvalSaving,
  confirmRejectKeyRequest,
  formatExpiry,
  keyRequestKindLabel,
  keyRequestsLoading,
  openApproval,
  refreshAdminUsers,
  rejectingRequestId,
} = useAppControllerContext()
</script>

<template>
<section class="content-card approval-card">
  <div class="approval-card-heading">
    <div class="approval-title">
      <span class="approval-title-icon"><i class="pi pi-key" /></span>
      <div>
        <h2>密钥申请审批</h2>
        <p>批准时只设置有效期并触发生成，连接凭据只能由用户授权的 Agent 领取。</p>
      </div>
    </div>
    <div class="approval-heading-actions">
      <Tag
        :value="`${adminKeyRequests.length} 项待处理`"
        :severity="adminKeyRequests.length ? 'warn' : 'success'"
        rounded
      />
      <Button
        v-tooltip.top="'刷新申请'"
        icon="pi pi-refresh"
        severity="secondary"
        text
        rounded
        aria-label="刷新密钥申请"
        :loading="keyRequestsLoading"
        @click="refreshAdminUsers"
      />
    </div>
  </div>

  <div v-if="keyRequestsLoading && !adminKeyRequests.length" class="approval-loading">
    <ProgressSpinner stroke-width="4" />
    <span>正在读取待审批申请…</span>
  </div>
  <div v-else-if="adminKeyRequests.length" class="approval-list">
    <article
      v-for="request in adminKeyRequests"
      :key="request.id"
      class="approval-item"
    >
      <Avatar
        :image="request.avatarUrl || undefined"
        :label="request.username.slice(0, 1).toUpperCase()"
        shape="circle"
      />
      <div class="approval-request-main">
        <div class="approval-user">
          <strong>{{ request.displayName || request.username }}</strong>
          <span>
            {{ request.username }}
            <template v-if="request.email"> · {{ request.email }}</template>
          </span>
        </div>
        <RequestMessage
          :message="request.requestMessage"
          compact
        />
      </div>
      <Tag
        :value="keyRequestKindLabel(request)"
        :severity="request.kind === 'rotate' ? 'warn' : 'info'"
      />
      <span class="approval-time">
        <i class="pi pi-clock" />
        {{ request.createdAt ? formatExpiry(request.createdAt) : '刚刚提交' }}
      </span>
      <div class="approval-actions">
        <Button
          label="拒绝"
          icon="pi pi-times"
          severity="danger"
          outlined
          size="small"
          :loading="rejectingRequestId === request.id"
          :disabled="approvalSaving"
          @click="confirmRejectKeyRequest(request)"
        />
        <Button
          label="批准并设置有效期"
          icon="pi pi-check"
          size="small"
          :disabled="rejectingRequestId !== ''"
          @click="openApproval(request)"
        />
      </div>
    </article>
  </div>
  <div v-else class="approval-empty">
    <span><i class="pi pi-check-circle" /></span>
    <div>
      <strong>没有待审批的密钥申请</strong>
      <small>首次申请和过期重生成申请会显示在这里。</small>
    </div>
  </div>
</section>
</template>
