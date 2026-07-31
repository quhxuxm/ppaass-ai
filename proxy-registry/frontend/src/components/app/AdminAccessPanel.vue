<script setup lang="ts">
import Button from 'primevue/button'
import InputNumber from 'primevue/inputnumber'
import AuditEventPanel from '../AuditEventPanel.vue'
import { useAppControllerContext } from '../../appController'

const {
  adminAuditEvents,
  auditAction,
  auditEventsHasMore,
  auditEventsLoading,
  auditEventsLoadingMore,
  auditSearch,
  filterAuditEvents,
  loadMoreAuditEvents,
  refreshAuditEvents,
  retentionDays,
  retentionSaving,
  saveRetentionDays,
} = useAppControllerContext()
</script>

<template>
<section class="content-card retention-card">
  <div class="retention-copy">
    <span class="retention-icon"><i class="pi pi-history" /></span>
    <div>
      <h2>访问记录保留策略</h2>
      <p>
        设置所有普通用户可查看本人访问记录的天数。默认 7 天，管理员不能借此查看任何用户的具体记录。
      </p>
    </div>
  </div>
  <div class="retention-control">
    <label for="retention-days">全局保留天数</label>
    <div>
      <InputNumber
        v-model="retentionDays"
        input-id="retention-days"
        :min="1"
        :max="365"
        :step="1"
        show-buttons
        suffix=" 天"
        :use-grouping="false"
        aria-describedby="retention-help"
      />
      <Button
        label="保存设置"
        icon="pi pi-check"
        :loading="retentionSaving"
        @click="saveRetentionDays"
      />
    </div>
    <small id="retention-help">允许范围 1–365 天；超出保留期的记录由服务端清理。</small>
  </div>
</section>

<AuditEventPanel
  :action="auditAction"
  :events="adminAuditEvents"
  :has-more="auditEventsHasMore"
  :loading="auditEventsLoading"
  :loading-more="auditEventsLoadingMore"
  :search="auditSearch"
  @filter="filterAuditEvents"
  @load-more="loadMoreAuditEvents"
  @refresh="refreshAuditEvents"
/>
</template>
