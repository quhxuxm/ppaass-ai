<script setup lang="ts">
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Tag from 'primevue/tag'
import type { AuditAction, AuditEvent } from '../api'

defineProps<{
  events: AuditEvent[]
  loading: boolean
}>()

const emit = defineEmits<{ refresh: [] }>()

const actionLabels: Record<AuditAction, string> = {
  key_request_approved: '批准密钥申请',
  key_request_rejected: '拒绝密钥申请',
  key_regenerated: '重生成密钥',
  proxy_access_enabled: '启用代理连接',
  proxy_access_disabled: '禁用代理连接',
  web_login_enabled: '允许 Web 登录',
  web_login_disabled: '禁止 Web 登录',
  proxy_server_enabled: '启用服务器',
  proxy_server_disabled: '停用服务器',
  permissions_updated: '分配用户权限',
}

function actionSeverity(action: AuditAction): 'success' | 'danger' | 'warn' | 'info' {
  if (action.endsWith('_disabled') || action === 'key_request_rejected') {
    return 'danger'
  }
  if (action === 'key_regenerated' || action === 'permissions_updated') {
    return 'warn'
  }
  return action.endsWith('_enabled') || action === 'key_request_approved'
    ? 'success'
    : 'info'
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(value))
}

function parsePermissions(value: string | null): string[] | null {
  if (!value) return null
  try {
    const parsed: unknown = JSON.parse(value)
    return Array.isArray(parsed) && parsed.every((item) => typeof item === 'string')
      ? parsed
      : null
  } catch {
    return null
  }
}

function changeSummary(event: AuditEvent): string {
  if (event.action === 'permissions_updated') {
    const previous = parsePermissions(event.previousValue) ?? []
    const next = parsePermissions(event.newValue) ?? []
    const added = next.filter((permission) => !previous.includes(permission))
    const removed = previous.filter((permission) => !next.includes(permission))
    const parts = [
      added.length ? `新增：${added.join('、')}` : '',
      removed.length ? `移除：${removed.join('、')}` : '',
    ].filter(Boolean)
    return parts.join('；') || '权限集合未变化'
  }
  if (event.action === 'key_regenerated') {
    return `密钥版本 ${event.previousValue ?? '—'} → ${event.newValue ?? '—'}`
  }
  if (event.contextId) {
    return `申请编号：${event.contextId}`
  }
  return `${event.previousValue ?? '—'} → ${event.newValue ?? '—'}`
}
</script>

<template>
  <section class="content-card audit-card" aria-labelledby="audit-title">
    <header class="audit-header">
      <div>
        <span class="audit-icon"><i class="pi pi-shield" /></span>
        <div>
          <h2 id="audit-title">操作审计</h2>
          <p>仅管理员可见，记录敏感操作的执行人、目标、原因和变更结果。</p>
        </div>
      </div>
      <Button
        icon="pi pi-refresh"
        label="刷新"
        severity="secondary"
        outlined
        size="small"
        :loading="loading"
        @click="emit('refresh')"
      />
    </header>

    <DataTable
      class="audit-table"
      :value="events"
      :loading="loading"
      data-key="id"
      paginator
      :rows="10"
      :rows-per-page-options="[10, 25, 50]"
      scrollable
      table-style="width: 100%; min-width: 76rem; table-layout: fixed"
    >
      <template #empty>
        <div class="audit-empty">
          <i class="pi pi-history" />
          <span>还没有敏感操作审计记录</span>
        </div>
      </template>
      <Column header="时间" style="width: 13%">
        <template #body="{ data }">
          <span class="audit-time">{{ formatTime(data.createdAt) }}</span>
        </template>
      </Column>
      <Column header="操作" style="width: 12%">
        <template #body="{ data }">
          <Tag
            class="audit-action"
            :value="actionLabels[data.action as AuditAction]"
            :severity="actionSeverity(data.action)"
          />
        </template>
      </Column>
      <Column header="操作者" style="width: 11%">
        <template #body="{ data }">
          <strong class="audit-actor" :title="data.actorAccountId">
            {{ data.actorLoginName }}
          </strong>
        </template>
      </Column>
      <Column header="操作目标" style="width: 14%">
        <template #body="{ data }">
          <div class="audit-target">
            <strong :title="data.targetId">{{ data.targetName }}</strong>
            <small>{{ data.targetKind === 'proxy_server' ? 'Proxy 服务器' : '用户' }}</small>
          </div>
        </template>
      </Column>
      <Column header="操作原因" style="width: 18%">
        <template #body="{ data }">
          <span class="audit-reason" :title="data.reason || '用户本人操作'">
            {{ data.reason || '用户本人操作' }}
          </span>
        </template>
      </Column>
      <Column header="变更详情" style="width: 32%">
        <template #body="{ data }">
          <span class="audit-change" :title="changeSummary(data)">
            {{ changeSummary(data) }}
          </span>
        </template>
      </Column>
    </DataTable>
  </section>
</template>

<style scoped>
.audit-card { margin-top: 20px; overflow: hidden; }
.audit-header, .audit-header > div { display: flex; align-items: center; gap: 1rem; }
.audit-header { min-height: 88px; justify-content: space-between; padding: 20px 22px; }
.audit-header h2, .audit-header p { margin: 0; }
.audit-header h2 { color: #101828; font-size: 1.04rem; }
.audit-header p { margin-top: 6px; color: #667085; font-size: .77rem; line-height: 1.5; }
.audit-icon { display: grid; place-items: center; width: 48px; height: 48px; border-radius: 14px;
  color: #155eef; background: #eaf1ff; font-size: 1.05rem; flex: 0 0 auto; }
.audit-table :deep(.p-datatable-table-container) { overflow-x: auto; }
.audit-table :deep(.p-datatable-header-cell) {
  color: #667085;
  font-size: .72rem;
  font-weight: 650;
  background: #f8fafc;
}
.audit-table :deep(.p-datatable-thead > tr > th),
.audit-table :deep(.p-datatable-tbody > tr > td) { min-width: 0; overflow: hidden; }
.audit-table :deep(.p-datatable-tbody > tr > td) {
  padding-block: 14px;
  vertical-align: top;
  color: #475467;
  font-size: .8rem;
}
.audit-time, .audit-actor { display: block; max-width: 100%; white-space: nowrap; }
.audit-action { max-width: 100%; font-size: .72rem; white-space: nowrap; }
.audit-actor { overflow: hidden; text-overflow: ellipsis; }
.audit-target { display: flex; flex-direction: column; gap: .2rem; min-width: 0; }
.audit-target strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.audit-reason, .audit-change {
  display: -webkit-box;
  max-width: 100%;
  overflow: hidden;
  overflow-wrap: anywhere;
  white-space: normal;
  line-height: 1.45;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}
.audit-target small { color: var(--text-muted); }
.audit-empty { display: flex; align-items: center; justify-content: center; gap: .7rem; padding: 3rem; color: var(--text-muted); }
@media (max-width: 700px) {
  .audit-header { align-items: flex-start; }
  .audit-header > div { align-items: flex-start; }
  .audit-header :deep(.p-button-label) { display: none; }
}
</style>
