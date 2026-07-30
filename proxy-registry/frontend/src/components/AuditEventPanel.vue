<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import type { AuditAction, AuditEvent } from '../api'

const props = defineProps<{
  action: AuditAction | null
  events: AuditEvent[]
  hasMore: boolean
  loading: boolean
  loadingMore: boolean
  search: string
}>()

const emit = defineEmits<{
  filter: [search: string, action: AuditAction | null]
  loadMore: []
  refresh: []
}>()

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
const search = ref(props.search)
const selectedAction = ref<AuditAction | null>(props.action)
const actionOptions = Object.entries(actionLabels).map(([value, label]) => ({
  label,
  value: value as AuditAction,
}))
const hasFilter = computed(
  () => Boolean(search.value.trim()) || selectedAction.value !== null,
)

watch(
  () => [props.search, props.action] as const,
  ([nextSearch, nextAction]) => {
    search.value = nextSearch
    selectedAction.value = nextAction
  },
)

function applyFilter(): void {
  emit('filter', search.value.trim(), selectedAction.value)
}

function resetFilter(): void {
  search.value = ''
  selectedAction.value = null
  applyFilter()
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

    <form class="audit-filter" @submit.prevent="applyFilter">
      <span class="audit-search">
        <i class="pi pi-search" />
        <InputText
          v-model="search"
          maxlength="120"
          placeholder="搜索操作者、目标、原因或申请编号"
          aria-label="搜索审计记录"
        />
      </span>
      <Select
        v-model="selectedAction"
        :options="actionOptions"
        option-label="label"
        option-value="value"
        placeholder="全部操作类型"
        show-clear
        aria-label="按操作类型筛选"
      />
      <Button type="submit" label="查询" icon="pi pi-search" :loading="loading" />
      <Button
        v-if="hasFilter"
        type="button"
        label="重置"
        severity="secondary"
        text
        :disabled="loading"
        @click="resetFilter"
      />
    </form>

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
    <footer v-if="events.length" class="audit-footer">
      <span>已加载 {{ events.length }} 条记录</span>
      <Button
        v-if="hasMore"
        label="加载更早记录"
        icon="pi pi-angle-down"
        severity="secondary"
        outlined
        size="small"
        :loading="loadingMore"
        :disabled="loading"
        @click="emit('loadMore')"
      />
      <small v-else>已显示全部匹配记录</small>
    </footer>
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
.audit-filter {
  display: grid;
  grid-template-columns: minmax(240px, 1fr) minmax(190px, 240px) auto auto;
  align-items: center;
  gap: 10px;
  padding: 14px 22px;
  border-top: 1px solid #eaecf0;
  border-bottom: 1px solid #eaecf0;
  background: #fcfcfd;
}
.audit-search { position: relative; min-width: 0; }
.audit-search > i {
  position: absolute;
  top: 50%;
  left: 13px;
  z-index: 1;
  color: #98a2b3;
  font-size: .8rem;
  transform: translateY(-50%);
}
.audit-search .p-inputtext { width: 100%; padding-left: 35px; }
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
.audit-footer {
  min-height: 62px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 14px;
  padding: 10px 22px;
  color: #667085;
  font-size: .72rem;
  border-top: 1px solid #eaecf0;
  background: #fcfcfd;
}
.audit-footer small { color: #98a2b3; }
@media (max-width: 700px) {
  .audit-header { align-items: flex-start; }
  .audit-header > div { align-items: flex-start; }
  .audit-header :deep(.p-button-label) { display: none; }
  .audit-filter { grid-template-columns: 1fr; }
  .audit-filter > .p-select { width: 100%; }
  .audit-footer { align-items: stretch; flex-direction: column; }
}
</style>
