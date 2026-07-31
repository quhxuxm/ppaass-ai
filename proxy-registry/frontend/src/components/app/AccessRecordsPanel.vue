<script setup lang="ts">
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import InputText from 'primevue/inputtext'
import Tag from 'primevue/tag'
import { useAppControllerContext } from '../../appController'

const {
  accessHostFilter,
  accessRecordsFirst,
  accessRecordsLoading,
  accessRetentionDays,
  filteredAccessRecords,
  formatExpiry,
  refreshAccessRecords,
} = useAppControllerContext()
</script>

<template>
<section class="content-card access-records-card">
  <div class="table-toolbar">
    <div>
      <h2>最近访问</h2>
      <p>
        仅显示你本人最近 {{ accessRetentionDays }} 天内访问过的目标；相同地址合并并累计次数。
      </p>
    </div>
    <div class="table-actions">
      <span class="search-box">
        <i class="pi pi-search" />
        <InputText
          v-model="accessHostFilter"
          type="search"
          placeholder="过滤主机名或 IP"
          aria-label="过滤访问主机"
        />
      </span>
      <Button
        label="刷新"
        icon="pi pi-refresh"
        severity="secondary"
        outlined
        size="small"
        :loading="accessRecordsLoading"
        @click="refreshAccessRecords()"
      />
    </div>
  </div>
  <div class="access-privacy-note">
    <i class="pi pi-info-circle" />
    <span>
      对 HTTPS 连接，代理只能记录目标域名或 IP、最近使用的端口和传输方式，不会看到或记录具体页面 URL 与路径。
    </span>
  </div>
  <DataTable
    :value="filteredAccessRecords"
    :loading="accessRecordsLoading"
    :paginator="filteredAccessRecords.length > 10"
    :rows="10"
    v-model:first="accessRecordsFirst"
    data-key="targetHost"
    sort-field="accessedAt"
    :sort-order="-1"
    removable-sort
    scrollable
    table-style="min-width: 53rem"
  >
    <template #empty>
      <div class="table-empty access-empty">
        <i class="pi pi-history" />
        <span>
          {{
            accessHostFilter.trim()
              ? '没有匹配的主机'
              : '保留周期内暂无代理访问记录'
          }}
        </span>
      </div>
    </template>
    <Column
      field="accessedAt"
      header="最近访问"
      sortable
      style="min-width: 13rem"
    >
      <template #body="{ data }">
        {{ formatExpiry(data.accessedAt) }}
      </template>
    </Column>
    <Column
      field="targetHost"
      header="目标域名 / IP"
      sortable
      style="min-width: 17rem"
    >
      <template #body="{ data }">
        <code class="target-host">{{ data.targetHost }}</code>
      </template>
    </Column>
    <Column field="targetPort" header="端口" sortable style="min-width: 6rem">
      <template #body="{ data }">
        <code>{{ data.targetPort }}</code>
      </template>
    </Column>
    <Column field="transport" header="传输" sortable style="min-width: 7rem">
      <template #body="{ data }">
        <Tag
          :value="data.transport.toUpperCase()"
          :severity="data.transport === 'tcp' ? 'info' : 'warn'"
          rounded
        />
      </template>
    </Column>
    <Column field="accessCount" header="访问次数" sortable style="min-width: 7rem">
      <template #body="{ data }">
        <strong>{{ data.accessCount }} 次</strong>
      </template>
    </Column>
  </DataTable>
</section>
</template>
