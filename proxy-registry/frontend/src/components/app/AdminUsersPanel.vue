<script setup lang="ts">
import Avatar from 'primevue/avatar'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import InputText from 'primevue/inputtext'
import Tag from 'primevue/tag'
import { useAppControllerContext } from '../../appController'

const {
  accountStatusLabel,
  adminLoading,
  adminSearch,
  canAdminRotateDirectly,
  confirmDelete,
  confirmRotateAdminKey,
  deleteBlockedReason,
  deletingUsername,
  filteredAdminUsers,
  formatExpiry,
  isRootAdmin,
  managedAgentPermissions,
  managedCustomPermissions,
  managedHiddenPermissionCount,
  managedPermissionsTitle,
  managedProxyAddressesTitle,
  managedUsername,
  openEdit,
  refreshAdminUsers,
  rotatingUsername,
} = useAppControllerContext()
</script>

<template>
<section class="content-card users-card">
  <div class="table-toolbar">
    <div>
      <h2>用户列表</h2>
      <p>历史数据库用户没有 Web 登录账号；如需登录，请由管理员新建正式账号。</p>
    </div>
    <div class="table-actions">
      <span class="search-box">
        <i class="pi pi-search" />
        <InputText
          v-model="adminSearch"
          placeholder="搜索用户名或邮箱"
          aria-label="搜索用户"
        />
      </span>
      <Button
        v-tooltip.top="'刷新'"
        icon="pi pi-refresh"
        severity="secondary"
        outlined
        aria-label="刷新用户列表"
        :loading="adminLoading"
        @click="refreshAdminUsers"
      />
    </div>
  </div>

  <DataTable
    :value="filteredAdminUsers"
    :loading="adminLoading"
    data-key="profile.username"
    paginator
    :rows="10"
    :rows-per-page-options="[10, 25, 50]"
    scrollable
    table-style="min-width: 72rem"
    paginator-template="FirstPageLink PrevPageLink PageLinks NextPageLink LastPageLink RowsPerPageDropdown"
    current-page-report-template="第 {first}–{last} 条，共 {totalRecords} 条"
  >
    <template #empty>
      <div class="table-empty">
        <i class="pi pi-users" />
        <span>{{ adminSearch ? '没有匹配的用户' : '还没有用户' }}</span>
      </div>
    </template>
    <Column header="用户" frozen style="min-width: 11.5rem">
      <template #body="{ data }">
        <div class="user-cell">
          <Avatar :label="managedUsername(data).slice(0, 1).toUpperCase()" shape="circle" />
          <span>
            <strong :title="managedUsername(data)">
              {{ managedUsername(data) }}
            </strong>
          </span>
        </div>
      </template>
    </Column>
    <Column header="角色" style="min-width: 7rem">
      <template #body="{ data }">
        <div class="tag-stack">
          <Tag
            :value="
              isRootAdmin(data)
                ? '根管理员'
                : data.account?.role === 'admin'
                  ? '管理员'
                  : '普通用户'
            "
            :severity="data.account?.role === 'admin' ? 'info' : 'secondary'"
          />
        </div>
      </template>
    </Column>
    <Column header="状态" style="min-width: 5rem">
      <template #body="{ data }">
        <span
          class="account-status-indicator"
          :class="{ active: data.account?.status === 'active' }"
          :title="accountStatusLabel(data)"
          :aria-label="accountStatusLabel(data)"
          role="img"
        />
      </template>
    </Column>
    <Column header="密钥有效期" style="min-width: 9.5rem">
      <template #body="{ data }">
        <span
          class="key-expiry-value"
          :class="{ expired: data.keyState === 'expired' }"
          :title="data.keyState === 'expired' ? '密钥已过期' : undefined"
        >
          {{ data.profile ? formatExpiry(data.profile.expiresAt) : '—' }}
        </span>
      </template>
    </Column>
    <Column header="Proxy 地址" style="min-width: 10rem">
      <template #body="{ data }">
        <div
          v-if="data.proxyAddresses.length"
          class="permission-tags user-list-tag-summary"
          :title="managedProxyAddressesTitle(data)"
          :aria-label="managedProxyAddressesTitle(data)"
        >
          <Tag
            v-for="address in data.proxyAddresses.slice(0, 1)"
            :key="address.id"
            :value="address.label"
            severity="info"
            class="user-list-tag-summary-primary"
          />
          <Tag
            v-if="data.proxyAddresses.length > 1"
            :value="`+${data.proxyAddresses.length - 1}`"
            severity="secondary"
            rounded
            class="user-list-tag-summary-count"
          />
        </div>
        <Tag v-else value="未分配" severity="danger" />
      </template>
    </Column>
    <Column header="Agent 权限" style="min-width: 18rem">
      <template #body="{ data }">
        <div
          v-if="data.account?.role === 'admin'"
          class="permission-tags user-permission-tags user-list-tag-summary"
          :title="managedPermissionsTitle(data)"
          :aria-label="managedPermissionsTitle(data)"
        >
          <Tag value="Agent 全权限" severity="info" />
        </div>
        <div
          v-else-if="data.profile"
          class="permission-tags user-permission-tags user-list-tag-summary"
          :title="managedPermissionsTitle(data)"
          :aria-label="managedPermissionsTitle(data)"
        >
          <Tag
            v-for="permission in managedAgentPermissions(data).slice(0, 2)"
            :key="permission.code"
            :value="permission.label"
            severity="secondary"
            class="user-list-tag-summary-primary"
          />
          <Tag
            v-if="managedHiddenPermissionCount(data)"
            :value="`+${managedHiddenPermissionCount(data)} 项`"
            severity="secondary"
            rounded
            class="user-list-tag-summary-count"
          />
          <Tag
            v-if="
              !managedAgentPermissions(data).length &&
              !managedCustomPermissions(data).length
            "
            value="Agent 基础功能"
            severity="secondary"
          />
        </div>
        <span v-else>—</span>
      </template>
    </Column>
    <Column
      header="操作"
      frozen
      align-frozen="right"
      style="min-width: 8.5rem"
    >
      <template #body="{ data }">
        <div class="row-actions">
          <Button
            v-if="canAdminRotateDirectly(data)"
            v-tooltip.top="'重新生成有效期内的密钥'"
            icon="pi pi-refresh"
            severity="warn"
            text
            rounded
            aria-label="重新生成用户密钥"
            :loading="rotatingUsername === managedUsername(data)"
            @click="confirmRotateAdminKey(data)"
          />
          <Button
            v-tooltip.top="data.profile?.origin === 'legacy' ? '查看兼容配置' : '编辑'"
            :icon="data.profile?.origin === 'legacy' ? 'pi pi-eye' : 'pi pi-pencil'"
            severity="secondary"
            text
            rounded
            aria-label="编辑用户"
            @click="openEdit(data)"
          />
          <span
            class="row-action-tooltip"
            v-tooltip.top="deleteBlockedReason(data) || '删除用户'"
          >
            <Button
              icon="pi pi-trash"
              severity="danger"
              text
              rounded
              :aria-label="
                deleteBlockedReason(data) || '删除用户'
              "
              :loading="deletingUsername === managedUsername(data)"
              :disabled="Boolean(deleteBlockedReason(data))"
              @click="confirmDelete(data)"
            />
          </span>
        </div>
      </template>
    </Column>
  </DataTable>
</section>
</template>
