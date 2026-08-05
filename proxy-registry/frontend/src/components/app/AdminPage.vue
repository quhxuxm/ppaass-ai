<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import { useAppControllerContext } from '../../appController'
import ProxyAddressCatalog from '../ProxyAddressCatalog.vue'
import AdminAccessPanel from './AdminAccessPanel.vue'
import AdminApprovalsPanel from './AdminApprovalsPanel.vue'
import AdminUsersPanel from './AdminUsersPanel.vue'

const {
  activeAdminSection,
  adminLoading,
  adminMetrics,
  adminSectionOptions,
  openCreate,
  proxyAddresses,
  refreshAdminUsers,
  refreshProxyAddresses,
  selectAdminSection,
  session,
} = useAppControllerContext()

let proxyRefreshTimer: number | null = null
const proxyRefreshing = ref(false)

async function refreshProxyCatalog(): Promise<void> {
  if (proxyRefreshing.value) return
  proxyRefreshing.value = true
  try {
    await refreshProxyAddresses()
  } finally {
    proxyRefreshing.value = false
  }
}

onMounted(() => {
  proxyRefreshTimer = window.setInterval(() => {
    if (activeAdminSection.value === 'proxies') {
      void refreshProxyCatalog()
    }
  }, 30_000)
})
onBeforeUnmount(() => {
  if (proxyRefreshTimer !== null) window.clearInterval(proxyRefreshTimer)
})
</script>

<template>
  <section class="page-section">
    <div class="page-heading admin-heading">
      <div>
        <p class="eyebrow">ADMIN CONSOLE</p>
        <h1>用户管理</h1>
        <p>管理账户、代理连接和有效期，并可触发密钥生成；连接凭据只由账户本人授权的 Agent 领取。</p>
      </div>
      <div class="admin-heading-actions">
        <Tag
          :value="`Registry：${session?.registryInstanceId || 'unknown'}`"
          severity="info"
          icon="pi pi-server"
          rounded
        />
        <Button label="新建普通用户" icon="pi pi-user-plus" @click="openCreate" />
      </div>
    </div>

    <div class="summary-grid admin-summary">
      <article class="summary-card">
        <span class="summary-icon blue"><i class="pi pi-users" /></span>
        <div><small>全部用户</small><strong>{{ adminMetrics.total }}</strong></div>
      </article>
      <article class="summary-card">
        <span class="summary-icon green"><i class="pi pi-check" /></span>
        <div><small>启用账号</small><strong>{{ adminMetrics.activeAccounts }}</strong></div>
      </article>
      <article class="summary-card">
        <span class="summary-icon red"><i class="pi pi-ban" /></span>
        <div><small>停用账号</small><strong>{{ adminMetrics.disabledAccounts }}</strong></div>
      </article>
      <article class="summary-card pending-metric">
        <span class="summary-icon orange"><i class="pi pi-bell" /></span>
        <div><small>待审批申请</small><strong>{{ adminMetrics.pending }}</strong></div>
      </article>
    </div>

    <nav class="admin-section-tabs" aria-label="管理员工作区" role="tablist">
      <button
        v-for="section in adminSectionOptions"
        :key="section.value"
        type="button"
        role="tab"
        :aria-selected="activeAdminSection === section.value"
        :class="{ active: activeAdminSection === section.value }"
        @click="selectAdminSection(section.value)"
      >
        <i :class="section.icon" />
        <span>{{ section.label }}</span>
        <small v-if="section.count !== null">{{ section.count }}</small>
      </button>
    </nav>

    <AdminApprovalsPanel v-if="activeAdminSection === 'approvals'" />
    <ProxyAddressCatalog
      v-if="activeAdminSection === 'proxies'"
      :addresses="proxyAddresses"
      :loading="adminLoading"
      :refreshing="proxyRefreshing"
      @changed="refreshAdminUsers"
      @refresh="refreshProxyCatalog"
    />
    <AdminAccessPanel v-if="activeAdminSection === 'audit'" />
    <AdminUsersPanel v-if="activeAdminSection === 'users'" />
  </section>
</template>
