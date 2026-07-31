<script setup lang="ts">
import ProgressSpinner from 'primevue/progressspinner'
import Tag from 'primevue/tag'
import { useAppControllerContext } from '../../appController'
import AccessRecordsPanel from './AccessRecordsPanel.vue'
import AccountIdentityPanel from './AccountIdentityPanel.vue'
import AccountSecurityPanel from './AccountSecurityPanel.vue'

const { account, pageLoading } = useAppControllerContext()
</script>

<template>
  <section class="page-section">
    <div class="page-heading">
      <div>
        <p class="eyebrow">ACCOUNT OVERVIEW</p>
        <h1>我的代理身份</h1>
        <p>查看当前身份状态、连接权限和账户安全设置。</p>
      </div>
      <Tag
        :value="account?.status === 'active' ? '账号已启用' : '账号已停用'"
        :severity="account?.status === 'active' ? 'success' : 'danger'"
        rounded
      />
    </div>

    <div v-if="pageLoading" class="content-loading">
      <ProgressSpinner stroke-width="4" />
      <span>正在读取账户信息…</span>
    </div>

    <template v-else>
      <AccountIdentityPanel />
      <AccountSecurityPanel />
      <AccessRecordsPanel />
    </template>
  </section>
</template>
