<script setup lang="ts">
import Avatar from 'primevue/avatar'
import Button from 'primevue/button'
import { useAppControllerContext } from '../../appController'

const {
  account,
  activePage,
  isAdmin,
  isAgentHandoffSession,
  performLogout,
} = useAppControllerContext()
</script>

<template>
<header class="topbar">
  <a class="brand compact" href="/" aria-label="PPAASS 首页">
    <span class="brand-mark"><i class="pi pi-shield" /></span>
    <span>
      <strong>PPAASS</strong>
      <small>用户中心</small>
    </span>
  </a>

  <nav class="main-nav" aria-label="主导航">
    <button
      type="button"
      :class="{ active: activePage === 'account' }"
      @click="activePage = 'account'"
    >
      <i class="pi pi-id-card" /> 我的账户
    </button>
    <button
      v-if="isAdmin"
      type="button"
      :class="{ active: activePage === 'admin' }"
      @click="activePage = 'admin'"
    >
      <i class="pi pi-users" /> 用户管理
    </button>
  </nav>

  <div class="account-menu">
    <Avatar
      :image="account?.avatarUrl || undefined"
      :label="
        account?.avatarUrl
          ? undefined
          : (account?.displayName || account?.username || 'U')
              .slice(0, 1)
              .toUpperCase()
      "
      shape="circle"
    />
    <span class="account-menu-copy">
      <strong>{{ account?.displayName || account?.username }}</strong>
      <small>{{ account?.role === 'admin' ? '管理员' : '普通用户' }}</small>
    </span>
    <Button
      :class="[
        'topbar-logout-action',
        { 'agent-handoff-logout': isAgentHandoffSession },
      ]"
      v-tooltip.bottom="'退出登录'"
      icon="pi pi-sign-out"
      label="退出登录"
      severity="secondary"
      text
      rounded
      aria-label="退出登录"
      @click="performLogout"
    />
  </div>
</header>
</template>
