<script setup lang="ts">
import Button from "primevue/button";
import AppIcon, { type AppIconName } from "./AppIcon";
import type { TabKey } from "../types";

defineProps<{
  tabs: Array<{ key: TabKey; label: string; icon: AppIconName }>;
  activeTab: TabKey;
  collapsed: boolean;
  accountUsername: string;
  accountDisplayName: string | null;
  accountAvatarUrl: string | null;
  accountRole: "user" | "admin";
  accountManagementBusy: boolean;
  adminRequestCount: number;
  canRotateKey: boolean;
  keyRotationBusy: boolean;
  logoutBusy: boolean;
  busy: boolean;
}>();

const emit = defineEmits<{
  "update:activeTab": [value: TabKey];
  "update:collapsed": [value: boolean];
  manageAccount: [];
  rotateKey: [];
  logout: [];
}>();
</script>

<template>
  <aside :class="['sidebar', { collapsed }]">
    <div class="brand">
      <div class="brand-mark">
        <img src="/app-icon.png" alt="" aria-hidden="true" />
      </div>
      <div class="brand-copy">
        <div class="brand-title">PPAASS</div>
        <div class="brand-subtitle">桌面代理</div>
      </div>
      <Button
        class="sidebar-toggle"
        text
        rounded
        :aria-label="collapsed ? '展开导航' : '收起导航'"
        :title="collapsed ? '展开导航' : '收起导航'"
        @click="emit('update:collapsed', !collapsed)"
      >
        <template #icon="slotProps">
          <AppIcon :class="slotProps.class" :name="collapsed ? 'chevron-right' : 'chevron-left'" />
        </template>
      </Button>
    </div>

    <nav class="nav">
      <Button
        v-for="tab in tabs"
        :key="tab.key"
        :class="[
          'nav-button',
          {
            active: activeTab === tab.key,
            'nav-button-count-badge':
              tab.key === 'admin-requests' && adminRequestCount > 0,
            'nav-button-count-badge-wide':
              tab.key === 'admin-requests' && adminRequestCount > 9
          }
        ]"
        :label="tab.label"
        :title="tab.label"
        :badge="
          tab.key === 'admin-requests' && adminRequestCount
            ? String(adminRequestCount)
            : undefined
        "
        :badge-class="
          tab.key === 'admin-requests' && adminRequestCount
            ? {
                'nav-request-badge': true,
                'nav-request-badge-circle': adminRequestCount < 10,
                'nav-request-badge-wide': adminRequestCount >= 10
              }
            : undefined
        "
        badge-severity="danger"
        text
        @click="emit('update:activeTab', tab.key)"
      >
        <template #icon="slotProps">
          <AppIcon :class="[slotProps.class, 'nav-icon-plate']" :name="tab.icon" />
        </template>
      </Button>
    </nav>

    <section class="sidebar-account" :title="`当前账户：${accountUsername}`">
      <div class="sidebar-account-identity">
        <span class="sidebar-account-avatar" aria-hidden="true">
          <img v-if="accountAvatarUrl" :src="accountAvatarUrl" alt="" />
          <AppIcon v-else name="user" />
        </span>
        <span class="sidebar-account-copy">
          <small>{{ accountRole === "admin" ? "管理员" : "普通用户" }}</small>
          <strong>{{ accountDisplayName || accountUsername }}</strong>
        </span>
      </div>
      <Button
        class="sidebar-account-action"
        :label="accountRole === 'admin' ? '管理用户' : '账户管理'"
        severity="secondary"
        text
        :loading="accountManagementBusy"
        :disabled="busy || accountManagementBusy || keyRotationBusy || logoutBusy"
        @click="emit('manageAccount')"
      >
        <template #icon="slotProps">
          <AppIcon :class="slotProps.class" name="user" />
        </template>
      </Button>
      <Button
        v-if="canRotateKey"
        class="sidebar-account-action"
        label="生成新密钥"
        severity="secondary"
        text
        :loading="keyRotationBusy"
        :disabled="busy || accountManagementBusy || keyRotationBusy || logoutBusy"
        @click="emit('rotateKey')"
      >
        <template #icon="slotProps">
          <AppIcon :class="slotProps.class" name="key" />
        </template>
      </Button>
      <Button
        class="sidebar-logout"
        label="退出"
        severity="secondary"
        text
        :loading="logoutBusy"
        :disabled="busy || accountManagementBusy || keyRotationBusy || logoutBusy"
        aria-label="退出当前账户"
        title="退出当前账户"
        @click="emit('logout')"
      >
        <template #icon="slotProps">
          <AppIcon :class="slotProps.class" name="log-out" />
        </template>
      </Button>
    </section>
  </aside>
</template>
