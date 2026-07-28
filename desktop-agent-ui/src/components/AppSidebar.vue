<script setup lang="ts">
import Button from "primevue/button";
import AppIcon, { type AppIconName } from "./AppIcon";
import type { TabKey } from "../types";

defineProps<{
  tabs: Array<{ key: TabKey; label: string; icon: AppIconName }>;
  activeTab: TabKey;
  collapsed: boolean;
  accountUsername: string;
  logoutBusy: boolean;
  busy: boolean;
}>();

const emit = defineEmits<{
  "update:activeTab": [value: TabKey];
  "update:collapsed": [value: boolean];
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
        :class="['nav-button', { active: activeTab === tab.key }]"
        :label="tab.label"
        :title="tab.label"
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
          <AppIcon name="user" />
        </span>
        <span class="sidebar-account-copy">
          <small>当前账户</small>
          <strong>{{ accountUsername }}</strong>
        </span>
      </div>
      <Button
        class="sidebar-logout"
        label="退出"
        severity="secondary"
        text
        :loading="logoutBusy"
        :disabled="busy || logoutBusy"
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
