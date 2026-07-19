<script setup lang="ts">
import Button from "primevue/button";
import Tag from "primevue/tag";
import AppIcon, { type AppIconName } from "./AppIcon";
import { shortPath } from "../formatters";
import type { TabKey } from "../types";

defineProps<{
  tabs: Array<{ key: TabKey; label: string; icon: AppIconName }>;
  activeTab: TabKey;
  collapsed: boolean;
  running: boolean;
  runningLabel: string;
  runningSeverity: string;
  pid?: number | null;
  configPath?: string | null;
}>();

const emit = defineEmits<{
  "update:activeTab": [value: TabKey];
  "update:collapsed": [value: boolean];
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

    <div class="sidebar-status">
      <Tag :severity="runningSeverity" :value="runningLabel" rounded />
      <div class="sidebar-meta">
        <span>PID</span>
        <strong>{{ running && pid ? pid : "—" }}</strong>
      </div>
      <div class="sidebar-meta">
        <span>配置</span>
        <strong :title="configPath ?? ''">{{ shortPath(configPath) }}</strong>
      </div>
    </div>
  </aside>
</template>
