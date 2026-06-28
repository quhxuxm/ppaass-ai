<script setup lang="ts">
import Button from "primevue/button";
import Tag from "primevue/tag";
import { shortPath } from "../formatters";
import type { TabKey } from "../types";

defineProps<{
  tabs: Array<{ key: TabKey; label: string; icon: string }>;
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
      <div class="brand-mark">P</div>
      <div class="brand-copy">
        <div class="brand-title">PPAASS</div>
        <div class="brand-subtitle">桌面代理</div>
      </div>
      <Button
        class="sidebar-toggle"
        :icon="collapsed ? 'pi pi-angle-right' : 'pi pi-angle-left'"
        text
        rounded
        :aria-label="collapsed ? '展开导航' : '收起导航'"
        :title="collapsed ? '展开导航' : '收起导航'"
        @click="emit('update:collapsed', !collapsed)"
      />
    </div>

    <nav class="nav">
      <Button
        v-for="tab in tabs"
        :key="tab.key"
        :class="['nav-button', { active: activeTab === tab.key }]"
        :icon="tab.icon"
        :label="tab.label"
        :title="tab.label"
        text
        @click="emit('update:activeTab', tab.key)"
      />
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
