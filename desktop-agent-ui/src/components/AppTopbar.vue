<script setup lang="ts">
import Button from "primevue/button";
import AppIcon from "./AppIcon";

defineProps<{
  subtitle: string;
  running: boolean;
  configLocked: boolean;
  configAvailable: boolean;
  dirty: boolean;
  busy: boolean;
}>();

const emit = defineEmits<{
  reload: [];
  "restore-default-config": [];
  save: [];
  start: [];
  stop: [];
}>();
</script>

<template>
  <header class="topbar">
    <div>
      <h1>桌面代理</h1>
      <p>{{ subtitle }}</p>
    </div>
    <div class="toolbar">
      <Button severity="secondary" outlined rounded aria-label="重新载入" @click="emit('reload')">
        <template #icon="slotProps"><AppIcon :class="slotProps.class" name="refresh" /></template>
      </Button>
      <Button
        label="恢复默认"
        severity="secondary"
        outlined
        :disabled="!configAvailable || configLocked || busy"
        @click="emit('restore-default-config')"
      >
        <template #icon="slotProps"><AppIcon :class="slotProps.class" name="restore" /></template>
      </Button>
      <Button
        severity="secondary"
        outlined
        rounded
        aria-label="保存配置"
        :disabled="configLocked || !dirty || busy"
        @click="emit('save')"
      >
        <template #icon="slotProps"><AppIcon :class="slotProps.class" name="save" /></template>
      </Button>
      <Button v-if="running" label="停止" severity="danger" :disabled="busy" @click="emit('stop')">
        <template #icon="slotProps"><AppIcon :class="slotProps.class" name="stop" /></template>
      </Button>
      <Button v-else label="启动" severity="primary" :disabled="busy" @click="emit('start')">
        <template #icon="slotProps"><AppIcon :class="slotProps.class" name="play" /></template>
      </Button>
    </div>
  </header>
</template>
