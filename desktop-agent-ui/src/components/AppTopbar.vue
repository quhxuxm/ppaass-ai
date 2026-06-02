<script setup lang="ts">
import Button from "primevue/button";

defineProps<{
  subtitle: string;
  running: boolean;
  configLocked: boolean;
  dirty: boolean;
  busy: boolean;
}>();

const emit = defineEmits<{
  reload: [];
  save: [];
  start: [];
  stop: [];
}>();
</script>

<template>
  <header class="topbar">
    <div>
      <h1>Desktop Agent</h1>
      <p>{{ subtitle }}</p>
    </div>
    <div class="toolbar">
      <Button icon="pi pi-refresh" severity="secondary" outlined rounded aria-label="重新载入" @click="emit('reload')" />
      <Button
        icon="pi pi-save"
        severity="secondary"
        outlined
        rounded
        aria-label="保存配置"
        :disabled="configLocked || !dirty || busy"
        @click="emit('save')"
      />
      <Button v-if="running" label="停止" icon="pi pi-stop" severity="danger" :disabled="busy" @click="emit('stop')" />
      <Button v-else label="启动" icon="pi pi-play" severity="primary" :disabled="busy" @click="emit('start')" />
    </div>
  </header>
</template>
