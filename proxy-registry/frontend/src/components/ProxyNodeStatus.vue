<script setup lang="ts">
import Tag from 'primevue/tag'
import type { ProxyAddress } from '../api'

defineProps<{ node: ProxyAddress }>()

function heartbeatText(timestamp: number | null): string {
  if (timestamp === null) return '尚无心跳'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(timestamp * 1000))
}
</script>

<template>
  <div class="node-status">
    <Tag
      v-if="node.entryId"
      :value="node.entryOnline ? '在线' : '离线'"
      :severity="node.entryOnline ? 'success' : 'danger'"
      rounded
    />
    <Tag
      :value="node.enabled ? '已启用' : '已停用'"
      :severity="node.enabled ? 'info' : 'secondary'"
      rounded
    />
    <small v-if="node.entryId" :title="`最后心跳：${heartbeatText(node.entryLastHeartbeatAt)}`">
      {{ heartbeatText(node.entryLastHeartbeatAt) }}
    </small>
  </div>
</template>

<style scoped>
.node-status {
  display: grid;
  justify-items: start;
  gap: 4px;
}

.node-status small {
  max-width: 9rem;
  overflow: hidden;
  color: #98a2b3;
  font-size: 0.61rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
