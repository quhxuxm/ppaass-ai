<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { useConfigStore } from "../stores/config";

const configStore = useConfigStore();
const refreshInterval = ref<number | null>(null);

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatUptime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  return `${hours}h ${minutes}m ${secs}s`;
}

onMounted(() => {
  configStore.refreshState();
  refreshInterval.value = window.setInterval(() => {
    configStore.refreshState();
  }, 2000);
});

onUnmounted(() => {
  if (refreshInterval.value) {
    clearInterval(refreshInterval.value);
  }
});
</script>

<template>
  <div class="status-panel">
    <h2>Agent Status</h2>

    <div v-if="configStore.state" class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Status</div>
        <div :class="['stat-value', 'status-' + configStore.state.status]">
          {{ configStore.state.status.toUpperCase() }}
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-label">Active Connections</div>
        <div class="stat-value">{{ configStore.state.connections }}</div>
      </div>

      <div class="stat-card">
        <div class="stat-label">Uptime</div>
        <div class="stat-value">{{ formatUptime(configStore.state.uptime) }}</div>
      </div>

      <div class="stat-card">
        <div class="stat-label">Data Sent</div>
        <div class="stat-value">{{ formatBytes(configStore.state.bytes_sent) }}</div>
      </div>

      <div class="stat-card">
        <div class="stat-label">Data Received</div>
        <div class="stat-value">{{ formatBytes(configStore.state.bytes_received) }}</div>
      </div>
    </div>

    <div v-else class="no-data">
      <p>Agent is not running or status is unavailable.</p>
    </div>

    <button class="refresh-btn" @click="configStore.refreshState">
      Refresh
    </button>
  </div>
</template>

<style scoped>
.status-panel {
  max-width: 600px;
}

.status-panel h2 {
  margin-bottom: 20px;
  color: #2c3e50;
}

@media (prefers-color-scheme: dark) {
  .status-panel h2 {
    color: #ecf0f1;
  }
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 15px;
  margin-bottom: 20px;
}

.stat-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 15px;
  text-align: center;
}

@media (prefers-color-scheme: dark) {
  .stat-card {
    background: #3a3a3a;
    border-color: #555;
  }
}

.stat-label {
  font-size: 12px;
  color: #7f8c8d;
  margin-bottom: 5px;
  text-transform: uppercase;
}

.stat-value {
  font-size: 20px;
  font-weight: 600;
  color: #2c3e50;
}

@media (prefers-color-scheme: dark) {
  .stat-value {
    color: #ecf0f1;
  }
}

.stat-value.status-running {
  color: #27ae60;
}

.stat-value.status-stopped {
  color: #e74c3c;
}

.stat-value.status-error {
  color: #f39c12;
}

.no-data {
  background: #f8f9fa;
  border: 1px dashed #dee2e6;
  border-radius: 8px;
  padding: 40px;
  text-align: center;
  color: #6c757d;
}

@media (prefers-color-scheme: dark) {
  .no-data {
    background: #3a3a3a;
    border-color: #555;
    color: #adb5bd;
  }
}

.refresh-btn {
  margin-top: 20px;
  padding: 10px 20px;
  background: #3498db;
  color: white;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  font-size: 14px;
}

.refresh-btn:hover {
  background: #2980b9;
}
</style>
