<script setup lang="ts">
import { ref, onMounted } from "vue";
import { useConfigStore } from "./stores/config";
import ConfigForm from "./components/ConfigForm.vue";
import StatusPanel from "./components/StatusPanel.vue";

const configStore = useConfigStore();
const activeTab = ref<"config" | "status">("config");

onMounted(async () => {
  await configStore.loadConfig();
});
</script>

<template>
  <div class="app-container">
    <header class="app-header">
      <h1>PPAASS Agent</h1>
      <nav class="tabs">
        <button
          :class="{ active: activeTab === 'config' }"
          @click="activeTab = 'config'"
        >
          Configuration
        </button>
        <button
          :class="{ active: activeTab === 'status' }"
          @click="activeTab = 'status'"
        >
          Status
        </button>
      </nav>
    </header>

    <main class="app-main">
      <ConfigForm v-if="activeTab === 'config'" />
      <StatusPanel v-else />
    </main>

    <footer class="app-footer">
      <span v-if="configStore.status === 'running'" class="status-indicator running">
        ● Running
      </span>
      <span v-else class="status-indicator stopped">
        ● Stopped
      </span>
    </footer>
  </div>
</template>

<style scoped>
.app-container {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  padding: 20px;
}

.app-header {
  margin-bottom: 20px;
}

.app-header h1 {
  margin-bottom: 15px;
  font-size: 24px;
  color: #2c3e50;
}

@media (prefers-color-scheme: dark) {
  .app-header h1 {
    color: #ecf0f1;
  }
}

.tabs {
  display: flex;
  gap: 10px;
}

.tabs button {
  padding: 10px 20px;
  border: none;
  background: #e0e0e0;
  cursor: pointer;
  border-radius: 5px;
  font-size: 14px;
  transition: all 0.2s;
}

.tabs button:hover {
  background: #d0d0d0;
}

.tabs button.active {
  background: #3498db;
  color: white;
}

@media (prefers-color-scheme: dark) {
  .tabs button {
    background: #444;
    color: #ecf0f1;
  }
  .tabs button:hover {
    background: #555;
  }
  .tabs button.active {
    background: #3498db;
  }
}

.app-main {
  flex: 1;
}

.app-footer {
  margin-top: 20px;
  padding-top: 15px;
  border-top: 1px solid #e0e0e0;
}

@media (prefers-color-scheme: dark) {
  .app-footer {
    border-top-color: #444;
  }
}

.status-indicator {
  font-size: 14px;
  font-weight: 500;
}

.status-indicator.running {
  color: #27ae60;
}

.status-indicator.stopped {
  color: #e74c3c;
}
</style>
