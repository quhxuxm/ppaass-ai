<script setup lang="ts">
import { ref, computed } from "vue";
import { useConfigStore } from "../stores/config";
import { open } from "@tauri-apps/plugin-dialog";

const configStore = useConfigStore();
const saving = ref(false);
const message = ref<{ type: "success" | "error"; text: string } | null>(null);

const logLevels = ["trace", "debug", "info", "warn", "error"];

const isValid = computed(() => {
  return (
    configStore.config.listen_address.trim() !== "" &&
    configStore.config.proxy_address.trim() !== "" &&
    configStore.config.username.trim() !== "" &&
    configStore.config.pool_size > 0 &&
    configStore.config.private_key_path.trim() !== ""
  );
});

async function selectPrivateKey() {
  try {
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "PEM Files", extensions: ["pem"] }],
    });
    if (selected && typeof selected === "string") {
      configStore.config.private_key_path = selected;
    } else if (Array.isArray(selected) && selected.length > 0) {
      configStore.config.private_key_path = selected[0];
    }
  } catch (e) {
    console.error("Failed to open file dialog:", e);
  }
}

async function handleSave() {
  if (!isValid.value) return;

  saving.value = true;
  message.value = null;

  try {
    await configStore.saveConfig();
    message.value = { type: "success", text: "Configuration saved successfully!" };
  } catch (e) {
    message.value = { type: "error", text: `Failed to save: ${e}` };
  } finally {
    saving.value = false;
  }
}

async function handleStart() {
  message.value = null;
  try {
    await configStore.startAgent();
    message.value = { type: "success", text: "Agent started successfully!" };
  } catch (e) {
    message.value = { type: "error", text: `Failed to start: ${e}` };
  }
}

async function handleStop() {
  message.value = null;
  try {
    await configStore.stopAgent();
    message.value = { type: "success", text: "Agent stopped." };
  } catch (e) {
    message.value = { type: "error", text: `Failed to stop: ${e}` };
  }
}
</script>

<template>
  <div class="config-form">
    <div v-if="message" :class="['message', message.type]">
      {{ message.text }}
    </div>

    <div class="form-group">
      <label for="listen_address">Listening Address</label>
      <input
        id="listen_address"
        v-model="configStore.config.listen_address"
        type="text"
        placeholder="127.0.0.1:1080"
      />
      <span class="help-text">The address the agent listens on for client connections</span>
    </div>

    <div class="form-group">
      <label for="proxy_address">Proxy Address</label>
      <input
        id="proxy_address"
        v-model="configStore.config.proxy_address"
        type="text"
        placeholder="proxy.example.com:8080"
      />
      <span class="help-text">The address of the proxy server to connect to</span>
    </div>

    <div class="form-group">
      <label for="username">Username</label>
      <input
        id="username"
        v-model="configStore.config.username"
        type="text"
        placeholder="your-username"
      />
      <span class="help-text">Your registered username on the proxy server</span>
    </div>

    <div class="form-group">
      <label for="pool_size">Connection Pool Size</label>
      <input
        id="pool_size"
        v-model.number="configStore.config.pool_size"
        type="number"
        min="1"
        max="100"
      />
      <span class="help-text">Number of connections to maintain in the pool (1-100)</span>
    </div>

    <div class="form-group">
      <label for="log_level">Log Level</label>
      <select id="log_level" v-model="configStore.config.log_level">
        <option v-for="level in logLevels" :key="level" :value="level">
          {{ level.toUpperCase() }}
        </option>
      </select>
      <span class="help-text">Logging verbosity level</span>
    </div>

    <div class="form-group">
      <label for="private_key">Private Key Path</label>
      <div class="file-input-group">
        <input
          id="private_key"
          v-model="configStore.config.private_key_path"
          type="text"
          placeholder="/path/to/private_key.pem"
        />
        <button type="button" class="browse-btn" @click="selectPrivateKey">
          Browse...
        </button>
      </div>
      <span class="help-text">Path to your RSA private key file</span>
    </div>

    <div class="form-actions">
      <button
        class="btn btn-primary"
        :disabled="!isValid || saving || configStore.loading"
        @click="handleSave"
      >
        {{ saving ? "Saving..." : "Save Configuration" }}
      </button>

      <button
        v-if="configStore.status !== 'running'"
        class="btn btn-success"
        :disabled="!isValid || configStore.loading"
        @click="handleStart"
      >
        Start Agent
      </button>

      <button
        v-else
        class="btn btn-danger"
        :disabled="configStore.loading"
        @click="handleStop"
      >
        Stop Agent
      </button>
    </div>
  </div>
</template>

<style scoped>
.config-form {
  max-width: 500px;
}

.message {
  padding: 10px 15px;
  border-radius: 5px;
  margin-bottom: 20px;
  font-size: 14px;
}

.message.success {
  background: #d4edda;
  color: #155724;
  border: 1px solid #c3e6cb;
}

.message.error {
  background: #f8d7da;
  color: #721c24;
  border: 1px solid #f5c6cb;
}

@media (prefers-color-scheme: dark) {
  .message.success {
    background: #1e4620;
    color: #a3d9a5;
    border-color: #2e7d32;
  }
  .message.error {
    background: #4a1c1c;
    color: #f5a5a5;
    border-color: #c62828;
  }
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
  color: #2c3e50;
}

@media (prefers-color-scheme: dark) {
  .form-group label {
    color: #ecf0f1;
  }
}

.form-group input,
.form-group select {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 14px;
  background: white;
  color: #333;
}

@media (prefers-color-scheme: dark) {
  .form-group input,
  .form-group select {
    background: #3a3a3a;
    border-color: #555;
    color: #ecf0f1;
  }
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
}

.help-text {
  display: block;
  margin-top: 5px;
  font-size: 12px;
  color: #7f8c8d;
}

.file-input-group {
  display: flex;
  gap: 10px;
}

.file-input-group input {
  flex: 1;
}

.browse-btn {
  padding: 10px 15px;
  background: #95a5a6;
  color: white;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  font-size: 14px;
}

.browse-btn:hover {
  background: #7f8c8d;
}

.form-actions {
  display: flex;
  gap: 10px;
  margin-top: 30px;
}

.btn {
  padding: 12px 24px;
  border: none;
  border-radius: 5px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2980b9;
}

.btn-success {
  background: #27ae60;
  color: white;
}

.btn-success:hover:not(:disabled) {
  background: #219a52;
}

.btn-danger {
  background: #e74c3c;
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background: #c0392b;
}
</style>
