import { defineStore } from "pinia";
import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { AgentConfig, AgentStatus, AgentState } from "../types/config";

export const useConfigStore = defineStore("config", () => {
    const config = ref<AgentConfig>({
        listen_address: "127.0.0.1:1080",
        proxy_address: "127.0.0.1:8080",
        username: "",
        pool_size: 10,
        log_level: "info",
        private_key_path: "",
    });

    const status = ref<AgentStatus>("stopped");
    const state = ref<AgentState | null>(null);
    const loading = ref(false);
    const error = ref<string | null>(null);

    async function loadConfig() {
        loading.value = true;
        error.value = null;
        try {
            const result = await invoke<AgentConfig>("get_config");
            config.value = result;
        } catch (e) {
            error.value = `Failed to load config: ${e}`;
        } finally {
            loading.value = false;
        }
    }

    async function saveConfig() {
        loading.value = true;
        error.value = null;
        try {
            await invoke("save_config", { config: config.value });
        } catch (e) {
            error.value = `Failed to save config: ${e}`;
            throw e;
        } finally {
            loading.value = false;
        }
    }

    async function startAgent() {
        loading.value = true;
        error.value = null;
        try {
            await invoke("start_agent");
            status.value = "running";
        } catch (e) {
            error.value = `Failed to start agent: ${e}`;
            status.value = "error";
        } finally {
            loading.value = false;
        }
    }

    async function stopAgent() {
        loading.value = true;
        error.value = null;
        try {
            await invoke("stop_agent");
            status.value = "stopped";
        } catch (e) {
            error.value = `Failed to stop agent: ${e}`;
        } finally {
            loading.value = false;
        }
    }

    async function refreshState() {
        try {
            state.value = await invoke<AgentState>("get_agent_state");
            status.value = state.value.status;
        } catch (e) {
            console.error("Failed to get agent state:", e);
        }
    }

    return {
        config,
        status,
        state,
        loading,
        error,
        loadConfig,
        saveConfig,
        startAgent,
        stopAgent,
        refreshState,
    };
});
