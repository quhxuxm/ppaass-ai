import { computed, onMounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type {
  AgentProxyEntry,
  AgentProxyEntrySelection,
  AgentProxyEntrySpeedResult
} from "../types";

export function useProxyEntrySelection() {
  const visible = ref(false);
  const loading = ref(false);
  const switching = ref(false);
  const error = ref("");
  const selection = ref<AgentProxyEntrySelection>(emptySelection());
  const pendingIds = ref<string[]>([]);
  const testingId = ref<string | null>(null);
  const speedResults = ref<Record<string, string>>({});

  const orderedEntries = computed(() => {
    const currentIds = new Set(selection.value.selected_proxy_entry_ids);
    return [...selection.value.entries].sort((left, right) => {
      if (currentIds.has(left.proxy_entry_id) && !currentIds.has(right.proxy_entry_id)) return -1;
      if (currentIds.has(right.proxy_entry_id) && !currentIds.has(left.proxy_entry_id)) return 1;
      return left.label.localeCompare(right.label, "zh-CN");
    });
  });
  const canConfirm = computed(
    () =>
      pendingIds.value.length > 0 &&
      !sameIds(pendingIds.value, selection.value.selected_proxy_entry_ids) &&
      !switching.value
  );

  onMounted(() => {
    void refresh(false);
  });

  async function refresh(showLoading = true) {
    if (showLoading) loading.value = true;
    try {
      selection.value = await invoke<AgentProxyEntrySelection>(
        "get_agent_proxy_entries"
      );
      pendingIds.value = [...selection.value.selected_proxy_entry_ids];
      error.value = "";
      return true;
    } catch (reason) {
      error.value = message(reason, "无法读取 Proxy Entry 列表");
      return false;
    } finally {
      loading.value = false;
    }
  }

  async function open() {
    visible.value = true;
    error.value = "";
    await refresh();
  }

  function close() {
    if (!switching.value) {
      visible.value = false;
      pendingIds.value = [...selection.value.selected_proxy_entry_ids];
      error.value = "";
    }
  }

  function choose(entry: AgentProxyEntry) {
    if (switching.value) return;
    if (pendingIds.value.includes(entry.proxy_entry_id)) {
      if (pendingIds.value.length === 1) {
        error.value = "至少需要选择一个 Proxy Entry";
        return;
      }
      pendingIds.value = pendingIds.value.filter((id) => id !== entry.proxy_entry_id);
    } else {
      pendingIds.value = [...pendingIds.value, entry.proxy_entry_id];
    }
    error.value = "";
  }

  async function confirm() {
    if (!canConfirm.value) return false;
    switching.value = true;
    error.value = "";
    try {
      selection.value = await invoke<AgentProxyEntrySelection>(
        "select_agent_proxy_entry_command",
        { proxyEntryIds: pendingIds.value }
      );
      pendingIds.value = [...selection.value.selected_proxy_entry_ids];
      visible.value = false;
      return true;
    } catch (reason) {
      error.value = message(reason, "切换 Proxy Entry 失败");
      await refresh(false);
      return false;
    } finally {
      switching.value = false;
    }
  }

  async function runSpeedTest(entry: AgentProxyEntry) {
    if (testingId.value || switching.value) return;
    testingId.value = entry.proxy_entry_id;
    error.value = "";
    const next = { ...speedResults.value };
    delete next[entry.proxy_entry_id];
    speedResults.value = next;
    try {
      const result = await invoke<AgentProxyEntrySpeedResult>(
        "speed_test_agent_proxy_entry",
        { proxyEntryId: entry.proxy_entry_id }
      );
      speedResults.value = {
        ...speedResults.value,
        [entry.proxy_entry_id]: speedSummary(result)
      };
    } catch (reason) {
      speedResults.value = {
        ...speedResults.value,
        [entry.proxy_entry_id]: "测速失败 · 点击重试"
      };
      error.value = message(reason, "Proxy Entry 测速失败");
    } finally {
      testingId.value = null;
    }
  }

  return {
    canConfirm,
    choose,
    close,
    confirm,
    error,
    loading,
    open,
    orderedEntries,
    pendingIds,
    runSpeedTest,
    selection,
    speedResults,
    switching,
    testingId,
    visible
  };
}

function emptySelection(): AgentProxyEntrySelection {
  return { entries: [], selected_proxy_entry_ids: [] };
}

function sameIds(left: string[], right: string[]) {
  return left.length === right.length && left.every((id) => right.includes(id));
}

function speedSummary(result: AgentProxyEntrySpeedResult) {
  const mbps = (result.bytes_per_second * 8) / 1_000_000;
  const rate = mbps >= 100 ? mbps.toFixed(0) : mbps.toFixed(1);
  return `${rate} Mbps · ${Math.max(1, result.latency_ms)} ms`;
}

function message(reason: unknown, fallback: string) {
  if (typeof reason === "string" && reason.trim()) return reason;
  if (reason instanceof Error && reason.message.trim()) return reason.message;
  return fallback;
}
