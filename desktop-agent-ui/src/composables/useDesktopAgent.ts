import { computed, onBeforeUnmount, onMounted, reactive } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { applyFieldToToml, coerceField, fallbackRawConfig, summarizeRaw } from "../configToml";
import { directModeLabels, tabs } from "../constants";
import { fallbackAgentState, fallbackConnectivityReport, fallbackTrafficSnapshot, loadFallbackConfig } from "../fallbacks";
import {
  delay,
  dnsRecordTimestamp,
  getErrorMessage,
  isAgentDnsRecord,
  normalizeDnsRecords,
  shortPath
} from "../formatters";
import { emptyTrafficBuckets, ensureTrafficBaseline, ensureTrafficHourlyStore, saveTrafficHourlyStore } from "../trafficStorage";
import type {
  AgentConfigSummary,
  AgentState,
  ConnectivityReport,
  DirectRuleGroup,
  DnsResolutionRecord,
  LoadedAgentConfig,
  NetworkTrafficSnapshot,
  TabKey,
  TrafficBaseline,
  ToastKind
} from "../types";

export function useDesktopAgent() {
  const state = reactive({
    activeTab: "overview" as TabKey,
    loading: true,
    busy: false,
    diagnosticsRunning: false,
    dirty: false,
    ruleDraft: "",
    statusText: "初始化",
    toast: null as null | { kind: ToastKind; message: string },
    config: null as LoadedAgentConfig | null,
    agent: {
      running: false,
      managed: false,
      pid: null,
      config_path: null,
      binary_path: null,
      logs: []
    } as AgentState,
    diagnostics: null as ConnectivityReport | null,
    traffic: {
      snapshot: null as NetworkTrafficSnapshot | null,
      previous: null as NetworkTrafficSnapshot | null,
      baseline: null as TrafficBaseline | null,
      hourly_buckets: emptyTrafficBuckets(),
      download_bps: 0,
      upload_bps: 0,
      day_download_bytes: 0,
      day_upload_bytes: 0
    },
    dnsRecords: [] as DnsResolutionRecord[]
  });

  const summary = computed(() => state.config?.summary ?? summarizeRaw(fallbackRawConfig));
  const running = computed(() => state.agent.running);
  const configLocked = computed(() => running.value);
  const runningLabel = computed(() => (running.value ? "运行中" : "已停止"));
  const runningSeverity = computed(() => (running.value ? "success" : "secondary"));
  const proxyDiagnosticResults = computed(() => state.diagnostics?.results ?? []);
  const tunDiagnosticResults = computed(() => state.diagnostics?.tun_results ?? []);
  const diagnosticsTotal = computed(() => proxyDiagnosticResults.value.length + tunDiagnosticResults.value.length);
  const diagnosticsPassed = computed(
    () =>
      proxyDiagnosticResults.value.filter((item) => item.success).length +
      tunDiagnosticResults.value.filter((item) => item.success).length
  );
  const tunDiagnosticsLabel = computed(() => {
    if (!state.diagnostics) {
      return "Pending";
    }
    if (!state.diagnostics.tun_enabled) {
      return "Disabled";
    }
    if (!state.diagnostics.tun_ready) {
      return "Not Ready";
    }
    if (!tunDiagnosticResults.value.length) {
      return "No tests";
    }
    const passed = tunDiagnosticResults.value.filter((item) => item.success).length;
    return `${passed}/${tunDiagnosticResults.value.length}`;
  });
  const directModeLabel = computed(() => directModeLabels[summary.value.direct_mode] ?? summary.value.direct_mode);
  const tunModeLabel = computed(() => (summary.value.tun_enabled ? "已启用" : "未启用"));
  const proxyEntryStateLabel = computed(() => "随 Agent 启动");
  const activeForwardingLabel = computed(() => (summary.value.tun_enabled ? "TUN + HTTP / SOCKS5" : "HTTP / SOCKS5 代理"));
  const recentDnsRecords = computed(() =>
    normalizeDnsRecords(state.dnsRecords)
      .filter(isAgentDnsRecord)
      .sort((left, right) => dnsRecordTimestamp(right) - dnsRecordTimestamp(left))
      .slice(0, 80)
  );
  const dnsCardLabel = computed(() => (summary.value.tun_proxy_dns ? `${recentDnsRecords.value.length} 条` : "System"));
  const directRuleGroups = computed(() => buildDirectRuleGroups(summary.value.direct_rules));

  let trafficTimer: number | undefined;
  let agentTimer: number | undefined;
  let dnsTimer: number | undefined;
  let pollingActive = false;
  let trafficRefreshInFlight = false;
  let agentRefreshInFlight = false;
  let dnsRefreshInFlight = false;

  onMounted(() => {
    pollingActive = true;
    void boot().finally(() => {
      if (!pollingActive) {
        return;
      }
      startTrafficPolling();
      startAgentPolling();
      startDnsPolling();
    });
  });

  onBeforeUnmount(() => {
    pollingActive = false;
    clearPollingTimer(trafficTimer);
    clearPollingTimer(agentTimer);
    clearPollingTimer(dnsTimer);
  });

  async function boot() {
    try {
      state.config = await invokeOrFallback<LoadedAgentConfig>("load_agent_config", {}, loadFallbackConfig);
      await refreshAgentState();
      state.statusText = "就绪";
    } catch (error) {
      state.statusText = "配置异常";
      showToast("error", getErrorMessage(error));
    } finally {
      state.loading = false;
    }
  }

  async function reloadAll() {
    try {
      state.busy = true;
      const path = state.config?.path;
      state.config = await invokeOrFallback<LoadedAgentConfig>(
        "load_agent_config",
        path ? { path } : {},
        loadFallbackConfig
      );
      await refreshAgentState();
      state.diagnostics = null;
      state.dirty = false;
      showToast("success", "已重新载入");
    } catch (error) {
      showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function saveConfig() {
    if (!state.config || !ensureConfigEditable()) {
      return;
    }
    try {
      state.busy = true;
      await persistConfig();
      showToast("success", `已保存到 ${shortPath(state.config.path)}`);
    } catch (error) {
      showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function startAgent() {
    if (!state.config) {
      return;
    }
    try {
      state.busy = true;
      if (state.dirty) {
        await persistConfig();
      }
      state.agent = await invokeOrFallback<AgentState>(
        "start_agent",
        { configPath: state.config.path },
        () => ({ ...fallbackAgentState(), running: true, managed: true, pid: 4242, config_path: state.config?.path })
      );
      await delay(1800);
      await refreshAgentState();
      showToast(
        state.agent.running ? "success" : "error",
        state.agent.running ? "Agent 已启动" : latestAgentLog() ?? "Agent 启动失败"
      );
    } catch (error) {
      await refreshAgentState();
      showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function stopAgent() {
    try {
      state.busy = true;
      state.agent = await invokeOrFallback<AgentState>(
        "stop_agent",
        {},
        () => ({ ...fallbackAgentState(), running: false, pid: null, config_path: state.config?.path })
      );
      showToast(state.agent.running ? "error" : "success", state.agent.running ? "Agent 仍在运行" : "Agent 已停止");
    } catch (error) {
      showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function runDiagnostics() {
    if (!state.config) {
      return;
    }
    try {
      state.diagnosticsRunning = true;
      state.diagnostics = null;
      state.diagnostics = await invokeOrFallback<ConnectivityReport>(
        "run_connectivity_tests",
        { path: state.config.path },
        () => fallbackConnectivityReport(state.config?.summary)
      );
      const total = diagnosticsTotal.value;
      const passed = diagnosticsPassed.value;
      showToast(total > 0 && passed === total ? "success" : "error", `诊断完成：${passed}/${total}`);
    } catch (error) {
      showToast("error", getErrorMessage(error));
    } finally {
      state.diagnosticsRunning = false;
    }
  }

  async function refreshAgentState() {
    if (agentRefreshInFlight) {
      return;
    }
    agentRefreshInFlight = true;
    try {
      state.agent = await invokeOrFallback<AgentState>("get_agent_state", {}, () => state.agent);
    } catch {
      // Keep the last visible agent state if the runtime status read fails.
    } finally {
      agentRefreshInFlight = false;
    }
  }

  function setField(field: keyof AgentConfigSummary, value: unknown) {
    if (!state.config || value === null || value === undefined || !ensureConfigEditable(false)) {
      return;
    }
    const coerced = coerceField(field, value);
    (state.config.summary as Record<string, unknown>)[field] = coerced;
    if (field === "runtime_threads") {
      state.config.summary.effective_runtime_threads = Number(coerced);
    }
    state.config.raw = applyFieldToToml(state.config.raw, field, coerced);
    state.diagnostics = null;
    state.dirty = true;
  }

  function setRawConfig(raw: string) {
    if (!state.config || !ensureConfigEditable(false)) {
      return;
    }
    state.config.raw = raw;
    try {
      state.config.summary = summarizeRaw(raw);
    } catch {
      // Keep structured fields stable while the TOML text is mid-edit.
    }
    state.dirty = true;
  }

  function addDirectRules(rules: string[]) {
    if (!state.config || !ensureConfigEditable()) {
      return;
    }
    updateDirectRules(normalizeRules([...state.config.summary.direct_rules, ...rules]));
    state.ruleDraft = "";
    showToast("success", "规则已更新");
  }

  function addDraftRules() {
    if (ensureConfigEditable()) {
      addDirectRules(parseRuleInput(state.ruleDraft));
    }
  }

  function removeDirectRule(index: number) {
    if (!state.config || !Number.isInteger(index) || !ensureConfigEditable()) {
      return;
    }
    const next = normalizeRules(state.config.summary.direct_rules).filter((_, current) => current !== index);
    updateDirectRules(next);
  }

  function guardIntegerBeforeInput(event: InputEvent) {
    const target = event.target;
    if (isIntegerInputTarget(target) && event.data && !/^\d+$/.test(event.data)) {
      event.preventDefault();
    }
  }

  function guardIntegerPaste(event: ClipboardEvent) {
    const target = event.target;
    if (!isIntegerInputTarget(target)) {
      return;
    }
    const text = event.clipboardData?.getData("text") ?? "";
    const digits = digitsOnly(text);
    if (digits === text) {
      return;
    }
    event.preventDefault();
    if (!digits) {
      return;
    }
    const start = target.selectionStart ?? target.value.length;
    const end = target.selectionEnd ?? target.value.length;
    target.setRangeText(digits, start, end, "end");
    target.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function sanitizeIntegerInput(event: Event) {
    const target = event.target;
    if (!isIntegerInputTarget(target)) {
      return;
    }
    const sanitized = digitsOnly(target.value);
    if (sanitized === target.value) {
      return;
    }
    const caret = target.selectionStart ?? sanitized.length;
    const beforeCaret = target.value.slice(0, caret);
    const removedBeforeCaret = beforeCaret.length - digitsOnly(beforeCaret).length;
    const nextCaret = Math.max(0, caret - removedBeforeCaret);
    target.value = sanitized;
    target.setSelectionRange(nextCaret, nextCaret);
    target.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function startTrafficPolling() {
    void pollTraffic();
  }

  async function pollTraffic() {
    if (!pollingActive) {
      return;
    }
    if (!state.busy) {
      await refreshTraffic();
    }
    if (pollingActive) {
      trafficTimer = window.setTimeout(() => void pollTraffic(), 1000);
    }
  }

  async function refreshTraffic() {
    if (trafficRefreshInFlight) {
      return;
    }
    trafficRefreshInFlight = true;
    try {
      updateTraffic(await invokeOrFallback<NetworkTrafficSnapshot>("get_network_traffic_snapshot", {}, fallbackTrafficSnapshot));
    } catch {
      // Keep the last visible telemetry sample if the OS counter read fails.
    } finally {
      trafficRefreshInFlight = false;
    }
  }

  function startAgentPolling() {
    void pollAgentState();
  }

  async function pollAgentState() {
    if (!pollingActive) {
      return;
    }
    if (!state.busy) {
      await refreshAgentState();
    }
    if (pollingActive) {
      agentTimer = window.setTimeout(() => void pollAgentState(), 1200);
    }
  }

  function startDnsPolling() {
    void pollDnsRecords();
  }

  async function pollDnsRecords() {
    if (!pollingActive) {
      return;
    }
    if (!state.busy) {
      await refreshDnsRecords();
    }
    if (pollingActive) {
      dnsTimer = window.setTimeout(() => void pollDnsRecords(), 2500);
    }
  }

  async function refreshDnsRecords() {
    if (dnsRefreshInFlight) {
      return;
    }
    dnsRefreshInFlight = true;
    try {
      const records = await invokeOrFallback<DnsResolutionRecord[]>("get_dns_resolution_records", {}, () => state.dnsRecords);
      if (Array.isArray(records)) {
        state.dnsRecords = records;
      }
    } catch {
      // Keep the last visible DNS records if the runtime status read fails.
    } finally {
      dnsRefreshInFlight = false;
    }
  }

  async function persistConfig() {
    if (!state.config) {
      return;
    }
    state.config = await invokeOrFallback<LoadedAgentConfig>(
      "save_agent_config",
      { path: state.config.path, raw: state.config.raw },
      () => state.config as LoadedAgentConfig
    );
    state.dirty = false;
  }

  function updateTraffic(snapshot: NetworkTrafficSnapshot) {
    const previous = state.traffic.snapshot;
    state.traffic.previous = previous;
    state.traffic.snapshot = snapshot;
    if (previous && snapshot.sampled_at_ms > previous.sampled_at_ms) {
      const elapsedSeconds = (snapshot.sampled_at_ms - previous.sampled_at_ms) / 1000;
      state.traffic.download_bps = bytesPerSecond(snapshot.total_received_bytes, previous.total_received_bytes, elapsedSeconds);
      state.traffic.upload_bps = bytesPerSecond(snapshot.total_transmitted_bytes, previous.total_transmitted_bytes, elapsedSeconds);
    }
    state.traffic.baseline = ensureTrafficBaseline(snapshot);
    updateHourlyTraffic(snapshot);
  }

  function updateHourlyTraffic(snapshot: NetworkTrafficSnapshot) {
    const store = ensureTrafficHourlyStore(snapshot);
    const elapsedMs = snapshot.sampled_at_ms - store.last_sampled_at_ms;
    const currentHour = new Date().getHours();
    if (
      elapsedMs > 0 &&
      elapsedMs <= 90_000 &&
      snapshot.total_received_bytes >= store.last_received &&
      snapshot.total_transmitted_bytes >= store.last_transmitted
    ) {
      const bucket = store.buckets[currentHour];
      bucket.download_bytes += snapshot.total_received_bytes - store.last_received;
      bucket.upload_bytes += snapshot.total_transmitted_bytes - store.last_transmitted;
    }
    store.last_received = snapshot.total_received_bytes;
    store.last_transmitted = snapshot.total_transmitted_bytes;
    store.last_sampled_at_ms = snapshot.sampled_at_ms;
    saveTrafficHourlyStore(store);
    state.traffic.hourly_buckets = store.buckets.map((bucket) => ({ ...bucket }));
    state.traffic.day_download_bytes = store.buckets.reduce((total, bucket) => total + bucket.download_bytes, 0);
    state.traffic.day_upload_bytes = store.buckets.reduce((total, bucket) => total + bucket.upload_bytes, 0);
  }

  function updateDirectRules(rules: string[]) {
    if (!state.config || !ensureConfigEditable(false)) {
      return;
    }
    state.config.summary.direct_rules = normalizeRules(rules);
    state.config.raw = applyFieldToToml(state.config.raw, "direct_rules", state.config.summary.direct_rules);
    state.diagnostics = null;
    state.dirty = true;
  }

  function ensureConfigEditable(notify = true) {
    if (!configLocked.value) {
      return true;
    }
    if (notify) {
      showToast("error", "Agent 运行中，停止后再修改配置");
    }
    return false;
  }

  function showToast(kind: ToastKind, message: string) {
    state.toast = { kind, message };
    window.setTimeout(() => {
      state.toast = null;
    }, 2600);
  }

  function latestAgentLog() {
    const logs = state.agent.logs ?? [];
    return logs.length > 0 ? logs[logs.length - 1] : null;
  }

  return {
    activeForwardingLabel,
    addDirectRules,
    addDraftRules,
    configLocked,
    diagnosticsPassed,
    diagnosticsTotal,
    directModeLabel,
    directRuleGroups,
    dnsCardLabel,
    guardIntegerBeforeInput,
    recentDnsRecords,
    proxyEntryStateLabel,
    refreshAgentState,
    reloadAll,
    removeDirectRule,
    runDiagnostics,
    running,
    runningLabel,
    runningSeverity,
    sanitizeIntegerInput,
    saveConfig,
    setField,
    setRawConfig,
    startAgent,
    state,
    stopAgent,
    summary,
    tabs,
    tunDiagnosticsLabel,
    tunModeLabel,
    guardIntegerPaste
  };
}

function buildDirectRuleGroups(rules: string[]) {
  const groups: DirectRuleGroup[] = [
    { key: "wildcard", label: "通配符", icon: "pi pi-asterisk", items: [] },
    { key: "network", label: "IP / CIDR", icon: "pi pi-hashtag", items: [] },
    { key: "domain", label: "域名", icon: "pi pi-globe", items: [] },
    { key: "other", label: "其他", icon: "pi pi-ellipsis-h", items: [] }
  ];
  const byKey = new Map(groups.map((group) => [group.key, group]));
  rules.forEach((rule, index) => {
    byKey.get(ruleGroupKey(rule))?.items.push({ rule, index });
  });
  return groups.filter((group) => group.items.length > 0);
}

function bytesPerSecond(current: number, previous: number, elapsedSeconds: number) {
  if (elapsedSeconds <= 0 || current < previous) {
    return 0;
  }
  return Math.round((current - previous) / elapsedSeconds);
}

function clearPollingTimer(timer: number | undefined) {
  if (timer) {
    window.clearTimeout(timer);
  }
}

function parseRuleInput(value: string) {
  return value.split(/[\s,，;；]+/);
}

function normalizeRules(rules: string[]) {
  const seen = new Set<string>();
  return rules
    .map((rule) => rule.trim())
    .filter(Boolean)
    .filter((rule) => {
      const key = rule.toLowerCase();
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
}

function ruleGroupKey(rule: string) {
  const normalized = rule.trim().toLowerCase();
  if (normalized.includes("*")) {
    return "wildcard";
  }
  if (isNetworkRule(normalized)) {
    return "network";
  }
  if (/^[a-z0-9._-]+(\.[a-z0-9._-]+)*$/i.test(normalized)) {
    return "domain";
  }
  return "other";
}

function isNetworkRule(rule: string) {
  return (
    /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(rule) ||
    /^([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}(\/\d{1,3})?$/i.test(rule)
  );
}

async function invokeOrFallback<T>(command: string, args: Record<string, unknown>, fallback: () => T): Promise<T> {
  if (!hasTauri()) {
    return fallback();
  }
  return invoke<T>(command, args);
}

function hasTauri() {
  return Boolean((window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
}

function isIntegerInputTarget(target: EventTarget | null): target is HTMLInputElement {
  return target instanceof HTMLInputElement && Boolean(target.closest(".p-inputnumber"));
}

function digitsOnly(value: string) {
  return value.replace(/\D+/g, "");
}
