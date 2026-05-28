<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive } from "vue";
import { invoke } from "@tauri-apps/api/core";
import Badge from "primevue/badge";
import Button from "primevue/button";
import Card from "primevue/card";
import InputNumber from "primevue/inputnumber";
import InputText from "primevue/inputtext";
import Knob from "primevue/knob";
import ProgressSpinner from "primevue/progressspinner";
import Select from "primevue/select";
import SelectButton from "primevue/selectbutton";
import Tag from "primevue/tag";
import Textarea from "primevue/textarea";
import ToggleSwitch from "primevue/toggleswitch";

type TabKey = "overview" | "network" | "tun" | "diagnostics" | "logs" | "toml";

type AgentConfigSummary = {
  listen_addr: string;
  proxy_addrs: string[];
  username: string;
  private_key_path: string;
  tcp_pool_size: number;
  udp_pool_size: number;
  connect_timeout_secs: number;
  compression_mode: string;
  log_level: string;
  log_dir?: string | null;
  log_file: string;
  runtime_threads?: number | null;
  tcp_mode: string;
  udp_mode: string;
  tcp_yamux_sessions: number;
  udp_yamux_sessions: number;
  tun_enabled: boolean;
  tun_name: string;
  tun_ipv4: string;
  tun_mtu: number;
  tun_proxy_dns: boolean;
  tun_block_quic: boolean;
  direct_mode: string;
  direct_rules: string[];
};

type LoadedAgentConfig = {
  path: string;
  raw: string;
  summary: AgentConfigSummary;
};

type AgentState = {
  running: boolean;
  managed?: boolean;
  pid?: number | null;
  config_path?: string | null;
  binary_path?: string | null;
  logs: string[];
};

type ConnectivityCheck = {
  target: string;
  protocol: string;
  url: string;
  proxy_url: string;
  success: boolean;
  http_code?: number | null;
  duration_ms: number;
  error?: string | null;
};

type ConnectivityReport = {
  listen_addr: string;
  agent_reachable: boolean;
  generated_at_ms: number;
  results: ConnectivityCheck[];
};

type NetworkTrafficSnapshot = {
  sampled_at_ms: number;
  total_received_bytes: number;
  total_transmitted_bytes: number;
  interfaces: NetworkInterfaceTraffic[];
};

type NetworkInterfaceTraffic = {
  name: string;
  received_bytes: number;
  transmitted_bytes: number;
};

type TrafficBaseline = {
  date: string;
  received: number;
  transmitted: number;
};

type TrafficHourBucket = {
  hour: number;
  download_bytes: number;
  upload_bytes: number;
};

type TrafficHourlyStore = {
  date: string;
  last_received: number;
  last_transmitted: number;
  last_sampled_at_ms: number;
  buckets: TrafficHourBucket[];
};

type ToastKind = "info" | "success" | "error";

const fallbackRawConfig = `listen_addr = "127.0.0.1:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"
tcp_pool_size = 5
udp_pool_size = 5
connect_timeout_secs = 20
compression_mode = "lz4"
log_level = "info"

[transport]
tcp_mode = "yamux"
udp_mode = "yamux"

[yamux.tcp]
sessions = 5
max_streams_per_session = 256
open_stream_timeout_secs = 10
keepalive_interval_secs = 30
connection_write_timeout_secs = 10
stream_window_size_kb = 2048

[yamux.udp]
sessions = 5
max_streams_per_session = 256
open_stream_timeout_secs = 10
keepalive_interval_secs = 30
connection_write_timeout_secs = 10
stream_window_size_kb = 2048

[tun]
enabled = false
name = "ppaass-tun"
ipv4 = "10.10.10.1/24"
mtu = 1500
proxy_dns = true
block_quic = true

[direct_access]
mode = "rules"
rules = ["localhost", "*.local", "127.0.0.0/8"]
`;

const tabs: Array<{ key: TabKey; label: string; icon: string }> = [
  { key: "overview", label: "总览", icon: "pi pi-th-large" },
  { key: "network", label: "连接", icon: "pi pi-sitemap" },
  { key: "tun", label: "TUN", icon: "pi pi-compass" },
  { key: "diagnostics", label: "诊断", icon: "pi pi-wifi" },
  { key: "logs", label: "日志", icon: "pi pi-list" },
  { key: "toml", label: "TOML", icon: "pi pi-code" }
];

const directRulePresets = [
  { label: "本机", icon: "pi pi-desktop", rules: ["localhost", "127.0.0.0/8", "::1"] },
  { label: "私网", icon: "pi pi-building", rules: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
  { label: "中国", icon: "pi pi-map-marker", rules: ["*.cn"] },
  { label: "Microsoft", icon: "pi pi-cloud", rules: ["*.microsoft.com", "*.bing.com"] }
];

const compressionOptions = ["none", "lz4", "gzip", "zstd"];
const logLevelOptions = ["trace", "debug", "info", "warn", "error"];
const transportModeOptions = ["auto", "yamux", "legacy"];
const directModeOptions = ["proxy_all", "direct_all", "rules"];
const trafficBaselineKey = "ppaass-agent-ui:traffic-baseline:v1";
const trafficHourlyKey = "ppaass-agent-ui:traffic-hourly:v1";

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
  }
});

const summary = computed(() => state.config?.summary ?? summarizeRaw(fallbackRawConfig));
const running = computed(() => state.agent.running);
const managed = computed(() => state.agent.managed !== false);
const runningLabel = computed(() => {
  if (!running.value) {
    return "已停止";
  }
  return managed.value ? "运行中" : "外部运行";
});
const runningSeverity = computed(() => (running.value ? "success" : "secondary"));
const diagnosticsPassed = computed(() => state.diagnostics?.results.filter((item) => item.success).length ?? 0);
const speedGaugeMax = computed(() => Math.max(256 * 1024, state.traffic.download_bps, state.traffic.upload_bps) * 1.25);
const downloadGaugeValue = computed(() => Math.round((state.traffic.download_bps / speedGaugeMax.value) * 100));
const uploadGaugeValue = computed(() => Math.round((state.traffic.upload_bps / speedGaugeMax.value) * 100));
const hourlyTrafficMax = computed(() =>
  Math.max(
    1,
    ...state.traffic.hourly_buckets.map((bucket) => bucket.download_bytes + bucket.upload_bytes)
  )
);

let trafficTimer: number | undefined;

onMounted(() => {
  void boot();
  startTrafficPolling();
});

onBeforeUnmount(() => {
  if (trafficTimer) {
    window.clearInterval(trafficTimer);
  }
});

async function boot() {
  try {
    state.config = await invokeOrFallback<LoadedAgentConfig>("load_agent_config", {}, loadFallbackConfig);
    state.agent = await invokeOrFallback<AgentState>("get_agent_state", {}, fallbackAgentState);
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
    state.agent = await invokeOrFallback<AgentState>("get_agent_state", {}, fallbackAgentState);
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
  if (!state.config) {
    return;
  }

  try {
    state.busy = true;
    state.config = await invokeOrFallback<LoadedAgentConfig>(
      "save_agent_config",
      { path: state.config.path, raw: state.config.raw },
      () => state.config as LoadedAgentConfig
    );
    state.dirty = false;
    showToast("success", "已保存");
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
    state.agent = await invokeOrFallback<AgentState>(
      "start_agent",
      { configPath: state.config.path },
      () => ({ ...fallbackAgentState(), running: true, managed: true, pid: 4242, config_path: state.config?.path })
    );
    showToast("success", "Agent 已启动");
  } catch (error) {
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
    showToast("success", "Agent 已停止");
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
    state.diagnostics = await invokeOrFallback<ConnectivityReport>(
      "run_connectivity_tests",
      { path: state.config.path },
      () => fallbackConnectivityReport(state.config?.summary)
    );
    const passed = state.diagnostics.results.filter((item) => item.success).length;
    const kind = passed === state.diagnostics.results.length ? "success" : "error";
    showToast(kind, `诊断完成：${passed}/${state.diagnostics.results.length}`);
  } catch (error) {
    showToast("error", getErrorMessage(error));
  } finally {
    state.diagnosticsRunning = false;
  }
}

function startTrafficPolling() {
  void refreshTraffic();
  trafficTimer = window.setInterval(() => {
    void refreshTraffic();
  }, 1000);
}

async function refreshTraffic() {
  try {
    const snapshot = await invokeOrFallback<NetworkTrafficSnapshot>(
      "get_network_traffic_snapshot",
      {},
      fallbackTrafficSnapshot
    );
    updateTraffic(snapshot);
  } catch {
    // Keep the last visible telemetry sample if the OS counter read fails.
  }
}

function updateTraffic(snapshot: NetworkTrafficSnapshot) {
  const previous = state.traffic.snapshot;
  state.traffic.previous = previous;
  state.traffic.snapshot = snapshot;

  if (previous && snapshot.sampled_at_ms > previous.sampled_at_ms) {
    const elapsedSeconds = (snapshot.sampled_at_ms - previous.sampled_at_ms) / 1000;
    state.traffic.download_bps = bytesPerSecond(
      snapshot.total_received_bytes,
      previous.total_received_bytes,
      elapsedSeconds
    );
    state.traffic.upload_bps = bytesPerSecond(
      snapshot.total_transmitted_bytes,
      previous.total_transmitted_bytes,
      elapsedSeconds
    );
  }

  const baseline = ensureTrafficBaseline(snapshot);
  state.traffic.baseline = baseline;
  updateHourlyTraffic(snapshot);
}

function bytesPerSecond(current: number, previous: number, elapsedSeconds: number) {
  if (elapsedSeconds <= 0 || current < previous) {
    return 0;
  }
  return Math.round((current - previous) / elapsedSeconds);
}

function ensureTrafficBaseline(snapshot: NetworkTrafficSnapshot) {
  const today = localDateKey();
  const saved = readTrafficBaseline();
  if (
    saved?.date === today &&
    saved.received <= snapshot.total_received_bytes &&
    saved.transmitted <= snapshot.total_transmitted_bytes
  ) {
    return saved;
  }

  const baseline = {
    date: today,
    received: snapshot.total_received_bytes,
    transmitted: snapshot.total_transmitted_bytes
  };
  localStorage.setItem(trafficBaselineKey, JSON.stringify(baseline));
  return baseline;
}

function readTrafficBaseline() {
  try {
    const raw = localStorage.getItem(trafficBaselineKey);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as TrafficBaseline;
    if (!parsed.date || !Number.isFinite(parsed.received) || !Number.isFinite(parsed.transmitted)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
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
  localStorage.setItem(trafficHourlyKey, JSON.stringify(store));

  state.traffic.hourly_buckets = store.buckets.map((bucket) => ({ ...bucket }));
  state.traffic.day_download_bytes = store.buckets.reduce((total, bucket) => total + bucket.download_bytes, 0);
  state.traffic.day_upload_bytes = store.buckets.reduce((total, bucket) => total + bucket.upload_bytes, 0);
}

function ensureTrafficHourlyStore(snapshot: NetworkTrafficSnapshot) {
  const today = localDateKey();
  const saved = readTrafficHourlyStore();
  if (
    saved?.date === today &&
    saved.last_received <= snapshot.total_received_bytes &&
    saved.last_transmitted <= snapshot.total_transmitted_bytes
  ) {
    return saved;
  }

  const store = {
    date: today,
    last_received: snapshot.total_received_bytes,
    last_transmitted: snapshot.total_transmitted_bytes,
    last_sampled_at_ms: snapshot.sampled_at_ms,
    buckets: emptyTrafficBuckets()
  };
  localStorage.setItem(trafficHourlyKey, JSON.stringify(store));
  return store;
}

function readTrafficHourlyStore() {
  try {
    const raw = localStorage.getItem(trafficHourlyKey);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as TrafficHourlyStore;
    if (
      !parsed.date ||
      !Number.isFinite(parsed.last_received) ||
      !Number.isFinite(parsed.last_transmitted) ||
      !Number.isFinite(parsed.last_sampled_at_ms)
    ) {
      return null;
    }
    return {
      ...parsed,
      buckets: normalizeTrafficBuckets(parsed.buckets)
    };
  } catch {
    return null;
  }
}

function normalizeTrafficBuckets(buckets: TrafficHourBucket[]) {
  const next = emptyTrafficBuckets();
  for (const bucket of buckets ?? []) {
    if (!Number.isInteger(bucket.hour) || bucket.hour < 0 || bucket.hour > 23) {
      continue;
    }
    next[bucket.hour] = {
      hour: bucket.hour,
      download_bytes: Number.isFinite(bucket.download_bytes) ? Math.max(0, bucket.download_bytes) : 0,
      upload_bytes: Number.isFinite(bucket.upload_bytes) ? Math.max(0, bucket.upload_bytes) : 0
    };
  }
  return next;
}

function emptyTrafficBuckets() {
  return Array.from({ length: 24 }, (_, hour) => ({
    hour,
    download_bytes: 0,
    upload_bytes: 0
  }));
}

function setField(field: keyof AgentConfigSummary, value: unknown) {
  if (!state.config || value === null || value === undefined) {
    return;
  }

  const coerced = coerceField(field, value);
  (state.config.summary as Record<string, unknown>)[field] = coerced;
  state.config.raw = applyFieldToToml(state.config.raw, field, coerced);
  state.diagnostics = null;
  state.dirty = true;
}

function setRawConfig(raw: string) {
  if (!state.config) {
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
  if (!state.config) {
    return;
  }
  const next = normalizeRules([...state.config.summary.direct_rules, ...rules]);
  updateDirectRules(next);
  state.ruleDraft = "";
  showToast("success", "规则已更新");
}

function addDraftRules() {
  addDirectRules(parseRuleInput(state.ruleDraft));
}

function removeDirectRule(index: number) {
  if (!state.config || !Number.isInteger(index)) {
    return;
  }
  const next = normalizeRules(state.config.summary.direct_rules).filter((_, current) => current !== index);
  updateDirectRules(next);
}

function updateDirectRules(rules: string[]) {
  if (!state.config) {
    return;
  }
  state.config.summary.direct_rules = normalizeRules(rules);
  state.config.raw = applyFieldToToml(state.config.raw, "direct_rules", state.config.summary.direct_rules);
  state.diagnostics = null;
  state.dirty = true;
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

function coerceField(field: keyof AgentConfigSummary, value: unknown): unknown {
  if (typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return value;
  }
  if (
    [
      "tcp_pool_size",
      "udp_pool_size",
      "connect_timeout_secs",
      "tcp_yamux_sessions",
      "udp_yamux_sessions",
      "tun_mtu",
      "runtime_threads"
    ].includes(field)
  ) {
    const parsed = Number.parseInt(String(value), 10);
    return Number.isFinite(parsed) ? Math.max(0, parsed) : 0;
  }
  if (field === "proxy_addrs" || field === "direct_rules") {
    return String(value)
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return String(value);
}

function applyFieldToToml(raw: string, field: keyof AgentConfigSummary, value: unknown) {
  const mapping: Record<string, { section: string | null; key: string; kind: "string" | "number" | "bool" | "array" }> = {
    listen_addr: { section: null, key: "listen_addr", kind: "string" },
    proxy_addrs: { section: null, key: "proxy_addrs", kind: "array" },
    username: { section: null, key: "username", kind: "string" },
    private_key_path: { section: null, key: "private_key_path", kind: "string" },
    tcp_pool_size: { section: null, key: "tcp_pool_size", kind: "number" },
    udp_pool_size: { section: null, key: "udp_pool_size", kind: "number" },
    connect_timeout_secs: { section: null, key: "connect_timeout_secs", kind: "number" },
    compression_mode: { section: null, key: "compression_mode", kind: "string" },
    log_level: { section: null, key: "log_level", kind: "string" },
    runtime_threads: { section: null, key: "runtime_threads", kind: "number" },
    tcp_mode: { section: "transport", key: "tcp_mode", kind: "string" },
    udp_mode: { section: "transport", key: "udp_mode", kind: "string" },
    tcp_yamux_sessions: { section: "yamux.tcp", key: "sessions", kind: "number" },
    udp_yamux_sessions: { section: "yamux.udp", key: "sessions", kind: "number" },
    tun_enabled: { section: "tun", key: "enabled", kind: "bool" },
    tun_name: { section: "tun", key: "name", kind: "string" },
    tun_ipv4: { section: "tun", key: "ipv4", kind: "string" },
    tun_mtu: { section: "tun", key: "mtu", kind: "number" },
    tun_proxy_dns: { section: "tun", key: "proxy_dns", kind: "bool" },
    tun_block_quic: { section: "tun", key: "block_quic", kind: "bool" },
    direct_mode: { section: "direct_access", key: "mode", kind: "string" },
    direct_rules: { section: "direct_access", key: "rules", kind: "array" },
    log_dir: { section: null, key: "log_dir", kind: "string" },
    log_file: { section: null, key: "log_file", kind: "string" }
  };

  const target = mapping[field];
  if (!target) {
    return raw;
  }

  return upsertTomlValue(raw, target.section, target.key, formatTomlValue(value, target.kind));
}

function upsertTomlValue(raw: string, section: string | null, key: string, value: string) {
  const lines = raw.split(/\r?\n/);
  const sectionStart = section ? findSection(lines, section) : 0;
  const sectionEnd = section ? findSectionEnd(lines, sectionStart) : findFirstSection(lines);
  const assignment = `${key} = ${value}`;

  if (section && sectionStart === -1) {
    const suffix = raw.endsWith("\n") ? "" : "\n";
    return `${raw}${suffix}\n[${section}]\n${assignment}\n`;
  }

  const start = section ? sectionStart + 1 : 0;
  const end = section ? sectionEnd : sectionEnd === -1 ? lines.length : sectionEnd;

  for (let index = start; index < end; index += 1) {
    const line = lines[index];
    if (new RegExp(`^\\s*${escapeRegExp(key)}\\s*=`).test(line)) {
      const replacementEnd = findAssignmentBlockEnd(lines, index);
      lines.splice(index, replacementEnd - index, assignment);
      return lines.join("\n");
    }
  }

  lines.splice(end, 0, assignment);
  return lines.join("\n");
}

function findSection(lines: string[], section: string) {
  return lines.findIndex((line) => line.trim() === `[${section}]`);
}

function findSectionEnd(lines: string[], start: number) {
  if (start < 0) {
    return lines.length;
  }
  const next = lines.findIndex((line, index) => index > start && /^\s*\[[^\]]+\]\s*$/.test(line));
  return next === -1 ? lines.length : next;
}

function findFirstSection(lines: string[]) {
  const index = lines.findIndex((line) => /^\s*\[[^\]]+\]\s*$/.test(line));
  return index === -1 ? lines.length : index;
}

function findAssignmentBlockEnd(lines: string[], start: number) {
  if (!lines[start].includes("[") || lines[start].includes("]")) {
    return start + 1;
  }
  for (let index = start + 1; index < lines.length; index += 1) {
    if (lines[index].trim() === "]") {
      return index + 1;
    }
  }
  return start + 1;
}

function formatTomlValue(value: unknown, kind: "string" | "number" | "bool" | "array") {
  if (kind === "string") {
    return JSON.stringify(String(value ?? ""));
  }
  if (kind === "number") {
    return String(Number(value) || 0);
  }
  if (kind === "bool") {
    return value ? "true" : "false";
  }
  const items = Array.isArray(value) ? value : [];
  return `[${items.map((item) => JSON.stringify(String(item))).join(", ")}]`;
}

function summarizeRaw(raw: string): AgentConfigSummary {
  return {
    listen_addr: matchString(raw, null, "listen_addr") ?? "127.0.0.1:10080",
    proxy_addrs: matchStringArray(raw, "proxy_addrs"),
    username: matchString(raw, null, "username") ?? "user1",
    private_key_path: matchString(raw, null, "private_key_path") ?? "keys/user1.pem",
    tcp_pool_size: matchNumber(raw, null, "tcp_pool_size") ?? 10,
    udp_pool_size: matchNumber(raw, null, "udp_pool_size") ?? 5,
    connect_timeout_secs: matchNumber(raw, null, "connect_timeout_secs") ?? 30,
    compression_mode: matchString(raw, null, "compression_mode") ?? "none",
    log_level: matchString(raw, null, "log_level") ?? "info",
    log_dir: matchString(raw, null, "log_dir"),
    log_file: matchString(raw, null, "log_file") ?? "desktop-agent.log",
    runtime_threads: matchNumber(raw, null, "runtime_threads"),
    tcp_mode: matchString(raw, "transport", "tcp_mode") ?? "auto",
    udp_mode: matchString(raw, "transport", "udp_mode") ?? "auto",
    tcp_yamux_sessions: matchNumber(raw, "yamux.tcp", "sessions") ?? 5,
    udp_yamux_sessions: matchNumber(raw, "yamux.udp", "sessions") ?? 5,
    tun_enabled: matchBool(raw, "tun", "enabled") ?? false,
    tun_name: matchString(raw, "tun", "name") ?? "ppaass-tun",
    tun_ipv4: matchString(raw, "tun", "ipv4") ?? "10.10.10.1/24",
    tun_mtu: matchNumber(raw, "tun", "mtu") ?? 1500,
    tun_proxy_dns: matchBool(raw, "tun", "proxy_dns") ?? false,
    tun_block_quic: matchBool(raw, "tun", "block_quic") ?? true,
    direct_mode: matchString(raw, "direct_access", "mode") ?? "proxy_all",
    direct_rules: matchStringArray(raw, "rules", "direct_access")
  };
}

function matchString(raw: string, section: string | null, key: string) {
  const body = sectionBody(raw, section);
  const match = body.match(new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*"([^"]*)"`, "m"));
  return match?.[1];
}

function matchNumber(raw: string, section: string | null, key: string) {
  const body = sectionBody(raw, section);
  const match = body.match(new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*(\\d+)`, "m"));
  return match ? Number.parseInt(match[1], 10) : undefined;
}

function matchBool(raw: string, section: string | null, key: string) {
  const body = sectionBody(raw, section);
  const match = body.match(new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*(true|false)`, "m"));
  return match ? match[1] === "true" : undefined;
}

function matchStringArray(raw: string, key: string, section: string | null = null) {
  const body = sectionBody(raw, section);
  const singleLine = body.match(new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*\\[([^\\]]*)\\]`, "m"));
  const arrayBody = singleLine?.[1];
  if (!arrayBody) {
    return [];
  }
  return [...arrayBody.matchAll(/"([^"]*)"/g)].map((match) => match[1]);
}

function sectionBody(raw: string, section: string | null) {
  if (!section) {
    const index = raw.search(/^\s*\[[^\]]+\]\s*$/m);
    return index === -1 ? raw : raw.slice(0, index);
  }
  const match = new RegExp(`^\\s*\\[${escapeRegExp(section)}\\]\\s*$`, "m").exec(raw);
  if (!match) {
    return "";
  }
  const start = (match.index ?? 0) + match[0].length;
  const rest = raw.slice(start);
  const next = rest.search(/^\s*\[[^\]]+\]\s*$/m);
  return next === -1 ? rest : rest.slice(0, next);
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

function loadFallbackConfig(): LoadedAgentConfig {
  return {
    path: "config/local/agent.toml",
    raw: fallbackRawConfig,
    summary: summarizeRaw(fallbackRawConfig)
  };
}

function fallbackAgentState(): AgentState {
  return {
    running: false,
    managed: false,
    pid: null,
    config_path: "config/local/agent.toml",
    binary_path: "target/release/desktop-agent",
    logs: ["desktop-agent ready", "proxy route guard initialized", "yamux tcp sessions: 5", "tun mode: disabled"]
  };
}

function fallbackConnectivityReport(currentSummary?: AgentConfigSummary): ConnectivityReport {
  const listenAddr = currentSummary?.listen_addr ?? "127.0.0.1:10080";
  const results = ["Google", "YouTube"].flatMap((target) =>
    ["HTTP", "SOCKS5"].map((protocol) => ({
      target,
      protocol,
      url: target === "Google" ? "https://www.google.com/generate_204" : "https://www.youtube.com/generate_204",
      proxy_url: `${protocol === "HTTP" ? "http" : "socks5h"}://${listenAddr}`,
      success: false,
      http_code: null,
      duration_ms: 0,
      error: "需要 Tauri 运行时"
    }))
  );

  return {
    listen_addr: listenAddr,
    agent_reachable: false,
    generated_at_ms: Date.now(),
    results
  };
}

function fallbackTrafficSnapshot(): NetworkTrafficSnapshot {
  return {
    sampled_at_ms: Date.now(),
    total_received_bytes: 0,
    total_transmitted_bytes: 0,
    interfaces: []
  };
}

function showToast(kind: ToastKind, message: string) {
  state.toast = { kind, message };
  window.setTimeout(() => {
    state.toast = null;
  }, 2600);
}

function shortPath(path?: string | null) {
  if (!path) {
    return "—";
  }
  const normalized = path.replaceAll("\\", "/");
  const parts = normalized.split("/");
  if (parts.length <= 2) {
    return normalized;
  }
  return `${parts.at(-2)}/${parts.at(-1)}`;
}

function shortProxyUrl(value: string) {
  return value.replace(/^https?:\/\//, "").replace(/^socks5h:\/\//, "socks5h ");
}

function formatTimestamp(timestampMs: number) {
  if (!timestampMs) {
    return "—";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(timestampMs));
}

function formatRate(bytesPerSecondValue: number) {
  return `${formatBytes(bytesPerSecondValue)}/s`;
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function hourlyBarHeight(bytes: number) {
  if (bytes <= 0) {
    return "2px";
  }
  return `${Math.max(4, (bytes / hourlyTrafficMax.value) * 100)}%`;
}

function hourLabel(hour: number) {
  if (hour === 0 || hour === 6 || hour === 12 || hour === 18 || hour === 23) {
    return String(hour).padStart(2, "0");
  }
  return "";
}

function localDateKey() {
  const now = new Date();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${now.getFullYear()}-${month}-${day}`;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
</script>

<template>
  <main class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">P</div>
        <div>
          <div class="brand-title">PPAASS</div>
          <div class="brand-subtitle">Desktop Agent</div>
        </div>
      </div>

      <nav class="nav">
        <Button
          v-for="tab in tabs"
          :key="tab.key"
          :class="['nav-button', { active: state.activeTab === tab.key }]"
          :icon="tab.icon"
          :label="tab.label"
          text
          @click="state.activeTab = tab.key"
        />
      </nav>

      <div class="sidebar-status">
        <Tag :severity="runningSeverity" :value="runningLabel" rounded />
        <div class="sidebar-meta">
          <span>PID</span>
          <strong>{{ running && state.agent.pid ? state.agent.pid : "—" }}</strong>
        </div>
        <div class="sidebar-meta">
          <span>配置</span>
          <strong :title="state.config?.path ?? ''">{{ shortPath(state.config?.path) }}</strong>
        </div>
      </div>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div>
          <h1>Desktop Agent</h1>
          <p>{{ summary.listen_addr || state.statusText }}</p>
        </div>
        <div class="toolbar">
          <Button icon="pi pi-refresh" severity="secondary" outlined rounded aria-label="重新载入" @click="reloadAll" />
          <Button
            icon="pi pi-save"
            severity="secondary"
            outlined
            rounded
            aria-label="保存配置"
            :disabled="!state.dirty"
            @click="saveConfig"
          />
          <Button v-if="running && managed" label="停止" icon="pi pi-stop" severity="danger" @click="stopAgent" />
          <Button v-else-if="running" label="外部运行" icon="pi pi-bolt" severity="secondary" disabled />
          <Button v-else label="启动" icon="pi pi-play" severity="primary" @click="startAgent" />
        </div>
      </header>

      <section v-if="state.loading" class="loading">
        <ProgressSpinner />
        <span>加载中</span>
      </section>

      <section v-else-if="!state.config" class="empty-state">
        <i class="pi pi-exclamation-triangle"></i>
        <h2>未载入配置</h2>
      </section>

      <div v-else-if="state.activeTab === 'overview'" class="content-grid">
        <Card class="panel span-7">
          <template #title>
            <div class="panel-heading inline">
              <div>
                <h2>运行状态</h2>
                <p>{{ state.agent.binary_path ? shortPath(state.agent.binary_path) : "desktop-agent" }}</p>
              </div>
              <Badge :value="state.agent.running ? 'Active' : 'Idle'" :severity="state.agent.running ? 'success' : 'secondary'" />
            </div>
          </template>
          <template #content>
            <div class="status-board">
              <div class="metric-tile">
                <i class="pi pi-broadcast-tower"></i>
                <span>本地入口</span>
                <strong>{{ summary.listen_addr }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-server"></i>
                <span>代理节点</span>
                <strong>{{ summary.proxy_addrs.length }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-clone"></i>
                <span>TCP 池</span>
                <strong>{{ summary.tcp_pool_size }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-wave-pulse"></i>
                <span>UDP 池</span>
                <strong>{{ summary.udp_pool_size }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-box"></i>
                <span>压缩</span>
                <strong>{{ summary.compression_mode }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-chart-line"></i>
                <span>日志</span>
                <strong>{{ summary.log_level }}</strong>
              </div>
            </div>
          </template>
        </Card>

        <Card class="panel span-5">
          <template #title>
            <div class="panel-heading inline">
              <h2>代理出口</h2>
              <Tag :value="`${summary.tcp_mode.toUpperCase()} / ${summary.udp_mode.toUpperCase()}`" severity="info" />
            </div>
          </template>
          <template #content>
            <div class="endpoint-list">
              <div v-for="proxy in summary.proxy_addrs" :key="proxy" class="endpoint-row">
                <i class="pi pi-server"></i>
                <span>{{ proxy }}</span>
              </div>
              <div v-if="!summary.proxy_addrs.length" class="endpoint-row muted">
                <i class="pi pi-server"></i>
                <span>未配置</span>
              </div>
            </div>
          </template>
        </Card>

        <Card class="panel span-6">
          <template #title>
            <div class="panel-heading inline">
              <h2>实时网速</h2>
              <Tag value="System" severity="info" />
            </div>
          </template>
          <template #content>
            <div class="speed-gauges">
              <div class="speed-gauge">
                <Knob
                  :model-value="downloadGaugeValue"
                  :size="132"
                  readonly
                  value-color="#2563eb"
                  range-color="#dbeafe"
                  text-color="#1e293b"
                />
                <span>下载</span>
                <strong>{{ formatRate(state.traffic.download_bps) }}</strong>
              </div>
              <div class="speed-gauge">
                <Knob
                  :model-value="uploadGaugeValue"
                  :size="132"
                  readonly
                  value-color="#14b8a6"
                  range-color="#ccfbf1"
                  text-color="#1e293b"
                />
                <span>上传</span>
                <strong>{{ formatRate(state.traffic.upload_bps) }}</strong>
              </div>
            </div>
          </template>
        </Card>

        <Card class="panel span-6">
          <template #title>
            <div class="panel-heading inline">
              <h2>今日流量</h2>
              <span>{{ state.traffic.baseline?.date ?? localDateKey() }}</span>
            </div>
          </template>
          <template #content>
            <div class="hourly-chart">
              <div class="hourly-totals">
                <Tag :value="`下载 ${formatBytes(state.traffic.day_download_bytes)}`" severity="info" rounded />
                <Tag :value="`上传 ${formatBytes(state.traffic.day_upload_bytes)}`" severity="success" rounded />
              </div>

              <div class="hourly-bars">
                <div v-for="bucket in state.traffic.hourly_buckets" :key="bucket.hour" class="hourly-column">
                  <div class="hourly-stack" :title="`${bucket.hour}:00 下载 ${formatBytes(bucket.download_bytes)} / 上传 ${formatBytes(bucket.upload_bytes)}`">
                    <div class="hourly-segment upload" :style="{ height: hourlyBarHeight(bucket.upload_bytes) }"></div>
                    <div class="hourly-segment download" :style="{ height: hourlyBarHeight(bucket.download_bytes) }"></div>
                  </div>
                  <span>{{ hourLabel(bucket.hour) }}</span>
                </div>
              </div>

              <div class="hourly-legend">
                <span><i class="legend-dot download"></i>下载</span>
                <span><i class="legend-dot upload"></i>上传</span>
              </div>
            </div>
          </template>
        </Card>

        <Card class="panel span-6">
          <template #title>
            <div class="panel-heading inline">
              <h2>TUN</h2>
              <Tag :value="summary.tun_enabled ? 'Enabled' : 'Disabled'" :severity="summary.tun_enabled ? 'success' : 'secondary'" />
            </div>
          </template>
          <template #content>
            <div class="kv-list">
              <div class="kv-row"><span>设备</span><strong>{{ summary.tun_name }}</strong></div>
              <div class="kv-row"><span>地址</span><strong>{{ summary.tun_ipv4 }}</strong></div>
              <div class="kv-row"><span>MTU</span><strong>{{ summary.tun_mtu }}</strong></div>
              <div class="kv-row"><span>DNS</span><strong>{{ summary.tun_proxy_dns ? "Proxy" : "System" }}</strong></div>
            </div>
          </template>
        </Card>

        <Card class="panel span-6">
          <template #title>
            <div class="panel-heading inline">
              <h2>直连规则</h2>
              <Tag :value="summary.direct_mode" severity="info" />
            </div>
          </template>
          <template #content>
            <div class="rule-strip">
              <Tag v-for="rule in summary.direct_rules.slice(0, 10)" :key="rule" :value="rule" severity="success" rounded />
              <Tag v-if="summary.direct_rules.length > 10" :value="`+${summary.direct_rules.length - 10}`" severity="secondary" rounded />
            </div>
          </template>
        </Card>
      </div>

      <div v-else-if="state.activeTab === 'network'" class="content-grid">
        <Card class="panel span-6">
          <template #title><h2>身份</h2></template>
          <template #content>
            <label class="field">
              <span><i class="pi pi-user"></i>用户</span>
              <InputText :model-value="summary.username" @update:model-value="setField('username', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-key"></i>私钥</span>
              <InputText :model-value="summary.private_key_path" @update:model-value="setField('private_key_path', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-broadcast-tower"></i>本地入口</span>
              <InputText :model-value="summary.listen_addr" @update:model-value="setField('listen_addr', $event)" />
            </label>
          </template>
        </Card>

        <Card class="panel span-6">
          <template #title><h2>代理</h2></template>
          <template #content>
            <label class="field">
              <span><i class="pi pi-server"></i>节点</span>
              <Textarea
                :model-value="summary.proxy_addrs.join('\n')"
                rows="5"
                auto-resize
                @update:model-value="setField('proxy_addrs', $event)"
              />
            </label>
            <div class="field-pair">
              <label class="field">
                <span><i class="pi pi-clock"></i>连接超时</span>
                <InputNumber
                  :model-value="summary.connect_timeout_secs"
                  :min="0"
                  :use-grouping="false"
                  @update:model-value="setField('connect_timeout_secs', $event)"
                />
              </label>
              <label class="field">
                <span><i class="pi pi-box"></i>压缩</span>
                <Select :model-value="summary.compression_mode" :options="compressionOptions" @update:model-value="setField('compression_mode', $event)" />
              </label>
            </div>
          </template>
        </Card>

        <Card class="panel span-6">
          <template #title><h2>连接池</h2></template>
          <template #content>
            <div class="field-pair">
              <label class="field">
                <span><i class="pi pi-clone"></i>TCP</span>
                <InputNumber :model-value="summary.tcp_pool_size" :min="0" :use-grouping="false" @update:model-value="setField('tcp_pool_size', $event)" />
              </label>
              <label class="field">
                <span><i class="pi pi-wave-pulse"></i>UDP</span>
                <InputNumber :model-value="summary.udp_pool_size" :min="0" :use-grouping="false" @update:model-value="setField('udp_pool_size', $event)" />
              </label>
            </div>
            <div class="field-pair">
              <label class="field">
                <span><i class="pi pi-share-alt"></i>TCP Yamux</span>
                <InputNumber :model-value="summary.tcp_yamux_sessions" :min="0" :use-grouping="false" @update:model-value="setField('tcp_yamux_sessions', $event)" />
              </label>
              <label class="field">
                <span><i class="pi pi-share-alt"></i>UDP Yamux</span>
                <InputNumber :model-value="summary.udp_yamux_sessions" :min="0" :use-grouping="false" @update:model-value="setField('udp_yamux_sessions', $event)" />
              </label>
            </div>
          </template>
        </Card>

        <Card class="panel span-6">
          <template #title><h2>传输</h2></template>
          <template #content>
            <label class="field">
              <span><i class="pi pi-toggle-on"></i>TCP</span>
              <SelectButton :model-value="summary.tcp_mode" :options="transportModeOptions" :allow-empty="false" @update:model-value="setField('tcp_mode', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-toggle-on"></i>UDP</span>
              <SelectButton :model-value="summary.udp_mode" :options="transportModeOptions" :allow-empty="false" @update:model-value="setField('udp_mode', $event)" />
            </label>
            <div class="field-pair">
              <label class="field">
                <span><i class="pi pi-chart-line"></i>日志</span>
                <Select :model-value="summary.log_level" :options="logLevelOptions" @update:model-value="setField('log_level', $event)" />
              </label>
              <label class="field">
                <span><i class="pi pi-microchip"></i>线程</span>
                <InputNumber :model-value="summary.runtime_threads ?? 0" :min="0" :use-grouping="false" @update:model-value="setField('runtime_threads', $event)" />
              </label>
            </div>
          </template>
        </Card>
      </div>

      <div v-else-if="state.activeTab === 'tun'" class="content-grid">
        <Card class="panel span-5">
          <template #title>
            <div class="panel-heading inline">
              <h2>设备</h2>
              <ToggleSwitch :model-value="summary.tun_enabled" @update:model-value="setField('tun_enabled', $event)" />
            </div>
          </template>
          <template #content>
            <label class="field">
              <span><i class="pi pi-desktop"></i>名称</span>
              <InputText :model-value="summary.tun_name" @update:model-value="setField('tun_name', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-hashtag"></i>IPv4</span>
              <InputText :model-value="summary.tun_ipv4" @update:model-value="setField('tun_ipv4', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-gauge"></i>MTU</span>
              <InputNumber :model-value="summary.tun_mtu" :min="0" :use-grouping="false" @update:model-value="setField('tun_mtu', $event)" />
            </label>
          </template>
        </Card>

        <Card class="panel span-7">
          <template #title><h2>流量策略</h2></template>
          <template #content>
            <div class="toggle-list">
              <div class="switch-row">
                <span>Proxy DNS</span>
                <ToggleSwitch :model-value="summary.tun_proxy_dns" @update:model-value="setField('tun_proxy_dns', $event)" />
              </div>
              <div class="switch-row">
                <span>阻断 QUIC</span>
                <ToggleSwitch :model-value="summary.tun_block_quic" @update:model-value="setField('tun_block_quic', $event)" />
              </div>
            </div>

            <label class="field direct-mode-field">
              <span><i class="pi pi-directions"></i>直连</span>
              <SelectButton :model-value="summary.direct_mode" :options="directModeOptions" :allow-empty="false" @update:model-value="setField('direct_mode', $event)" />
            </label>

            <div class="rules-editor">
              <label class="field rule-input-field">
                <span><i class="pi pi-list-plus"></i>规则</span>
                <div class="rule-input-row">
                  <InputText v-model="state.ruleDraft" placeholder="example.com  *.example.com  10.0.0.0/8" @keydown.enter.prevent="addDraftRules" />
                  <Button icon="pi pi-plus" severity="primary" rounded aria-label="添加" @click="addDraftRules" />
                </div>
              </label>

              <div class="preset-row">
                <Button
                  v-for="preset in directRulePresets"
                  :key="preset.label"
                  :icon="preset.icon"
                  :label="preset.label"
                  severity="secondary"
                  outlined
                  size="small"
                  @click="addDirectRules(preset.rules)"
                />
              </div>

              <div class="rule-toolbar">
                <span>{{ summary.direct_rules.length }} 条</span>
              </div>
              <div class="rule-chip-list">
                <div v-if="!summary.direct_rules.length" class="empty-rules">未配置</div>
                <div v-for="(rule, index) in summary.direct_rules" v-else :key="`${rule}-${index}`" class="rule-chip">
                  <span :title="rule">{{ rule }}</span>
                  <Button icon="pi pi-times" text rounded severity="secondary" aria-label="删除" @click="removeDirectRule(index)" />
                </div>
              </div>
            </div>
          </template>
        </Card>
      </div>

      <div v-else-if="state.activeTab === 'diagnostics'" class="content-grid">
        <Card class="panel span-5">
          <template #title>
            <div class="panel-heading inline">
              <div>
                <h2>出口诊断</h2>
                <p>{{ summary.listen_addr }}</p>
              </div>
              <Button
                :label="state.diagnosticsRunning ? '测试中' : '运行测试'"
                :icon="state.diagnosticsRunning ? 'pi pi-spin pi-spinner' : 'pi pi-play'"
                :disabled="state.diagnosticsRunning"
                @click="runDiagnostics"
              />
            </div>
          </template>
          <template #content>
            <div class="diagnostic-summary">
              <div class="metric-tile">
                <i :class="state.diagnostics?.agent_reachable ? 'pi pi-check-circle' : 'pi pi-exclamation-circle'"></i>
                <span>本地入口</span>
                <strong>{{ state.diagnostics ? (state.diagnostics.agent_reachable ? "Reachable" : "Offline") : "Pending" }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-globe"></i>
                <span>站点</span>
                <strong>Google / YouTube</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-shield"></i>
                <span>结果</span>
                <strong>{{ state.diagnostics ? `${diagnosticsPassed}/${state.diagnostics.results.length}` : "—" }}</strong>
              </div>
            </div>
          </template>
        </Card>

        <Card class="panel span-7">
          <template #title>
            <div class="panel-heading inline">
              <h2>链路结果</h2>
              <span>{{ state.diagnostics ? formatTimestamp(state.diagnostics.generated_at_ms) : "—" }}</span>
            </div>
          </template>
          <template #content>
            <div class="diagnostic-list">
              <div v-if="!state.diagnostics" class="diagnostic-row muted">
                <div><strong>Google</strong><span>HTTP / SOCKS5</span></div>
                <span>未测试</span>
              </div>
              <div v-if="!state.diagnostics" class="diagnostic-row muted">
                <div><strong>YouTube</strong><span>HTTP / SOCKS5</span></div>
                <span>未测试</span>
              </div>
              <div v-for="item in state.diagnostics?.results ?? []" :key="`${item.target}-${item.protocol}`" :class="['diagnostic-row', item.success ? 'ok' : 'fail']">
                <div>
                  <strong>{{ item.target }} · {{ item.protocol }}</strong>
                  <span :title="item.proxy_url">{{ shortProxyUrl(item.proxy_url) }}</span>
                </div>
                <div class="diagnostic-result">
                  <strong>{{ item.http_code ?? "—" }}</strong>
                  <span>{{ Math.max(1, Math.round(item.duration_ms)) }} ms</span>
                </div>
                <p v-if="item.error">{{ item.error }}</p>
              </div>
            </div>
          </template>
        </Card>
      </div>

      <Card v-else-if="state.activeTab === 'logs'" class="panel full-height">
        <template #title>
          <div class="panel-heading inline">
            <h2>日志</h2>
            <Button icon="pi pi-refresh" label="刷新" severity="secondary" outlined size="small" @click="reloadAll" />
          </div>
        </template>
        <template #content>
          <div class="log-view">
            <div v-if="!state.agent.logs.length" class="log-empty">暂无日志</div>
            <div v-for="(line, index) in state.agent.logs" :key="index">{{ line }}</div>
          </div>
        </template>
      </Card>

      <Card v-else-if="state.activeTab === 'toml'" class="panel full-height">
        <template #title>
          <div class="panel-heading inline">
            <h2>TOML</h2>
            <span :title="state.config?.path ?? ''">{{ shortPath(state.config?.path) }}</span>
          </div>
        </template>
        <template #content>
          <Textarea class="toml-editor" :model-value="state.config?.raw ?? ''" @update:model-value="setRawConfig(String($event))" />
        </template>
      </Card>
    </section>

    <Transition name="toast">
      <div v-if="state.toast" :class="['toast', state.toast.kind]">{{ state.toast.message }}</div>
    </Transition>
  </main>
</template>
