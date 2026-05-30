<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
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

type TabKey = "overview" | "forwarding" | "egress" | "routing" | "diagnostics" | "logs" | "toml";

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
  effective_runtime_threads: number;
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
  tun_enabled: boolean;
  tun_name: string;
  tun_ready: boolean;
  tun_status: string;
  agent_reachable: boolean;
  generated_at_ms: number;
  results: ConnectivityCheck[];
  tun_results: ConnectivityCheck[];
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

type DirectRuleGroup = {
  key: string;
  label: string;
  icon: string;
  items: Array<{ rule: string; index: number }>;
};

type OverviewCardKey = "status" | "proxy" | "egress" | "speed" | "traffic" | "tun" | "policy";

type OverviewCardDefinition = {
  key: OverviewCardKey;
  baseSpan: number;
};

type OverviewCardView = OverviewCardDefinition & {
  span: number;
};

type OverviewDragGhost = {
  x: number;
  y: number;
  width: number;
  height: number;
  offsetX: number;
  offsetY: number;
};

type LogTokenKind =
  | "plain"
  | "timestamp"
  | "level-trace"
  | "level-debug"
  | "level-info"
  | "level-warn"
  | "level-error"
  | "thread"
  | "target"
  | "field"
  | "string"
  | "number"
  | "address";

type LogToken = {
  value: string;
  kind: LogTokenKind;
};

type HighlightedLogLine = {
  raw: string;
  level: string | null;
  tokens: LogToken[];
};

type TomlTokenKind =
  | "plain"
  | "section"
  | "key"
  | "equals"
  | "string"
  | "number"
  | "boolean"
  | "date"
  | "comment"
  | "punctuation";

type TomlToken = {
  value: string;
  kind: TomlTokenKind;
};

type HighlightedTomlLine = {
  raw: string;
  tokens: TomlToken[];
};

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
  { key: "forwarding", label: "转发", icon: "pi pi-sitemap" },
  { key: "egress", label: "出口", icon: "pi pi-share-alt" },
  { key: "routing", label: "系统", icon: "pi pi-cog" },
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
const directModeLabels: Record<string, string> = {
  proxy_all: "全走代理",
  direct_all: "全量直连",
  rules: "按规则"
};
const directModeOptions = [
  { label: "代理", value: "proxy_all" },
  { label: "直连", value: "direct_all" },
  { label: "规则", value: "rules" }
];
const overviewLayoutKey = "ppaass-agent-ui:overview-card-order:v1";
const overviewCardDefinitions: OverviewCardDefinition[] = [
  { key: "status", baseSpan: 7 },
  { key: "proxy", baseSpan: 5 },
  { key: "egress", baseSpan: 6 },
  { key: "speed", baseSpan: 6 },
  { key: "traffic", baseSpan: 6 },
  { key: "tun", baseSpan: 6 },
  { key: "policy", baseSpan: 6 }
];
const defaultOverviewCardOrder = overviewCardDefinitions.map((card) => card.key);
const overviewCardByKey = new Map(overviewCardDefinitions.map((card) => [card.key, card]));
const trafficBaselineKey = "ppaass-agent-ui:traffic-baseline:v1";
const trafficHourlyKey = "ppaass-agent-ui:traffic-hourly:v1";
const state = reactive({
  activeTab: "overview" as TabKey,
  loading: true,
  busy: false,
  diagnosticsRunning: false,
  dirty: false,
  ruleDraft: "",
  overviewCardOrder: readOverviewCardOrder(),
  draggingOverviewCard: null as OverviewCardKey | null,
  dragOverOverviewCard: null as OverviewCardKey | null,
  overviewDragGhost: null as OverviewDragGhost | null,
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
const configLocked = computed(() => running.value);
const runningLabel = computed(() => {
  if (!running.value) {
    return "已停止";
  }
  return "运行中";
});
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
const speedGaugeMax = computed(() => Math.max(256 * 1024, state.traffic.download_bps, state.traffic.upload_bps) * 1.25);
const downloadGaugeValue = computed(() => Math.round((state.traffic.download_bps / speedGaugeMax.value) * 100));
const uploadGaugeValue = computed(() => Math.round((state.traffic.upload_bps / speedGaugeMax.value) * 100));
const hourlyTrafficMax = computed(() =>
  Math.max(
    1,
    ...state.traffic.hourly_buckets.map((bucket) => bucket.download_bytes + bucket.upload_bytes)
  )
);
const directModeLabel = computed(() => directModeLabels[summary.value.direct_mode] ?? summary.value.direct_mode);
const tunModeLabel = computed(() => (summary.value.tun_enabled ? "已启用" : "未启用"));
const proxyEntryStateLabel = computed(() => "随 Agent 启动");
const activeForwardingLabel = computed(() => (summary.value.tun_enabled ? "TUN + HTTP / SOCKS5" : "HTTP / SOCKS5 代理"));
const overviewCards = computed(() => buildOverviewCards(state.overviewCardOrder));
const highlightedLogs = computed(() => state.agent.logs.map(tokenizeLogLine));
const highlightedToml = computed(() => tokenizeToml(state.config?.raw ?? ""));
const tomlHighlightRef = ref<HTMLElement | null>(null);
const directRuleGroups = computed(() => {
  const groups: DirectRuleGroup[] = [
    { key: "wildcard", label: "通配符", icon: "pi pi-asterisk", items: [] },
    { key: "network", label: "IP / CIDR", icon: "pi pi-hashtag", items: [] },
    { key: "domain", label: "域名", icon: "pi pi-globe", items: [] },
    { key: "other", label: "其他", icon: "pi pi-ellipsis-h", items: [] }
  ];
  const byKey = new Map(groups.map((group) => [group.key, group]));

  summary.value.direct_rules.forEach((rule, index) => {
    byKey.get(ruleGroupKey(rule))?.items.push({ rule, index });
  });

  return groups.filter((group) => group.items.length > 0);
});

let trafficTimer: number | undefined;
let agentTimer: number | undefined;

onMounted(() => {
  void boot();
  startTrafficPolling();
  startAgentPolling();
});

onBeforeUnmount(() => {
  if (trafficTimer) {
    window.clearInterval(trafficTimer);
  }
  if (agentTimer) {
    window.clearInterval(agentTimer);
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
  if (!ensureConfigEditable()) {
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
    const kind = total > 0 && passed === total ? "success" : "error";
    showToast(kind, `诊断完成：${passed}/${total}`);
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
  if (!ensureConfigEditable(false)) {
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
  if (!state.config) {
    return;
  }
  if (!ensureConfigEditable(false)) {
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

function guardIntegerBeforeInput(event: InputEvent) {
  const target = event.target;
  if (!isIntegerInputTarget(target) || !event.data) {
    return;
  }

  if (!/^\d+$/.test(event.data)) {
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

function isIntegerInputTarget(target: EventTarget | null): target is HTMLInputElement {
  return target instanceof HTMLInputElement && Boolean(target.closest(".p-inputnumber"));
}

function digitsOnly(value: string) {
  return value.replace(/\D+/g, "");
}

function syncTomlHighlightScroll(event: Event) {
  const target = event.currentTarget as HTMLTextAreaElement | null;
  const highlighter = tomlHighlightRef.value;
  if (!target || !highlighter) {
    return;
  }
  highlighter.scrollTop = target.scrollTop;
  highlighter.scrollLeft = target.scrollLeft;
}

function addDirectRules(rules: string[]) {
  if (!state.config) {
    return;
  }
  if (!ensureConfigEditable()) {
    return;
  }
  const next = normalizeRules([...state.config.summary.direct_rules, ...rules]);
  updateDirectRules(next);
  state.ruleDraft = "";
  showToast("success", "规则已更新");
}

function addDraftRules() {
  if (!ensureConfigEditable()) {
    return;
  }
  addDirectRules(parseRuleInput(state.ruleDraft));
}

function removeDirectRule(index: number) {
  if (!state.config || !Number.isInteger(index)) {
    return;
  }
  if (!ensureConfigEditable()) {
    return;
  }
  const next = normalizeRules(state.config.summary.direct_rules).filter((_, current) => current !== index);
  updateDirectRules(next);
}

function updateDirectRules(rules: string[]) {
  if (!state.config) {
    return;
  }
  if (!ensureConfigEditable(false)) {
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

function readOverviewCardOrder() {
  try {
    const raw = localStorage.getItem(overviewLayoutKey);
    return normalizeOverviewCardOrder(raw ? JSON.parse(raw) : []);
  } catch {
    return [...defaultOverviewCardOrder];
  }
}

function normalizeOverviewCardOrder(value: unknown): OverviewCardKey[] {
  const order: OverviewCardKey[] = [];
  const known = new Set(defaultOverviewCardOrder);
  const rawItems = Array.isArray(value) ? value : [];

  for (const item of rawItems) {
    if (typeof item !== "string") {
      continue;
    }
    const key = item as OverviewCardKey;
    if (known.has(key) && !order.includes(key)) {
      order.push(key);
    }
  }

  for (const key of defaultOverviewCardOrder) {
    if (!order.includes(key)) {
      order.push(key);
    }
  }

  return order;
}

function buildOverviewCards(order: OverviewCardKey[]): OverviewCardView[] {
  const cards = normalizeOverviewCardOrder(order).map((key) => ({
    ...(overviewCardByKey.get(key) ?? overviewCardDefinitions[0]),
    span: overviewCardByKey.get(key)?.baseSpan ?? 12
  }));
  const result: OverviewCardView[] = [];
  let row: OverviewCardView[] = [];
  let rowSpan = 0;

  const flushRow = () => {
    if (!row.length) {
      return;
    }
    row[row.length - 1].span += 12 - rowSpan;
    result.push(...row);
    row = [];
    rowSpan = 0;
  };

  for (const card of cards) {
    if (rowSpan > 0 && rowSpan + card.baseSpan > 12) {
      flushRow();
    }
    row.push(card);
    rowSpan += card.baseSpan;
    if (rowSpan === 12) {
      flushRow();
    }
  }

  flushRow();
  return result;
}

function overviewCardTitle(key: OverviewCardKey) {
  const titles: Record<OverviewCardKey, string> = {
    status: "运行状态",
    proxy: "HTTP / SOCKS5",
    egress: "公共远端出口",
    speed: "实时网速",
    traffic: "今日流量",
    tun: "TUN",
    policy: "共享策略"
  };
  return titles[key];
}

function overviewCardSubtitle(key: OverviewCardKey) {
  if (key === "status") {
    return state.agent.binary_path ? shortPath(state.agent.binary_path) : "desktop-agent";
  }
  return "";
}

function onOverviewMouseDown(event: MouseEvent, key: OverviewCardKey) {
  if (event.button !== 0) {
    return;
  }
  if (event.target instanceof Element && event.target.closest("input, textarea, select, a, button:not(.overview-drag-handle)")) {
    return;
  }
  event.preventDefault();
  document.body.classList.add("overview-dragging");
  state.draggingOverviewCard = key;
  state.dragOverOverviewCard = null;
  const cardElement =
    event.currentTarget instanceof HTMLElement
      ? event.currentTarget
      : document.querySelector<HTMLElement>(`[data-overview-card="${key}"]`);
  const cardBox = cardElement?.getBoundingClientRect();
  if (cardBox) {
    state.overviewDragGhost = {
      x: cardBox.left,
      y: cardBox.top,
      width: cardBox.width,
      height: cardBox.height,
      offsetX: event.clientX - cardBox.left,
      offsetY: event.clientY - cardBox.top
    };
  }

  window.addEventListener("mousemove", onOverviewMouseMove);
  window.addEventListener("mouseup", onOverviewMouseUp, { once: true });
}

function onOverviewMouseMove(event: MouseEvent) {
  if (!state.draggingOverviewCard) {
    return;
  }

  if (state.overviewDragGhost) {
    state.overviewDragGhost.x = event.clientX - state.overviewDragGhost.offsetX;
    state.overviewDragGhost.y = event.clientY - state.overviewDragGhost.offsetY;
  }

  const targetKey = overviewCardKeyFromPoint(event.clientX, event.clientY);
  if (!targetKey || targetKey === state.draggingOverviewCard) {
    state.dragOverOverviewCard = null;
    return;
  }

  state.dragOverOverviewCard = targetKey;
  moveOverviewCard(
    state.draggingOverviewCard,
    targetKey,
    overviewDropPlacement(event.clientX, event.clientY, targetKey)
  );
}

function onOverviewMouseUp(event: MouseEvent) {
  const source = state.draggingOverviewCard;
  const target = overviewCardKeyFromPoint(event.clientX, event.clientY);
  if (source && target && source !== target) {
    moveOverviewCard(source, target, overviewDropPlacement(event.clientX, event.clientY, target));
  }
  resetOverviewMouseDrag();
}

function overviewCardKeyFromPoint(x: number, y: number) {
  const element = document.elementFromPoint(x, y);
  const card = element instanceof Element ? element.closest<HTMLElement>("[data-overview-card]") : null;
  const key = card?.dataset.overviewCard as OverviewCardKey | undefined;
  return key && overviewCardByKey.has(key) ? key : null;
}

function overviewDropPlacement(x: number, y: number, targetKey: OverviewCardKey): "before" | "after" {
  const target = document.querySelector<HTMLElement>(`[data-overview-card="${targetKey}"]`);
  let placement: "before" | "after" = "before";
  if (target) {
    const box = target.getBoundingClientRect();
    const pastVerticalMidpoint = y > box.top + box.height / 2;
    const pastHorizontalMidpoint = x > box.left + box.width / 2;
    placement = pastVerticalMidpoint || pastHorizontalMidpoint ? "after" : "before";
  }
  return placement;
}

function resetOverviewMouseDrag() {
  window.removeEventListener("mousemove", onOverviewMouseMove);
  window.removeEventListener("mouseup", onOverviewMouseUp);
  document.body.classList.remove("overview-dragging");
  state.draggingOverviewCard = null;
  state.dragOverOverviewCard = null;
  state.overviewDragGhost = null;
}

function moveOverviewCard(source: OverviewCardKey, target: OverviewCardKey, placement: "before" | "after") {
  const next = [...state.overviewCardOrder];
  const sourceIndex = next.indexOf(source);
  if (sourceIndex === -1) {
    return;
  }
  next.splice(sourceIndex, 1);
  const targetIndex = next.indexOf(target);
  if (targetIndex === -1) {
    return;
  }
  next.splice(placement === "after" ? targetIndex + 1 : targetIndex, 0, source);
  state.overviewCardOrder = normalizeOverviewCardOrder(next);
  localStorage.setItem(overviewLayoutKey, JSON.stringify(state.overviewCardOrder));
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
    if (field === "runtime_threads") {
      return Number.isFinite(parsed) ? Math.max(1, parsed) : 1;
    }
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
  const runtimeThreads = normalizeRuntimeThreads(matchNumber(raw, null, "runtime_threads"));
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
    runtime_threads: runtimeThreads,
    effective_runtime_threads: runtimeThreads ?? defaultRuntimeThreads(),
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

function defaultRuntimeThreads() {
  return Math.max(1, Math.floor(window.navigator.hardwareConcurrency || 1));
}

function normalizeRuntimeThreads(value: number | undefined) {
  return value && value > 0 ? value : undefined;
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
  const tunEnabled = currentSummary?.tun_enabled ?? false;
  const tunName = currentSummary?.tun_name ?? "ppaass-tun";
  const tunStatus = tunEnabled ? "TUN 状态需要 Tauri 运行时" : "TUN 未启用";
  const targets = ["Google", "YouTube"];
  const results = targets.flatMap((target) =>
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
  const tunResults = tunEnabled
    ? targets.map((target) => ({
      target,
      protocol: "TUN",
      url: target === "Google" ? "https://www.google.com/generate_204" : "https://www.youtube.com/generate_204",
      proxy_url: `tun://${tunName}`,
      success: false,
      http_code: null,
      duration_ms: 0,
      error: tunStatus
    }))
    : [];

  return {
    listen_addr: listenAddr,
    tun_enabled: tunEnabled,
    tun_name: tunName,
    tun_ready: false,
    tun_status: tunStatus,
    agent_reachable: false,
    generated_at_ms: Date.now(),
    results,
    tun_results: tunResults
  };
}

function startAgentPolling() {
  agentTimer = window.setInterval(() => {
    void refreshAgentState();
  }, 1200);
}

async function refreshAgentState() {
  try {
    state.agent = await invokeOrFallback<AgentState>("get_agent_state", {}, () => state.agent);
  } catch {
    // Keep the last visible agent state if the runtime status read fails.
  }
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

function latestAgentLog() {
  const logs = state.agent.logs ?? [];
  return logs.length > 0 ? logs[logs.length - 1] : null;
}

function tokenizeLogLine(line: string): HighlightedLogLine {
  const level = line.match(/\b(TRACE|DEBUG|INFO|WARN|ERROR)\b/)?.[1]?.toLowerCase() ?? null;
  const pattern =
    /(\d{4}-\d{2}-\d{2}T[^\s]+|\b(?:TRACE|DEBUG|INFO|WARN|ERROR)\b|ThreadId\([^)]+\)|\b[a-zA-Z_][\w:.-]*(?:\.rs)?:\d+:\d+:|\b[a-zA-Z_][\w.-]*=|"(?:[^"\\]|\\.)*"|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\b\d+(?:\.\d+)?\b)/g;
  const tokens: LogToken[] = [];
  let cursor = 0;

  for (const match of line.matchAll(pattern)) {
    const value = match[0];
    const index = match.index ?? 0;
    if (index > cursor) {
      tokens.push({ value: line.slice(cursor, index), kind: "plain" });
    }
    tokens.push({ value, kind: logTokenKind(value) });
    cursor = index + value.length;
  }

  if (cursor < line.length) {
    tokens.push({ value: line.slice(cursor), kind: "plain" });
  }

  return { raw: line, level, tokens: tokens.length ? tokens : [{ value: line, kind: "plain" }] };
}

function logTokenKind(value: string): LogTokenKind {
  if (/^\d{4}-\d{2}-\d{2}T/.test(value)) {
    return "timestamp";
  }
  if (/^(TRACE|DEBUG|INFO|WARN|ERROR)$/.test(value)) {
    return `level-${value.toLowerCase()}` as LogTokenKind;
  }
  if (/^ThreadId\(/.test(value)) {
    return "thread";
  }
  if (/\.rs:\d+:\d+:$/.test(value) || /^[a-zA-Z_][\w:.-]+:$/.test(value)) {
    return "target";
  }
  if (/^[a-zA-Z_][\w.-]*=$/.test(value)) {
    return "field";
  }
  if (/^"/.test(value)) {
    return "string";
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(value)) {
    return "address";
  }
  if (/^\d/.test(value)) {
    return "number";
  }
  return "plain";
}

function tokenizeToml(raw: string): HighlightedTomlLine[] {
  return raw.split("\n").map((line) => ({ raw: line, tokens: tokenizeTomlLine(line) }));
}

function tokenizeTomlLine(line: string): TomlToken[] {
  if (!line) {
    return [{ value: "", kind: "plain" }];
  }

  const commentIndex = findTomlDelimiter(line, "#");
  const code = commentIndex >= 0 ? line.slice(0, commentIndex) : line;
  const comment = commentIndex >= 0 ? line.slice(commentIndex) : "";
  const tokens: TomlToken[] = [];
  const sectionMatch = code.match(/^(\s*)(\[\[?)([^\]]+)(\]\]?)(\s*)$/);

  if (sectionMatch) {
    pushTomlToken(tokens, sectionMatch[1], "plain");
    pushTomlToken(tokens, `${sectionMatch[2]}${sectionMatch[3]}${sectionMatch[4]}`, "section");
    pushTomlToken(tokens, sectionMatch[5], "plain");
    pushTomlToken(tokens, comment, "comment");
    return tokens.length ? tokens : [{ value: line, kind: "plain" }];
  }

  const equalsIndex = findTomlDelimiter(code, "=");
  if (equalsIndex >= 0) {
    tokenizeTomlKey(code.slice(0, equalsIndex), tokens);
    pushTomlToken(tokens, "=", "equals");
    tokenizeTomlValue(code.slice(equalsIndex + 1), tokens);
  } else {
    tokenizeTomlValue(code, tokens);
  }

  pushTomlToken(tokens, comment, "comment");
  return tokens.length ? tokens : [{ value: line, kind: "plain" }];
}

function tokenizeTomlKey(keyPart: string, tokens: TomlToken[]) {
  const keyMatch = keyPart.match(/^(\s*)(.*?)(\s*)$/);
  if (!keyMatch) {
    pushTomlToken(tokens, keyPart, "plain");
    return;
  }
  pushTomlToken(tokens, keyMatch[1], "plain");
  pushTomlToken(tokens, keyMatch[2], "key");
  pushTomlToken(tokens, keyMatch[3], "plain");
}

function tokenizeTomlValue(value: string, tokens: TomlToken[]) {
  let cursor = 0;
  while (cursor < value.length) {
    const rest = value.slice(cursor);
    const whitespace = rest.match(/^\s+/)?.[0];
    if (whitespace) {
      pushTomlToken(tokens, whitespace, "plain");
      cursor += whitespace.length;
      continue;
    }

    const char = value[cursor];
    if (char === "\"" || char === "'") {
      const stringEnd = findTomlStringEnd(value, cursor, char);
      pushTomlToken(tokens, value.slice(cursor, stringEnd), "string");
      cursor = stringEnd;
      continue;
    }

    const word = rest.match(/^(true|false)\b/)?.[0];
    if (word) {
      pushTomlToken(tokens, word, "boolean");
      cursor += word.length;
      continue;
    }

    const date = rest.match(/^\d{4}-\d{2}-\d{2}(?:[Tt ][0-9:.+-Zz]+)?/)?.[0];
    if (date) {
      pushTomlToken(tokens, date, "date");
      cursor += date.length;
      continue;
    }

    const number = rest.match(/^[+-]?(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?)/)?.[0];
    if (number) {
      pushTomlToken(tokens, number, "number");
      cursor += number.length;
      continue;
    }

    if ("[]{}.,=".includes(char)) {
      pushTomlToken(tokens, char, "punctuation");
      cursor += 1;
      continue;
    }

    pushTomlToken(tokens, char, "plain");
    cursor += 1;
  }
}

function findTomlDelimiter(line: string, delimiter: string) {
  let quote: string | null = null;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quote) {
      if (quote === "\"" && char === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (char === quote && !escaped) {
        quote = null;
      }
      escaped = false;
      continue;
    }
    if (char === "\"" || char === "'") {
      quote = char;
      continue;
    }
    if (char === delimiter) {
      return index;
    }
  }
  return -1;
}

function findTomlStringEnd(value: string, start: number, quote: string) {
  let escaped = false;
  for (let index = start + 1; index < value.length; index += 1) {
    const char = value[index];
    if (quote === "\"" && char === "\\" && !escaped) {
      escaped = true;
      continue;
    }
    if (char === quote && !escaped) {
      return index + 1;
    }
    escaped = false;
  }
  return value.length;
}

function pushTomlToken(tokens: TomlToken[], value: string, kind: TomlTokenKind) {
  if (value) {
    tokens.push({ value, kind });
  }
}

function delay(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
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
  return value.replace(/^https?:\/\//, "").replace(/^socks5h:\/\//, "socks5h ").replace(/^tun:\/\//, "tun ");
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
  <main
    class="app-frame"
    @beforeinput.capture="guardIntegerBeforeInput"
    @paste.capture="guardIntegerPaste"
    @input.capture="sanitizeIntegerInput"
  >
    <div class="shell">
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
            :disabled="configLocked || !state.dirty || state.busy"
            @click="saveConfig"
          />
          <Button v-if="running" label="停止" icon="pi pi-stop" severity="danger" :disabled="state.busy" @click="stopAgent" />
          <Button v-else label="启动" icon="pi pi-play" severity="primary" :disabled="state.busy" @click="startAgent" />
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

      <div v-else-if="state.activeTab === 'overview'" class="content-grid overview-grid">
        <Card
          v-for="card in overviewCards"
          :key="card.key"
          :class="[
            'panel',
            'overview-card',
            {
              dragging: state.draggingOverviewCard === card.key,
              'drop-target': state.dragOverOverviewCard === card.key
            }
          ]"
          :style="{ gridColumn: 'span ' + card.span }"
          :data-overview-card="card.key"
          @mousedown="onOverviewMouseDown($event, card.key)"
        >
          <template #title>
            <div class="panel-heading inline overview-card-heading">
              <div class="overview-card-title">
                <h2>{{ overviewCardTitle(card.key) }}</h2>
                <p v-if="overviewCardSubtitle(card.key)">{{ overviewCardSubtitle(card.key) }}</p>
              </div>
              <div class="overview-card-actions">
                <Badge
                  v-if="card.key === 'status'"
                  :value="state.agent.running ? 'Active' : 'Idle'"
                  :severity="state.agent.running ? 'success' : 'secondary'"
                />
                <Tag v-else-if="card.key === 'proxy'" :value="proxyEntryStateLabel" severity="success" />
                <Tag
                  v-else-if="card.key === 'egress'"
                  :value="`${summary.tcp_mode.toUpperCase()} / ${summary.udp_mode.toUpperCase()}`"
                  severity="info"
                />
                <Tag v-else-if="card.key === 'speed'" value="System" severity="info" />
                <span v-else-if="card.key === 'traffic'">{{ state.traffic.baseline?.date ?? localDateKey() }}</span>
                <Tag
                  v-else-if="card.key === 'tun'"
                  :value="summary.tun_enabled ? 'Enabled' : 'Disabled'"
                  :severity="summary.tun_enabled ? 'success' : 'secondary'"
                />
                <Tag v-else-if="card.key === 'policy'" :value="directModeLabel" severity="info" />
                <button
                  type="button"
                  class="overview-drag-handle"
                  aria-label="拖动调整顺序"
                  title="拖动调整顺序"
                >
                  <i class="pi pi-arrows-alt" aria-hidden="true"></i>
                </button>
              </div>
            </div>
          </template>
          <template #content>
            <div v-if="card.key === 'status'" class="status-board">
              <div class="metric-tile">
                <i class="pi pi-sitemap"></i>
                <span>当前转发</span>
                <strong>{{ activeForwardingLabel }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-globe"></i>
                <span>代理入口</span>
                <strong>{{ summary.listen_addr }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-server"></i>
                <span>公共出口</span>
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
            <div v-else-if="card.key === 'proxy'" class="kv-list">
              <div class="kv-row"><span>监听</span><strong>{{ summary.listen_addr }}</strong></div>
              <div class="kv-row"><span>协议</span><strong>HTTP / SOCKS5</strong></div>
              <div class="kv-row"><span>公共出口</span><strong>{{ summary.proxy_addrs.length }} 个节点</strong></div>
            </div>
            <div v-else-if="card.key === 'egress'" class="endpoint-list">
              <div v-for="proxy in summary.proxy_addrs" :key="proxy" class="endpoint-row">
                <i class="pi pi-server"></i>
                <span>{{ proxy }}</span>
              </div>
              <div v-if="!summary.proxy_addrs.length" class="endpoint-row muted">
                <i class="pi pi-server"></i>
                <span>未配置</span>
              </div>
            </div>
            <div v-else-if="card.key === 'speed'" class="speed-gauges">
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
            <div v-else-if="card.key === 'traffic'" class="hourly-chart">
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
            <div v-else-if="card.key === 'tun'" class="kv-list">
              <div class="kv-row"><span>设备</span><strong>{{ summary.tun_name }}</strong></div>
              <div class="kv-row"><span>地址</span><strong>{{ summary.tun_ipv4 }}</strong></div>
              <div class="kv-row"><span>MTU</span><strong>{{ summary.tun_mtu }}</strong></div>
              <div class="kv-row"><span>DNS</span><strong>{{ summary.tun_proxy_dns ? "Proxy" : "System" }}</strong></div>
            </div>
            <div v-else-if="card.key === 'policy'" class="kv-list">
              <div class="kv-row"><span>配置段</span><strong>direct_access</strong></div>
              <div class="kv-row"><span>服务对象</span><strong>代理入口与 TUN 模式</strong></div>
              <div class="kv-row"><span>规则</span><strong>{{ summary.direct_rules.length }} 条</strong></div>
            </div>
          </template>
        </Card>

        <div
          v-if="state.draggingOverviewCard && state.overviewDragGhost"
          class="overview-drag-ghost"
          :style="{
            left: `${state.overviewDragGhost.x}px`,
            top: `${state.overviewDragGhost.y}px`,
            width: `${state.overviewDragGhost.width}px`,
            height: `${state.overviewDragGhost.height}px`
          }"
        >
          <div class="overview-drag-ghost-heading">
            <strong>{{ overviewCardTitle(state.draggingOverviewCard) }}</strong>
            <i class="pi pi-arrows-alt" aria-hidden="true"></i>
          </div>
          <div class="overview-drag-ghost-lines" aria-hidden="true">
            <span></span>
            <span></span>
            <span></span>
          </div>
        </div>
      </div>

      <div v-else-if="state.activeTab === 'forwarding'" class="content-grid">
        <section class="card-group span-12">
          <div class="card-group-heading">
            <div>
              <h2>HTTP / SOCKS5 代理</h2>
              <p>{{ summary.listen_addr }}</p>
            </div>
            <Tag :value="proxyEntryStateLabel" severity="success" />
          </div>
          <div class="card-group-grid">
            <Card class="panel">
              <template #title><h2>代理入口</h2></template>
              <template #content>
                <div class="method-summary">
                  <div class="method-fact"><span>入站协议</span><strong>HTTP / SOCKS5</strong></div>
                  <div class="method-fact"><span>监听状态</span><strong>{{ proxyEntryStateLabel }}</strong></div>
                </div>
                <label class="field">
                  <span><i class="pi pi-wifi"></i>监听地址</span>
                  <InputText :model-value="summary.listen_addr" :disabled="configLocked" @update:model-value="setField('listen_addr', $event)" />
                </label>
              </template>
            </Card>

            <Card class="panel">
              <template #title>
                <div class="panel-heading inline">
                  <h2>代理状态</h2>
                  <Tag :value="activeForwardingLabel" severity="info" />
                </div>
              </template>
              <template #content>
                <div class="kv-list">
                  <div class="kv-row"><span>监听</span><strong>{{ summary.listen_addr }}</strong></div>
                  <div class="kv-row"><span>协议</span><strong>HTTP / SOCKS5</strong></div>
                  <div class="kv-row"><span>状态</span><strong>{{ proxyEntryStateLabel }}</strong></div>
                  <div class="kv-row"><span>公共出口</span><strong>{{ summary.proxy_addrs.length }} 个节点</strong></div>
                </div>
              </template>
            </Card>
          </div>
        </section>

        <section class="card-group span-12">
          <div class="card-group-heading">
            <div>
              <h2>TUN 模式</h2>
              <p>{{ summary.tun_name }} · {{ summary.tun_ipv4 }}</p>
            </div>
            <ToggleSwitch :model-value="summary.tun_enabled" :disabled="configLocked" @update:model-value="setField('tun_enabled', $event)" />
          </div>
          <div class="card-group-grid">
            <Card class="panel">
              <template #title><h2>TUN 设备</h2></template>
              <template #content>
                <div class="method-summary">
                  <div class="method-fact"><span>转发方式</span><strong>虚拟网卡</strong></div>
                  <div class="method-fact"><span>当前状态</span><strong>{{ tunModeLabel }}</strong></div>
                </div>
                <label class="field">
                  <span><i class="pi pi-desktop"></i>名称</span>
                  <InputText :model-value="summary.tun_name" :disabled="configLocked" @update:model-value="setField('tun_name', $event)" />
                </label>
              </template>
            </Card>

            <Card class="panel">
              <template #title><h2>TUN 专属策略</h2></template>
              <template #content>
                <div class="toggle-list">
                  <div class="switch-row">
                    <span>Proxy DNS</span>
                    <ToggleSwitch :model-value="summary.tun_proxy_dns" :disabled="configLocked" @update:model-value="setField('tun_proxy_dns', $event)" />
                  </div>
                  <div class="switch-row">
                    <span>阻断 QUIC</span>
                    <ToggleSwitch :model-value="summary.tun_block_quic" :disabled="configLocked" @update:model-value="setField('tun_block_quic', $event)" />
                  </div>
                </div>
              </template>
            </Card>
          </div>
        </section>
      </div>

      <div v-else-if="state.activeTab === 'egress'" class="content-grid">
        <Card class="panel span-6">
          <template #title>
            <div class="panel-heading inline">
              <h2>公共远端出口</h2>
              <span>{{ summary.proxy_addrs.length }} 个节点</span>
            </div>
          </template>
          <template #content>
            <label class="field">
              <span><i class="pi pi-server"></i>节点</span>
              <Textarea
                :model-value="summary.proxy_addrs.join('\n')"
                :disabled="configLocked"
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
                  :allow-empty="false"
                  :disabled="configLocked"
                  :use-grouping="false"
                  @update:model-value="setField('connect_timeout_secs', $event)"
                />
              </label>
              <label class="field">
                <span><i class="pi pi-box"></i>压缩</span>
                <Select :model-value="summary.compression_mode" :options="compressionOptions" :disabled="configLocked" @update:model-value="setField('compression_mode', $event)" />
              </label>
            </div>
          </template>
        </Card>

        <Card class="panel span-6">
          <template #title><h2>身份凭据</h2></template>
          <template #content>
            <label class="field">
              <span><i class="pi pi-user"></i>用户</span>
              <InputText :model-value="summary.username" :disabled="configLocked" @update:model-value="setField('username', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-key"></i>私钥</span>
              <InputText :model-value="summary.private_key_path" :disabled="configLocked" @update:model-value="setField('private_key_path', $event)" />
            </label>
          </template>
        </Card>

        <Card class="panel span-12">
          <template #title><h2>出口通道</h2></template>
          <template #content>
            <div class="field-pair">
              <label class="field">
                <span><i class="pi pi-clone"></i>TCP</span>
                <InputNumber :model-value="summary.tcp_pool_size" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="setField('tcp_pool_size', $event)" />
              </label>
              <label class="field">
                <span><i class="pi pi-wave-pulse"></i>UDP</span>
                <InputNumber :model-value="summary.udp_pool_size" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="setField('udp_pool_size', $event)" />
              </label>
            </div>
            <div class="field-pair">
              <label class="field">
                <span><i class="pi pi-sliders-h"></i>TCP 传输</span>
                <SelectButton :model-value="summary.tcp_mode" :options="transportModeOptions" :allow-empty="false" :disabled="configLocked" @update:model-value="setField('tcp_mode', $event)" />
              </label>
              <label class="field">
                <span><i class="pi pi-sliders-h"></i>UDP 传输</span>
                <SelectButton :model-value="summary.udp_mode" :options="transportModeOptions" :allow-empty="false" :disabled="configLocked" @update:model-value="setField('udp_mode', $event)" />
              </label>
            </div>
            <div class="field-pair">
              <label class="field">
                <span><i class="pi pi-share-alt"></i>TCP Yamux</span>
                <InputNumber :model-value="summary.tcp_yamux_sessions" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="setField('tcp_yamux_sessions', $event)" />
              </label>
              <label class="field">
                <span><i class="pi pi-share-alt"></i>UDP Yamux</span>
                <InputNumber :model-value="summary.udp_yamux_sessions" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="setField('udp_yamux_sessions', $event)" />
              </label>
            </div>
          </template>
        </Card>
      </div>

      <div v-else-if="state.activeTab === 'routing'" class="content-grid">
        <section class="card-group span-12">
          <div class="card-group-heading">
            <div>
              <h2>系统运行参数</h2>
              <p>{{ summary.log_level }} · {{ summary.effective_runtime_threads }} 线程</p>
            </div>
            <Tag value="全局" severity="secondary" />
          </div>
          <div class="content-grid">
            <Card class="panel span-12">
              <template #title><h2>运行参数</h2></template>
              <template #content>
                <div class="field-pair">
                  <label class="field">
                    <span><i class="pi pi-chart-line"></i>日志</span>
                    <Select :model-value="summary.log_level" :options="logLevelOptions" :disabled="configLocked" @update:model-value="setField('log_level', $event)" />
                  </label>
                  <label class="field">
                    <span><i class="pi pi-microchip"></i>线程</span>
                    <InputNumber :model-value="summary.effective_runtime_threads" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="setField('runtime_threads', $event)" />
                  </label>
                </div>
              </template>
            </Card>
          </div>
        </section>

        <section class="card-group span-12">
          <div class="card-group-heading">
            <div>
              <h2>流量策略</h2>
              <p>direct_access</p>
            </div>
            <Tag :value="directModeLabel" severity="info" />
          </div>
          <div class="content-grid">
            <Card class="panel span-12">
              <template #title>
                <div class="panel-heading inline">
                  <h2>共享直连策略</h2>
                  <Tag :value="directModeLabel" severity="info" />
                </div>
              </template>
              <template #content>
                <div class="policy-grid">
                  <label class="field direct-mode-field">
                    <span><i class="pi pi-directions"></i>模式</span>
                    <SelectButton
                      :model-value="summary.direct_mode"
                      :options="directModeOptions"
                      option-label="label"
                      option-value="value"
                      :allow-empty="false"
                      :disabled="configLocked"
                      @update:model-value="setField('direct_mode', $event)"
                    />
                  </label>
                  <div class="policy-facts">
                    <div class="policy-fact"><span>当前转发</span><strong>{{ activeForwardingLabel }}</strong></div>
                    <div class="policy-fact"><span>规则数量</span><strong>{{ summary.direct_rules.length }} 条</strong></div>
                    <div class="policy-fact"><span>配置段</span><strong>direct_access</strong></div>
                  </div>
                </div>
                <div class="forwarding-methods">
                  <div class="forwarding-method">
                    <i class="pi pi-server"></i>
                    <div>
                      <span>HTTP / SOCKS5 代理</span>
                      <strong>{{ summary.listen_addr }}</strong>
                    </div>
                  </div>
                  <div class="forwarding-method">
                    <i class="pi pi-compass"></i>
                    <div>
                      <span>TUN 模式</span>
                      <strong>{{ tunModeLabel }} · {{ summary.tun_name }}</strong>
                    </div>
                  </div>
                </div>
              </template>
            </Card>

            <Card class="panel span-5">
              <template #title><h2>快捷预设</h2></template>
              <template #content>
                <div class="preset-list">
                  <Button
                    v-for="preset in directRulePresets"
                    :key="preset.label"
                    :icon="preset.icon"
                    :label="preset.label"
                    severity="secondary"
                    outlined
                    :disabled="configLocked"
                    @click="addDirectRules(preset.rules)"
                  />
                </div>
              </template>
            </Card>

            <Card class="panel span-7">
              <template #title>
                <div class="panel-heading inline">
                  <h2>规则管理</h2>
                  <Tag :value="`${summary.direct_rules.length} 条`" severity="info" />
                </div>
              </template>
              <template #content>
                <div class="rule-manager">
                  <section class="rule-create">
                    <div class="section-heading">
                      <span>添加规则</span>
                      <strong>{{ directModeLabel }}</strong>
                    </div>
                    <div class="rule-compose">
                      <label class="field rule-input-field">
                        <span><i class="pi pi-plus-circle"></i>规则值</span>
                        <InputText v-model="state.ruleDraft" placeholder="域名 / 通配符 / CIDR" :disabled="configLocked" @keydown.enter.prevent="addDraftRules" />
                      </label>
                      <Button icon="pi pi-plus" label="添加" severity="primary" :disabled="configLocked" @click="addDraftRules" />
                    </div>
                  </section>

                  <section class="rule-inventory">
                    <div class="section-heading">
                      <span>当前规则</span>
                      <strong>{{ directRuleGroups.length }} 组</strong>
                    </div>
                    <div v-if="!summary.direct_rules.length" class="empty-rules">未配置</div>
                    <div v-else class="rule-group-list">
                      <section v-for="group in directRuleGroups" :key="group.key" class="rule-group">
                        <div class="rule-group-heading">
                          <div>
                            <i :class="group.icon"></i>
                            <span>{{ group.label }}</span>
                          </div>
                          <strong>{{ group.items.length }}</strong>
                        </div>
                        <div class="rule-chip-list grouped">
                          <div v-for="item in group.items" :key="`${group.key}-${item.rule}-${item.index}`" class="rule-chip">
                            <span :title="item.rule">{{ item.rule }}</span>
                            <button type="button" class="rule-chip-remove" aria-label="删除" :disabled="configLocked" @click="removeDirectRule(item.index)">
                              <span class="rule-chip-remove-mark" aria-hidden="true"></span>
                            </button>
                          </div>
                        </div>
                      </section>
                    </div>
                  </section>
                </div>
              </template>
            </Card>
          </div>
        </section>
      </div>

      <div v-else-if="state.activeTab === 'diagnostics'" class="content-grid">
        <Card class="panel span-5">
          <template #title>
            <div class="panel-heading inline">
              <div>
                <h2>链路诊断</h2>
                <p>{{ summary.tun_enabled ? `${summary.tun_name} · TUN` : summary.listen_addr }}</p>
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
                <strong>
                  {{
                    state.diagnostics
                      ? state.diagnostics.tun_enabled
                        ? state.diagnostics.agent_reachable
                          ? "Proxy On"
                          : "Paused"
                        : state.diagnostics.agent_reachable
                          ? "Reachable"
                          : "Offline"
                      : "Pending"
                  }}
                </strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-globe"></i>
                <span>站点</span>
                <strong>Google / YouTube</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-compass"></i>
                <span>TUN</span>
                <strong>{{ tunDiagnosticsLabel }}</strong>
              </div>
              <div class="metric-tile">
                <i class="pi pi-shield"></i>
                <span>结果</span>
                <strong>{{ state.diagnostics ? `${diagnosticsPassed}/${diagnosticsTotal}` : "—" }}</strong>
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
              <div v-if="state.diagnosticsRunning" class="diagnostic-row muted">
                <div><strong>后台测试中</strong><span>Google / YouTube · HTTP / SOCKS5 / TUN</span></div>
                <span>等待结果</span>
              </div>
              <div v-if="!state.diagnostics && !state.diagnosticsRunning" class="diagnostic-row muted">
                <div><strong>Google</strong><span>HTTP / SOCKS5</span></div>
                <span>未测试</span>
              </div>
              <div v-if="!state.diagnostics && !state.diagnosticsRunning" class="diagnostic-row muted">
                <div><strong>YouTube</strong><span>HTTP / SOCKS5</span></div>
                <span>未测试</span>
              </div>
              <div v-if="!state.diagnostics && !state.diagnosticsRunning" class="diagnostic-row muted">
                <div><strong>TUN</strong><span>{{ summary.tun_enabled ? summary.tun_name : "未启用" }}</span></div>
                <span>{{ summary.tun_enabled ? "未测试" : "跳过" }}</span>
              </div>
              <div v-if="state.diagnostics && !state.diagnostics.tun_enabled" class="diagnostic-row muted">
                <div><strong>TUN</strong><span>未启用</span></div>
                <span>跳过</span>
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
              <div v-for="item in state.diagnostics?.tun_results ?? []" :key="`${item.target}-${item.protocol}`" :class="['diagnostic-row', item.success ? 'ok' : 'fail']">
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
            <Button icon="pi pi-refresh" label="刷新" severity="secondary" outlined size="small" @click="refreshAgentState" />
          </div>
        </template>
        <template #content>
          <div class="log-view">
            <div v-if="!state.agent.logs.length" class="log-empty">暂无日志</div>
            <template v-else>
              <div
                v-for="(entry, index) in highlightedLogs"
                :key="index"
                :class="['log-line', entry.level ? `log-line-${entry.level}` : '']"
                :title="entry.raw"
              >
                <span
                  v-for="(token, tokenIndex) in entry.tokens"
                  :key="tokenIndex"
                  :class="['log-token', `log-${token.kind}`]"
                >{{ token.value }}</span>
              </div>
            </template>
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
          <div class="toml-editor-shell">
            <pre ref="tomlHighlightRef" class="toml-highlight" aria-hidden="true"><code><span
              v-for="(line, lineIndex) in highlightedToml"
              :key="lineIndex"
              class="toml-line"
            ><span
              v-for="(token, tokenIndex) in line.tokens"
              :key="tokenIndex"
              :class="['toml-token', `toml-${token.kind}`]"
            >{{ token.value }}</span>{{ lineIndex < highlightedToml.length - 1 ? "\n" : "" }}</span></code></pre>
            <Textarea
              class="toml-editor"
              :model-value="state.config?.raw ?? ''"
              :readonly="configLocked"
              spellcheck="false"
              wrap="off"
              @scroll="syncTomlHighlightScroll"
              @update:model-value="setRawConfig(String($event))"
            />
          </div>
        </template>
      </Card>
      </section>
    </div>

    <Transition name="toast">
      <div v-if="state.toast" :class="['toast', state.toast.kind]">{{ state.toast.message }}</div>
    </Transition>
  </main>
</template>
