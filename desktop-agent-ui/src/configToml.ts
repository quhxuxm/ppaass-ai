import type { AgentConfigSummary } from "./types";
import fallbackRawConfigSource from "../../config/local/agent.toml?raw";

export const fallbackRawConfig = fallbackRawConfigSource;

const defaultFieldValues = {
  listen_addr: "0.0.0.0:10080",
  proxy_addrs: ["127.0.0.1:8080"],
  username: "user1",
  private_key_path: "keys/user1.pem",
  tcp_pool_size: 10,
  udp_pool_size: 5,
  connect_timeout_secs: 30,
  tcp_relay_buffer_size_kb: 256,
  compression_mode: "none",
  log_level: "info",
  log_dir: "",
  log_file: "desktop-agent.log",
  tcp_mode: "auto",
  udp_mode: "auto",
  // TCP Yamux 保持保守默认值。HLS/TUN 场景下盲目增大外层连接数会增加
  // agent<->proxy 侧竞争，可能让单个视频分片读得更碎。
  tcp_yamux_sessions: 5,
  udp_yamux_sessions: 5,
  tcp_yamux_max_streams_per_session: 256,
  udp_yamux_max_streams_per_session: 256,
  tcp_yamux_open_stream_timeout_secs: 10,
  udp_yamux_open_stream_timeout_secs: 10,
  tcp_yamux_keepalive_interval_secs: 30,
  udp_yamux_keepalive_interval_secs: 30,
  tcp_yamux_connection_write_timeout_secs: 10,
  udp_yamux_connection_write_timeout_secs: 10,
  tcp_yamux_stream_window_size_kb: 8192,
  udp_yamux_stream_window_size_kb: 8192,
  tun_enabled: false,
  tun_name: "ppaass-tun",
  tun_ipv4: "10.10.10.1/24",
  tun_mtu: 1500,
  tun_proxy_dns: false,
  tun_block_quic: false,
  tun_quic_policy: "allow",
  direct_mode: "proxy_all",
  direct_rules: []
} satisfies Partial<Record<keyof AgentConfigSummary, unknown>>;

export function coerceField(field: keyof AgentConfigSummary, value: unknown): unknown {
  if (isBlankInput(value)) {
    return defaultValueForField(field);
  }
  if (typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return value;
  }
  if (field === "tun_quic_policy") {
    return normalizeQuicPolicy(String(value ?? ""));
  }
  if (
    [
      "tcp_pool_size",
      "udp_pool_size",
      "connect_timeout_secs",
      "tcp_relay_buffer_size_kb",
      "tcp_yamux_sessions",
      "udp_yamux_sessions",
      "tcp_yamux_max_streams_per_session",
      "udp_yamux_max_streams_per_session",
      "tcp_yamux_open_stream_timeout_secs",
      "udp_yamux_open_stream_timeout_secs",
      "tcp_yamux_keepalive_interval_secs",
      "udp_yamux_keepalive_interval_secs",
      "tcp_yamux_connection_write_timeout_secs",
      "udp_yamux_connection_write_timeout_secs",
      "tcp_yamux_stream_window_size_kb",
      "udp_yamux_stream_window_size_kb",
      "tun_mtu",
      "runtime_threads"
    ].includes(field)
  ) {
    const parsed = Number.parseInt(String(value), 10);
    if (field === "runtime_threads") {
      return Number.isFinite(parsed) ? Math.max(1, parsed) : 1;
    }
    const minimum = minimumNumberForField(field);
    return Number.isFinite(parsed) ? Math.max(minimum, parsed) : minimum;
  }
  if (field === "proxy_addrs" || field === "direct_rules") {
    return String(value)
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return String(value);
}

export function applyFieldToToml(raw: string, field: keyof AgentConfigSummary, value: unknown) {
  const mapping: Record<string, { section: string | null; key: string; kind: "string" | "number" | "bool" | "array" }> = {
    listen_addr: { section: null, key: "listen_addr", kind: "string" },
    proxy_addrs: { section: null, key: "proxy_addrs", kind: "array" },
    username: { section: null, key: "username", kind: "string" },
    private_key_path: { section: null, key: "private_key_path", kind: "string" },
    tcp_pool_size: { section: null, key: "tcp_pool_size", kind: "number" },
    udp_pool_size: { section: null, key: "udp_pool_size", kind: "number" },
    connect_timeout_secs: { section: null, key: "connect_timeout_secs", kind: "number" },
    tcp_relay_buffer_size_kb: { section: null, key: "tcp_relay_buffer_size_kb", kind: "number" },
    compression_mode: { section: null, key: "compression_mode", kind: "string" },
    log_level: { section: null, key: "log_level", kind: "string" },
    runtime_threads: { section: null, key: "runtime_threads", kind: "number" },
    tcp_mode: { section: "transport", key: "tcp_mode", kind: "string" },
    udp_mode: { section: "transport", key: "udp_mode", kind: "string" },
    tcp_yamux_sessions: { section: "yamux.tcp", key: "sessions", kind: "number" },
    udp_yamux_sessions: { section: "yamux.udp", key: "sessions", kind: "number" },
    tcp_yamux_max_streams_per_session: { section: "yamux.tcp", key: "max_streams_per_session", kind: "number" },
    udp_yamux_max_streams_per_session: { section: "yamux.udp", key: "max_streams_per_session", kind: "number" },
    tcp_yamux_open_stream_timeout_secs: { section: "yamux.tcp", key: "open_stream_timeout_secs", kind: "number" },
    udp_yamux_open_stream_timeout_secs: { section: "yamux.udp", key: "open_stream_timeout_secs", kind: "number" },
    tcp_yamux_keepalive_interval_secs: { section: "yamux.tcp", key: "keepalive_interval_secs", kind: "number" },
    udp_yamux_keepalive_interval_secs: { section: "yamux.udp", key: "keepalive_interval_secs", kind: "number" },
    tcp_yamux_connection_write_timeout_secs: { section: "yamux.tcp", key: "connection_write_timeout_secs", kind: "number" },
    udp_yamux_connection_write_timeout_secs: { section: "yamux.udp", key: "connection_write_timeout_secs", kind: "number" },
    tcp_yamux_stream_window_size_kb: { section: "yamux.tcp", key: "stream_window_size_kb", kind: "number" },
    udp_yamux_stream_window_size_kb: { section: "yamux.udp", key: "stream_window_size_kb", kind: "number" },
    tun_enabled: { section: "tun", key: "enabled", kind: "bool" },
    tun_name: { section: "tun", key: "name", kind: "string" },
    tun_ipv4: { section: "tun", key: "ipv4", kind: "string" },
    tun_mtu: { section: "tun", key: "mtu", kind: "number" },
    tun_proxy_dns: { section: "tun", key: "proxy_dns", kind: "bool" },
    tun_block_quic: { section: "tun", key: "block_quic", kind: "bool" },
    tun_quic_policy: { section: "tun", key: "quic_policy", kind: "string" },
    direct_mode: { section: "direct_access", key: "mode", kind: "string" },
    direct_rules: { section: "direct_access", key: "rules", kind: "array" },
    log_dir: { section: null, key: "log_dir", kind: "string" },
    log_file: { section: null, key: "log_file", kind: "string" }
  };

  const target = mapping[field];
  if (!target) {
    return raw;
  }

  if (field === "tun_quic_policy") {
    const policy = normalizeQuicPolicy(String(value ?? ""));
    const withPolicy = upsertTomlValue(raw, "tun", "quic_policy", formatTomlValue(policy, "string", field));
    // 同步旧版 `block_quic`，避免旧 agent 读取同一份配置时意外放行代理路径 QUIC。
    return upsertTomlValue(withPolicy, "tun", "block_quic", policy === "allow" ? "false" : "true");
  }

  return upsertTomlValue(raw, target.section, target.key, formatTomlValue(value, target.kind, field));
}

export function summarizeRaw(raw: string): AgentConfigSummary {
  const runtimeThreads = normalizeRuntimeThreads(matchNumber(raw, null, "runtime_threads"));
  const legacyTunBlockQuic = matchBool(raw, "tun", "block_quic") ?? defaultValueForField<boolean>("tun_block_quic");
  const tunQuicPolicy = normalizeQuicPolicy(
    matchString(raw, "tun", "quic_policy") ?? (legacyTunBlockQuic ? "direct_if_rule_match" : "allow")
  );
  return {
    listen_addr: stringOrDefault(matchString(raw, null, "listen_addr"), "listen_addr"),
    proxy_addrs: arrayOrDefault(matchStringArray(raw, "proxy_addrs"), "proxy_addrs"),
    username: stringOrDefault(matchString(raw, null, "username"), "username"),
    private_key_path: stringOrDefault(matchString(raw, null, "private_key_path"), "private_key_path"),
    tcp_pool_size: matchNumber(raw, null, "tcp_pool_size") ?? defaultValueForField<number>("tcp_pool_size"),
    udp_pool_size: matchNumber(raw, null, "udp_pool_size") ?? defaultValueForField<number>("udp_pool_size"),
    connect_timeout_secs: matchNumber(raw, null, "connect_timeout_secs") ?? defaultValueForField<number>("connect_timeout_secs"),
    tcp_relay_buffer_size_kb:
      matchNumber(raw, null, "tcp_relay_buffer_size_kb") ?? defaultValueForField<number>("tcp_relay_buffer_size_kb"),
    compression_mode: stringOrDefault(matchString(raw, null, "compression_mode"), "compression_mode"),
    log_level: stringOrDefault(matchString(raw, null, "log_level"), "log_level"),
    log_dir: matchString(raw, null, "log_dir"),
    log_file: stringOrDefault(matchString(raw, null, "log_file"), "log_file"),
    runtime_threads: runtimeThreads,
    effective_runtime_threads: runtimeThreads ?? defaultRuntimeThreads(),
    tcp_mode: stringOrDefault(matchString(raw, "transport", "tcp_mode"), "tcp_mode"),
    udp_mode: stringOrDefault(matchString(raw, "transport", "udp_mode"), "udp_mode"),
    tcp_yamux_sessions: matchNumber(raw, "yamux.tcp", "sessions") ?? defaultValueForField<number>("tcp_yamux_sessions"),
    udp_yamux_sessions: matchNumber(raw, "yamux.udp", "sessions") ?? defaultValueForField<number>("udp_yamux_sessions"),
    tcp_yamux_max_streams_per_session: matchNumber(raw, "yamux.tcp", "max_streams_per_session") ?? defaultValueForField<number>("tcp_yamux_max_streams_per_session"),
    udp_yamux_max_streams_per_session: matchNumber(raw, "yamux.udp", "max_streams_per_session") ?? defaultValueForField<number>("udp_yamux_max_streams_per_session"),
    tcp_yamux_open_stream_timeout_secs: matchNumber(raw, "yamux.tcp", "open_stream_timeout_secs") ?? defaultValueForField<number>("tcp_yamux_open_stream_timeout_secs"),
    udp_yamux_open_stream_timeout_secs: matchNumber(raw, "yamux.udp", "open_stream_timeout_secs") ?? defaultValueForField<number>("udp_yamux_open_stream_timeout_secs"),
    tcp_yamux_keepalive_interval_secs: matchNumber(raw, "yamux.tcp", "keepalive_interval_secs") ?? defaultValueForField<number>("tcp_yamux_keepalive_interval_secs"),
    udp_yamux_keepalive_interval_secs: matchNumber(raw, "yamux.udp", "keepalive_interval_secs") ?? defaultValueForField<number>("udp_yamux_keepalive_interval_secs"),
    tcp_yamux_connection_write_timeout_secs: matchNumber(raw, "yamux.tcp", "connection_write_timeout_secs") ?? defaultValueForField<number>("tcp_yamux_connection_write_timeout_secs"),
    udp_yamux_connection_write_timeout_secs: matchNumber(raw, "yamux.udp", "connection_write_timeout_secs") ?? defaultValueForField<number>("udp_yamux_connection_write_timeout_secs"),
    tcp_yamux_stream_window_size_kb: matchNumber(raw, "yamux.tcp", "stream_window_size_kb") ?? defaultValueForField<number>("tcp_yamux_stream_window_size_kb"),
    udp_yamux_stream_window_size_kb: matchNumber(raw, "yamux.udp", "stream_window_size_kb") ?? defaultValueForField<number>("udp_yamux_stream_window_size_kb"),
    tun_enabled: matchBool(raw, "tun", "enabled") ?? defaultValueForField<boolean>("tun_enabled"),
    tun_name: stringOrDefault(matchString(raw, "tun", "name"), "tun_name"),
    tun_ipv4: stringOrDefault(matchString(raw, "tun", "ipv4"), "tun_ipv4"),
    tun_mtu: matchNumber(raw, "tun", "mtu") ?? defaultValueForField<number>("tun_mtu"),
    tun_proxy_dns: matchBool(raw, "tun", "proxy_dns") ?? defaultValueForField<boolean>("tun_proxy_dns"),
    tun_block_quic: tunQuicPolicy !== "allow",
    tun_quic_policy: tunQuicPolicy,
    direct_mode: stringOrDefault(matchString(raw, "direct_access", "mode"), "direct_mode"),
    direct_rules: matchStringArray(raw, "rules", "direct_access")
  };
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

function formatTomlValue(value: unknown, kind: "string" | "number" | "bool" | "array", field?: keyof AgentConfigSummary) {
  if (kind === "string") {
    return JSON.stringify(String(value ?? ""));
  }
  if (kind === "number") {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? String(numeric) : String(field ? defaultValueForField<number>(field) : 0);
  }
  if (kind === "bool") {
    return value ? "true" : "false";
  }
  const items = Array.isArray(value) ? value : [];
  return `[${items.map((item) => JSON.stringify(String(item))).join(", ")}]`;
}

function defaultRuntimeThreads() {
  return Math.max(1, Math.floor(globalThis.navigator?.hardwareConcurrency || 1));
}

function normalizeRuntimeThreads(value: number | undefined) {
  return value && value > 0 ? value : undefined;
}

function isBlankInput(value: unknown) {
  return value === null || value === undefined || (typeof value === "string" && value.trim() === "");
}

function defaultValueForField<T = unknown>(field: keyof AgentConfigSummary): T {
  if (field === "runtime_threads" || field === "effective_runtime_threads") {
    return defaultRuntimeThreads() as T;
  }
  const value = defaultFieldValues[field];
  return (Array.isArray(value) ? [...value] : value) as T;
}

function stringOrDefault(value: string | undefined, field: keyof AgentConfigSummary) {
  return value && value.trim() ? value : defaultValueForField<string>(field);
}

function arrayOrDefault(value: string[], field: keyof AgentConfigSummary) {
  return value.length > 0 ? value : defaultValueForField<string[]>(field);
}

function minimumNumberForField(field: keyof AgentConfigSummary) {
  if (
    field === "tcp_yamux_sessions" ||
    field === "udp_yamux_sessions" ||
    field === "tcp_yamux_max_streams_per_session" ||
    field === "udp_yamux_max_streams_per_session" ||
    field === "tcp_yamux_open_stream_timeout_secs" ||
    field === "udp_yamux_open_stream_timeout_secs" ||
    field === "tcp_yamux_connection_write_timeout_secs" ||
    field === "udp_yamux_connection_write_timeout_secs"
  ) {
    return 1;
  }
  if (field === "tcp_yamux_stream_window_size_kb" || field === "udp_yamux_stream_window_size_kb") {
    return 256;
  }
  return 0;
}

function normalizeQuicPolicy(value: string) {
  return ["allow", "direct_if_rule_match", "block"].includes(value) ? value : defaultValueForField<string>("tun_quic_policy");
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

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
