import type { AgentConfigSummary, AgentTransportMode } from "./types";
import fallbackRawConfigSource from "../../config/local/agent.toml?raw";

export const fallbackRawConfig = fallbackRawConfigSource;

const defaultFieldValues = {
  listen_addr: "0.0.0.0:10080",
  proxy_addrs: ["127.0.0.1:8080"],
  username: "user1",
  private_key_path: "keys/user1.pem",
  transport_mode: "udp",
  udp_session_pool_size: 4,
  connect_timeout_secs: 30,
  compression_mode: "none",
  log_level: "info",
  log_dir: "",
  log_file: "desktop-agent.log",
  udp_yamux_sessions: 5,
  udp_yamux_max_streams_per_session: 32,
  udp_yamux_open_stream_timeout_secs: 10,
  udp_yamux_keepalive_interval_secs: 30,
  udp_yamux_connection_write_timeout_secs: 10,
  udp_yamux_stream_window_size_kb: 8192,
  tun_enabled: false,
  tun_name: "ppaass-tun",
  tun_ipv4: "10.10.10.1/24",
  tun_mtu: 1500,
  tun_proxy_udp: true,
  tun_proxy_dns: false,
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
  if (field === "transport_mode") {
    return normalizeTransportMode(String(value ?? ""));
  }
  if (
    [
      "connect_timeout_secs",
      "udp_session_pool_size",
      "udp_yamux_sessions",
      "udp_yamux_max_streams_per_session",
      "udp_yamux_open_stream_timeout_secs",
      "udp_yamux_keepalive_interval_secs",
      "udp_yamux_connection_write_timeout_secs",
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
    const normalized = Number.isFinite(parsed) ? Math.max(minimum, parsed) : minimum;
    return field === "udp_session_pool_size" ? Math.min(8, normalized) : normalized;
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
    transport_mode: { section: null, key: "transport_mode", kind: "string" },
    udp_session_pool_size: { section: null, key: "udp_session_pool_size", kind: "number" },
    connect_timeout_secs: { section: null, key: "connect_timeout_secs", kind: "number" },
    compression_mode: { section: null, key: "compression_mode", kind: "string" },
    log_level: { section: null, key: "log_level", kind: "string" },
    runtime_threads: { section: null, key: "runtime_threads", kind: "number" },
    udp_yamux_sessions: { section: "yamux.udp", key: "sessions", kind: "number" },
    udp_yamux_max_streams_per_session: { section: "yamux.udp", key: "max_streams_per_session", kind: "number" },
    udp_yamux_open_stream_timeout_secs: { section: "yamux.udp", key: "open_stream_timeout_secs", kind: "number" },
    udp_yamux_keepalive_interval_secs: { section: "yamux.udp", key: "keepalive_interval_secs", kind: "number" },
    udp_yamux_connection_write_timeout_secs: { section: "yamux.udp", key: "connection_write_timeout_secs", kind: "number" },
    udp_yamux_stream_window_size_kb: { section: "yamux.udp", key: "stream_window_size_kb", kind: "number" },
    tun_enabled: { section: "tun", key: "enabled", kind: "bool" },
    tun_name: { section: "tun", key: "name", kind: "string" },
    tun_ipv4: { section: "tun", key: "ipv4", kind: "string" },
    tun_mtu: { section: "tun", key: "mtu", kind: "number" },
    tun_proxy_udp: { section: "tun", key: "proxy_udp", kind: "bool" },
    tun_proxy_dns: { section: "tun", key: "proxy_dns", kind: "bool" },
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
    return upsertTomlValue(raw, "tun", "quic_policy", formatTomlValue(policy, "string", field));
  }

  return upsertTomlValue(raw, target.section, target.key, formatTomlValue(value, target.kind, field));
}

export function summarizeRaw(raw: string): AgentConfigSummary {
  rejectRemovedDesktopTransportFields(raw);
  const runtimeThreads = normalizeRuntimeThreads(matchNumber(raw, null, "runtime_threads"));
  const tunQuicPolicy = normalizeQuicPolicy(matchString(raw, "tun", "quic_policy") ?? "allow");
  return {
    listen_addr: stringOrDefault(matchString(raw, null, "listen_addr"), "listen_addr"),
    proxy_addrs: arrayOrDefault(matchStringArray(raw, "proxy_addrs"), "proxy_addrs"),
    username: stringOrDefault(matchString(raw, null, "username"), "username"),
    private_key_path: stringOrDefault(matchString(raw, null, "private_key_path"), "private_key_path"),
    transport_mode: normalizeTransportMode(matchString(raw, null, "transport_mode") ?? "udp"),
    udp_session_pool_size: normalizeUdpSessionPoolSize(matchNumber(raw, null, "udp_session_pool_size")),
    connect_timeout_secs: matchNumber(raw, null, "connect_timeout_secs") ?? defaultValueForField<number>("connect_timeout_secs"),
    compression_mode: stringOrDefault(matchString(raw, null, "compression_mode"), "compression_mode"),
    log_level: stringOrDefault(matchString(raw, null, "log_level"), "log_level"),
    log_dir: matchString(raw, null, "log_dir"),
    log_file: stringOrDefault(matchString(raw, null, "log_file"), "log_file"),
    runtime_threads: runtimeThreads,
    effective_runtime_threads: runtimeThreads ?? defaultRuntimeThreads(),
    udp_yamux_sessions: matchNumber(raw, "yamux.udp", "sessions") ?? defaultValueForField<number>("udp_yamux_sessions"),
    udp_yamux_max_streams_per_session: matchNumber(raw, "yamux.udp", "max_streams_per_session") ?? defaultValueForField<number>("udp_yamux_max_streams_per_session"),
    udp_yamux_open_stream_timeout_secs: matchNumber(raw, "yamux.udp", "open_stream_timeout_secs") ?? defaultValueForField<number>("udp_yamux_open_stream_timeout_secs"),
    udp_yamux_keepalive_interval_secs: matchNumber(raw, "yamux.udp", "keepalive_interval_secs") ?? defaultValueForField<number>("udp_yamux_keepalive_interval_secs"),
    udp_yamux_connection_write_timeout_secs: matchNumber(raw, "yamux.udp", "connection_write_timeout_secs") ?? defaultValueForField<number>("udp_yamux_connection_write_timeout_secs"),
    udp_yamux_stream_window_size_kb: matchNumber(raw, "yamux.udp", "stream_window_size_kb") ?? defaultValueForField<number>("udp_yamux_stream_window_size_kb"),
    tun_enabled: matchBool(raw, "tun", "enabled") ?? defaultValueForField<boolean>("tun_enabled"),
    tun_name: stringOrDefault(matchString(raw, "tun", "name"), "tun_name"),
    tun_ipv4: stringOrDefault(matchString(raw, "tun", "ipv4"), "tun_ipv4"),
    tun_mtu: matchNumber(raw, "tun", "mtu") ?? defaultValueForField<number>("tun_mtu"),
    tun_proxy_udp: matchBool(raw, "tun", "proxy_udp") ?? defaultValueForField<boolean>("tun_proxy_udp"),
    tun_proxy_dns: matchBool(raw, "tun", "proxy_dns") ?? defaultValueForField<boolean>("tun_proxy_dns"),
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
    field === "udp_session_pool_size" ||
    field === "udp_yamux_sessions" ||
    field === "udp_yamux_max_streams_per_session" ||
    field === "udp_yamux_open_stream_timeout_secs" ||
    field === "udp_yamux_connection_write_timeout_secs"
  ) {
    return 1;
  }
  if (field === "udp_yamux_stream_window_size_kb") {
    return 256;
  }
  return 0;
}

function normalizeUdpSessionPoolSize(value: number | undefined) {
  return Math.min(8, Math.max(1, value ?? defaultValueForField<number>("udp_session_pool_size")));
}

function normalizeQuicPolicy(value: string) {
  return ["allow", "block"].includes(value) ? value : defaultValueForField<string>("tun_quic_policy");
}

function normalizeTransportMode(value: string): AgentTransportMode {
  if (value === "auto" || value === "udp" || value === "tcp") {
    return value;
  }
  throw new Error(`transport_mode 只支持 auto、udp 或 tcp，当前值为 ${JSON.stringify(value)}`);
}

function rejectRemovedDesktopTransportFields(raw: string) {
  if (hasAssignment(raw, null, "quic_connection_pool_size")) {
    throw new Error("配置字段 quic_connection_pool_size 已移除，请使用 udp_session_pool_size");
  }
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

function hasAssignment(raw: string, section: string | null, key: string) {
  const body = sectionBody(raw, section);
  return new RegExp(`^\\s*${escapeRegExp(key)}\\s*=`, "m").test(body);
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
