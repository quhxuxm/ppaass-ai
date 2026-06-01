import type { AgentConfigSummary } from "./types";

export const fallbackRawConfig = `listen_addr = "127.0.0.1:10080"
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

export function coerceField(field: keyof AgentConfigSummary, value: unknown): unknown {
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

export function applyFieldToToml(raw: string, field: keyof AgentConfigSummary, value: unknown) {
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

export function summarizeRaw(raw: string): AgentConfigSummary {
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

function defaultRuntimeThreads() {
  return Math.max(1, Math.floor(globalThis.navigator?.hardwareConcurrency || 1));
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

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
