import { fallbackRawConfig, summarizeRaw } from "./configToml";
import type { AgentConfigSummary, AgentState, ConnectivityReport, LoadedAgentConfig, NetworkTrafficSnapshot } from "./types";

export function loadFallbackConfig(): LoadedAgentConfig {
  return {
    path: "config/local/agent.toml",
    raw: fallbackRawConfig,
    summary: summarizeRaw(fallbackRawConfig)
  };
}

export function fallbackAgentState(): AgentState {
  return {
    running: false,
    managed: false,
    pid: null,
    config_path: "config/local/agent.toml",
    binary_path: "target/release/desktop-agent",
    logs: ["desktop-agent ready", "proxy route guard initialized", "yamux tcp sessions: 5", "tun mode: disabled"]
  };
}

export function fallbackConnectivityReport(currentSummary?: AgentConfigSummary): ConnectivityReport {
  const listenAddr = currentSummary?.listen_addr ?? "0.0.0.0:10080";
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
    ? targets.flatMap((target) => [
      {
        target,
        protocol: "TUN",
        url: target === "Google" ? "https://www.google.com/generate_204" : "https://www.youtube.com/generate_204",
        proxy_url: `tun://${tunName}`,
        success: false,
        http_code: null,
        duration_ms: 0,
        error: tunStatus
      },
      {
        target,
        protocol: "QUIC",
        url: target === "Google" ? "quic://www.google.com:443" : "quic://www.youtube.com:443",
        proxy_url: `tun://${tunName}`,
        success: false,
        http_code: null,
        duration_ms: 0,
        error: tunStatus
      }
    ])
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

export function fallbackTrafficSnapshot(): NetworkTrafficSnapshot {
  return {
    sampled_at_ms: Date.now(),
    total_received_bytes: 0,
    total_transmitted_bytes: 0,
    interfaces: []
  };
}
