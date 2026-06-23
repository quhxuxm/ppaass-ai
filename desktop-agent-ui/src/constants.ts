import type { TabKey } from "./types";

export const tabs: Array<{ key: TabKey; label: string; icon: string }> = [
  { key: "overview", label: "总览", icon: "pi pi-th-large" },
  { key: "forwarding", label: "转发", icon: "pi pi-sitemap" },
  { key: "egress", label: "出口", icon: "pi pi-share-alt" },
  { key: "routing", label: "系统", icon: "pi pi-cog" },
  { key: "diagnostics", label: "诊断", icon: "pi pi-wifi" },
  { key: "logs", label: "日志", icon: "pi pi-list" },
  { key: "toml", label: "TOML", icon: "pi pi-code" }
];

export const directRulePresets = [
  { label: "本机", icon: "pi pi-desktop", rules: ["localhost", "127.0.0.0/8", "::1"] },
  { label: "私网", icon: "pi pi-building", rules: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
  { label: "中国", icon: "pi pi-map-marker", rules: ["*.cn"] },
  { label: "Microsoft", icon: "pi pi-cloud", rules: ["*.microsoft.com", "*.bing.com"] }
];

export const compressionOptions = ["none", "lz4", "gzip", "zstd"];
export const logLevelOptions = ["trace", "debug", "info", "warn", "error"];
export const transportModeLabels: Record<string, string> = {
  auto: "自动",
  yamux: "Yamux",
  legacy: "常规通道"
};

export const transportModeOptions = [
  { label: transportModeLabels.auto, value: "auto" },
  { label: transportModeLabels.yamux, value: "yamux" },
  { label: transportModeLabels.legacy, value: "legacy" }
];

export function transportModeLabel(mode: string) {
  return transportModeLabels[mode] ?? mode;
}

export const directModeLabels: Record<string, string> = {
  proxy_all: "全走代理",
  direct_all: "全量直连",
  rules: "按规则"
};

export const directModeOptions = [
  { label: "代理", value: "proxy_all" },
  { label: "直连", value: "direct_all" },
  { label: "规则", value: "rules" }
];

export const quicPolicyLabels: Record<string, string> = {
  allow: "允许",
  direct_if_rule_match: "仅直连 QUIC",
  block: "全部阻断"
};

export const quicPolicyOptions = [
  { label: quicPolicyLabels.allow, value: "allow" },
  { label: quicPolicyLabels.direct_if_rule_match, value: "direct_if_rule_match" },
  { label: quicPolicyLabels.block, value: "block" }
];

export function quicPolicyLabel(policy: string) {
  return quicPolicyLabels[policy] ?? policy;
}
