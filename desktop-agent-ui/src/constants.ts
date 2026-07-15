import type { TabKey } from "./types";
import type { AppIconName } from "./components/AppIcon";

export const tabs: Array<{ key: TabKey; label: string; icon: AppIconName }> = [
  { key: "overview", label: "总览", icon: "layout-dashboard" },
  { key: "forwarding", label: "转发", icon: "network" },
  { key: "egress", label: "出口", icon: "waypoints" },
  { key: "routing", label: "系统", icon: "settings" },
  { key: "diagnostics", label: "诊断", icon: "activity" },
  { key: "logs", label: "日志", icon: "scroll-text" },
  { key: "toml", label: "TOML", icon: "code" }
];

export const directRulePresets: Array<{ label: string; icon: AppIconName; rules: string[] }> = [
  { label: "本机", icon: "monitor", rules: ["localhost", "127.0.0.0/8", "::1"] },
  { label: "私网", icon: "building", rules: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
  { label: "中国", icon: "map-pin", rules: ["*.cn"] },
  { label: "Microsoft", icon: "cloud", rules: ["*.microsoft.com", "*.bing.com"] }
];

export const compressionOptions = ["none", "lz4", "gzip", "zstd"];
export const transportModeOptions = [
  { label: "原生 UDP 模式（TCP + 加密 UDP）", value: "udp" },
  { label: "全 TCP 模式", value: "tcp" }
];
export const logLevelOptions = ["trace", "debug", "info", "warn", "error"];

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
  allow: "允许 QUIC",
  block: "全部阻断"
};

export const quicPolicyOptions = [
  { label: quicPolicyLabels.allow, value: "allow" },
  { label: quicPolicyLabels.block, value: "block" }
];

export function quicPolicyLabel(policy: string) {
  return quicPolicyLabels[policy] ?? policy;
}
