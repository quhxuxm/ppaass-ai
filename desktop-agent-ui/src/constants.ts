import type { TabKey } from "./types";
import type { AppIconName } from "./components/AppIcon";

export const tabs: Array<{ key: TabKey; label: string; icon: AppIconName }> = [
  { key: "overview", label: "总览", icon: "layout-dashboard" },
  { key: "admin-requests", label: "密钥申请", icon: "key" },
  { key: "forwarding", label: "转发", icon: "network" },
  { key: "egress", label: "出口", icon: "waypoints" },
  { key: "routing", label: "系统", icon: "settings" },
  { key: "capture", label: "抓包", icon: "file-down" },
  { key: "diagnostics", label: "诊断", icon: "activity" },
  { key: "logs", label: "日志", icon: "scroll-text" },
  { key: "toml", label: "TOML", icon: "code" }
];

export const directRulePresets: Array<{ label: string; icon: AppIconName; rules: string[] }> = [
  { label: "本机", icon: "monitor", rules: ["localhost", "127.0.0.0/8", "::1"] },
  { label: "私网", icon: "building", rules: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
  { label: "中国", icon: "map-pin", rules: ["*.cn"] },
  { label: "Microsoft", icon: "cloud", rules: ["*.microsoft.com", "*.bing.com"] },
  {
    label: "Teams",
    icon: "cloud",
    rules: [
      "teams.microsoft.com",
      "*.teams.microsoft.com",
      "teams.cloud.microsoft",
      "*.teams.cloud.microsoft",
      "*.lync.com",
      "*.skype.com",
      "cloud.microsoft",
      "*.cloud.microsoft",
      "static.microsoft",
      "*.static.microsoft",
      "usercontent.microsoft",
      "*.usercontent.microsoft",
      "*.auth.microsoft.com",
      "*.msftidentity.com",
      "*.msidentity.com",
      "account.activedirectory.windowsazure.com",
      "accounts.accesscontrol.windows.net",
      "adminwebservice.microsoftonline.com",
      "api.passwordreset.microsoftonline.com",
      "autologon.microsoftazuread-sso.com",
      "becws.microsoftonline.com",
      "ccs.login.microsoftonline.com",
      "clientconfig.microsoftonline-p.net",
      "companymanager.microsoftonline.com",
      "device.login.microsoftonline.com",
      "graph.microsoft.com",
      "graph.windows.net",
      "login-us.microsoftonline.com",
      "login.microsoft.com",
      "login.microsoftonline-p.com",
      "login.microsoftonline.com",
      "login.windows.net",
      "logincert.microsoftonline.com",
      "loginex.microsoftonline.com",
      "nexus.microsoftonline-p.com",
      "passwordreset.microsoftonline.com",
      "provisioningapi.microsoftonline.com",
      "*.hip.live.com",
      "*.microsoftonline-p.com",
      "*.microsoftonline.com",
      "*.msauth.net",
      "*.msauthimages.net",
      "*.msecnd.net",
      "*.msftauth.net",
      "*.msftauthimages.net",
      "*.phonefactor.net",
      "enterpriseregistration.windows.net",
      "account.live.com",
      "login.live.com",
      "aka.ms",
      "*.keydelivery.mediaservices.windows.net",
      "*.streaming.mediaservices.windows.net",
      "join.secure.skypeassets.com",
      "mlccdnprod.azureedge.net",
      "52.112.0.0/14",
      "52.122.0.0/15",
      "20.20.32.0/19",
      "20.190.128.0/18",
      "20.231.128.0/19",
      "40.126.0.0/18",
      "2603:1006:2000::/48",
      "2603:1007:200::/48",
      "2603:1016:1400::/48",
      "2603:1017::/48",
      "2603:1026:3000::/48",
      "2603:1027::/48",
      "2603:1027:1::/48",
      "2603:1036:3000::/48",
      "2603:1037::/48",
      "2603:1037:1::/48",
      "2603:1046:2000::/48",
      "2603:1047::/48",
      "2603:1047:1::/48",
      "2603:1056:2000::/48",
      "2603:1057:2::/48",
      "2603:1057::/48",
      "2603:1063::/38",
      "2620:1ec:6::/48",
      "2620:1ec:40::/42"
    ]
  },
  { label: "Skype", icon: "cloud", rules: ["skype.com", "*.skype.com"] },
  { label: "Outlook", icon: "cloud", rules: ["outlook.com", "*.outlook.com", "outlook.office.com", "*.outlook.office.com"] },
  { label: "Office", icon: "cloud", rules: ["office.com", "*.office.com", "office365.com", "*.office365.com"] }
];

export const compressionOptions = ["none", "lz4", "gzip", "zstd"];
export const transportModeOptions = [
  { label: "自动模式", value: "auto" },
  { label: "原生 UDP 模式", value: "udp" },
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
