import { readonly, ref } from "vue";

export type AppLocale = "zh-CN" | "en";

export const APP_LOCALE_STORAGE_KEY = "ppaass-ui-language";
export const languageOptions: ReadonlyArray<{ value: AppLocale; label: string }> = [
  { value: "zh-CN", label: "中文" },
  { value: "en", label: "English" }
];

const messages: Record<string, string> = {
  "中文": "Chinese",
  "桌面代理": "Desktop Agent",
  "总览": "Overview", "转发": "Forwarding", "出口": "Egress", "系统": "System",
  "诊断": "Diagnostics", "日志": "Logs", "配置": "Config",
  "展开导航": "Expand navigation", "收起导航": "Collapse navigation",
  "语言": "Language", "选择界面语言": "Choose interface language",
  "界面设置": "Interface", "配置管理": "Configuration", "已修改": "Modified", "保存": "Save",
  "保存更改": "Save changes",
  "界面与配置": "Appearance & config", "调整显示偏好或恢复配置": "Adjust display preferences or restore configuration",
  "有未保存的更改": "Unsaved changes", "配置已同步": "Configuration synced",
  "更多": "More", "语言与外观": "Language and appearance",
  "代理服务": "Agent service", "启动代理": "Start agent", "停止代理": "Stop agent",
  "运行信息": "Runtime information", "当前代理进程与配置": "Current agent process and configuration",
  "服务状态": "Service status", "进程 ID": "Process ID", "配置文件": "Configuration file",
  "配色": "Theme", "配色风格": "Color theme", "选择界面配色": "Choose interface colors",
  "重新载入": "Reload", "恢复默认": "Restore defaults", "保存配置": "Save config",
  "启动": "Start", "停止": "Stop", "加载中": "Loading", "未载入配置": "No configuration loaded",
  "初始化": "Initializing", "就绪": "Ready", "配置异常": "Configuration error",
  "运行中": "Running", "已停止": "Stopped", "空闲": "Idle", "已启用": "Enabled",
  "未启用": "Disabled", "未就绪": "Not ready", "待测试": "Not tested",
  "未测试": "Not tested", "无测试": "No tests", "跳过": "Skipped",
  "通过": "Passed", "失败": "Failed", "成功": "Success", "离线": "Offline",
  "可访问": "Reachable", "已暂停": "Paused", "代理已通": "Proxy reachable",
  "随代理启动": "Starts with agent", "全走代理": "Proxy all", "全量直连": "Direct all",
  "已从系统菜单启用": "Enabled from the system menu",
  "已从系统菜单关闭": "Disabled from the system menu",
  "，正在重启代理": "; restarting the agent",
  "按规则": "By rules", "代理": "Proxy", "直连": "Direct", "规则": "Rules",
  "允许 QUIC": "Allow QUIC", "全部阻断": "Block all", "自动模式": "Auto mode",
  "原生 UDP 模式": "Native UDP mode", "全 TCP 模式": "All TCP mode",
  "午夜霓虹": "Midnight Neon", "深海蓝": "Deep Ocean", "森林绿": "Forest Green",
  "日落橙": "Sunset Orange", "星云紫": "Nebula Violet", "暖瓷白": "Warm Porcelain",
  "晴空白": "Clear Sky", "薄荷白": "Mint White", "樱花白": "Sakura White",
  "运行状态": "Runtime status", "公共远端出口": "Public remote egress",
  "实时网速": "Live speed", "今日流量": "Today's traffic", "代理 DNS": "Proxy DNS",
  "共享策略": "Shared policy", "当前转发": "Active forwarding", "代理入口": "Proxy entry",
  "公共出口": "Public egress", "传输策略": "Transport policy", "压缩": "Compression",
  "监听": "Listen", "协议": "Protocol", "节点": "Nodes", "未配置": "Not configured",
  "下载": "Download", "上传": "Upload", "每小时合计": "Hourly total",
  "每小时下载": "Hourly download", "每小时上传": "Hourly upload",
  "今日每小时上传与下载流量趋势": "Today's hourly upload and download traffic trend",
  "空闲小时": "Idle hour", "代理 DNS 未启用": "Proxy DNS is disabled",
  "等待经过代理的 DNS 请求": "Waiting for proxied DNS requests",
  "清空": "Clear", "全选": "Select all",
  "该域名已在直连规则中": "This domain is already in direct rules",
  "点击选择该域名": "Click to select this domain", "已直连": "Direct",
  "缓存命中": "Cache hit", "直连解析": "Direct resolution", "系统 DNS": "System DNS",
  "TUN + DNS 缓存": "TUN + DNS cache",
  "该 DNS 响应来自代理内部 DNS cache，未重新请求上游 DNS": "This response came from the proxy DNS cache without a new upstream request",
  "该请求绕过了代理内部 DNS，由代理所在机器的系统解析": "This request bypassed proxy DNS and used the agent host resolver",
  "设备": "Device", "地址": "Address", "普通 UDP": "Regular UDP",
  "按规则分流": "Route by rules", "Agent 直连": "Agent direct",
  "QUIC 应用流量": "QUIC app traffic",
  "直连或自动回退代理": "Direct or auto fallback proxy",
  "直连或经加密 UDP 代理": "Direct or encrypted UDP proxy",
  "直连或经 TCP 代理": "Direct or TCP proxy", "经 Proxy 解析": "Resolve via proxy",
  "系统解析": "System resolution", "服务对象": "Applies to",
  "代理入口与 TUN 模式": "Proxy entry and TUN mode",
  "链路诊断": "Connectivity diagnostics", "运行测试": "Run tests", "测试中": "Testing",
  "本地入口": "Local entry", "站点": "Sites", "结果": "Result",
  "链路结果": "Connectivity results", "后台测试中": "Testing in background",
  "等待结果": "Waiting for results", "身份凭据": "Credentials", "用户": "User",
  "私钥": "Private key", "TCP 始终走 TCP": "TCP always uses TCP",
  "UDP 代理通道": "UDP proxy channel",
  "自动：原生 UDP 超时后仅该 session 转 TCP/Yamux；TCP 始终走 TCP。": "Auto: only a timed-out native UDP session falls back to TCP/Yamux; TCP always uses TCP.",
  "控制连接超时": "Control connection timeout", "消息压缩": "Message compression",
  "TCP 数据": "TCP data", "两种模式均使用 TCP": "TCP is used in both modes",
  "TCP 转发": "TCP forwarding",
  "TCP 目标始终使用独立 TCP 连接。": "TCP targets always use separate TCP connections.",
  "UDP 数据 · 原生加密 UDP": "UDP data · Native encrypted UDP",
  "自动模式首选": "Preferred in auto mode", "UDP 模式": "UDP mode",
  "加密 UDP 会话池": "Encrypted UDP session pool", "仅作用于 UDP relay": "UDP relay only",
  "UDP 会话数": "UDP sessions",
  "已认证 UDP 会话数，范围 1–8，默认 4。": "Authenticated UDP sessions. Range 1–8; default 4.",
  "RSA 认证，UDP 数据使用 AES-256-GCM；不重传、不保序。": "RSA authentication with AES-256-GCM UDP data; no retransmission or ordering.",
  "UDP 数据 · TCP/Yamux": "UDP data · TCP/Yamux", "自动回退通道": "Automatic fallback channel",
  "全 TCP": "All TCP", "UDP Yamux": "UDP Yamux",
  "作用于 UDP relay 子流": "Applies to UDP relay streams", "外层连接": "Outer connections",
  "Yamux 外层连接上限。": "Maximum Yamux outer connections.", "并发子流": "Concurrent streams",
  "单连接最大 UDP 子流数。": "Maximum UDP streams per connection.",
  "打开子流超时": "Open-stream timeout",
  "申请 Yamux 子流的超时。": "Timeout for acquiring a Yamux stream.",
  "Yamux 保活间隔；0 为关闭。": "Yamux keepalive interval; 0 disables it.",
  "写超时": "Write timeout", "Yamux 写入超时。": "Yamux write timeout.",
  "流控窗口": "Flow-control window", "单个 UDP 子流缓冲窗口。": "Buffer window for each UDP stream.",
  "HTTP / SOCKS5 代理": "HTTP / SOCKS5 proxy", "入站协议": "Inbound protocols",
  "监听状态": "Listen status", "监听地址": "Listen address", "代理状态": "Proxy status",
  "状态": "Status", "TUN 模式": "TUN mode", "TUN 设备": "TUN device",
  "转发方式": "Forwarding method", "虚拟网卡": "Virtual adapter", "当前状态": "Current status",
  "名称": "Name", "TUN 专属策略": "TUN-specific policy", "代理普通 UDP": "Proxy regular UDP",
  "关闭后普通 UDP 直连；DNS 与 QUIC 单独分流。": "When off, regular UDP goes direct; DNS and QUIC are routed separately.",
  "DNS 经 Proxy": "DNS via proxy", "仅控制传统 DNS（53 端口）。": "Controls traditional DNS on port 53 only.",
  "QUIC（UDP/443）策略": "QUIC (UDP/443) policy", "刷新": "Refresh", "暂无日志": "No logs",
  "系统运行参数": "System runtime settings", "全局": "Global", "运行参数": "Runtime settings",
  "线程": "Threads", "流量策略": "Traffic policy", "共享直连策略": "Shared direct policy",
  "模式": "Mode", "规则数量": "Rule count", "代理入口填域名": "Use domains for proxy entry",
  "HTTP/SOCKS5 支持域名规则，如 example.com、*.example.com。": "HTTP/SOCKS5 supports domain rules such as example.com and *.example.com.",
  "TUN 优先填 IP/CIDR": "Prefer IP/CIDR for TUN",
  "TUN 建议使用固定 IP/CIDR，如 192.168.0.0/16。": "For TUN, prefer a fixed IP/CIDR such as 192.168.0.0/16.",
  "TUN 域名规则": "TUN domain rules", "需代理 DNS": "Requires proxy DNS",
  "域名规则需开启代理 DNS，并在 DNS 缓存命中后生效。": "Domain rules require proxy DNS and take effect after a DNS cache hit.",
  "规则管理": "Rule management", "快捷预设": "Quick presets", "添加规则": "Add rules",
  "HTTP / SOCKS5 可填域名；TUN 优先填 IP/CIDR；TUN 域名规则需开启代理 DNS。": "HTTP/SOCKS5 accepts domains; prefer IP/CIDR for TUN; TUN domain rules require proxy DNS.",
  "规则值": "Rule value", "添加": "Add", "当前规则": "Current rules",
  "直连规则类型": "Direct rule type", "删除规则": "Delete rule",
  "通配符": "Wildcard", "域名": "Domain", "其他": "Other", "本机": "Localhost",
  "私网": "Private network", "中国": "China", "已解析 IP 目标": "Resolved IP targets",
  "按规则内容匹配": "Match rule content", "添加并重启": "Add and restart",
  "自动：加密 UDP → TCP": "Auto: encrypted UDP → TCP",
  "TCP + 加密 UDP": "TCP + encrypted UDP", "不存在": "Not found", "超时": "Timed out",
  "无返回记录": "No records returned", "解析超时": "Resolution timed out",
  "正在处理其他操作": "Another operation is in progress",
  "TUN 状态需要 Tauri 运行时": "TUN status requires the Tauri runtime",
  "需要 Tauri 运行时": "Requires the Tauri runtime",
  "配置字段 quic_connection_pool_size 已移除，请使用 udp_session_pool_size": "The quic_connection_pool_size field was removed; use udp_session_pool_size instead",
  "代理运行中，停止后再修改配置": "Stop the running agent before editing configuration",
  "已重新载入": "Reloaded",
  "当前环境无法读取内置默认配置": "Built-in defaults are unavailable in this environment",
  "已恢复默认配置，保存后生效": "Defaults restored; save to apply",
  "代理已启动": "Agent started", "代理启动失败": "Agent failed to start",
  "代理已停止": "Agent stopped", "代理仍在运行": "Agent is still running",
  "规则已更新": "Rules updated", "直连规则已添加并保存": "Direct rules added and saved",
  "直连规则已保存，但 Agent 停止失败": "Direct rules were saved, but the agent failed to stop",
  "直连规则已保存，但 Agent 重启失败": "Direct rules were saved, but the agent failed to restart",
  "直连规则已添加，Agent 已重启": "Direct rules added; agent restarted",
  "拖动调整顺序": "Drag to reorder"
};

const locale = ref<AppLocale>(localStorage.getItem(APP_LOCALE_STORAGE_KEY) === "en" ? "en" : "zh-CN");
const sources = new WeakMap<Node, string>();
const rendered = new WeakMap<Node, string>();
const attributeSources = new WeakMap<Element, Map<string, string>>();
const attributeRendered = new WeakMap<Element, Map<string, string>>();
const attributes = ["title", "aria-label", "placeholder"];
let observer: MutationObserver | undefined;

export function useI18n() {
  return { locale: readonly(locale), setLocale, t };
}

export function setLocale(value: AppLocale) {
  locale.value = value;
  localStorage.setItem(APP_LOCALE_STORAGE_KEY, value);
  document.documentElement.lang = value;
  if (document.body) translateTree(document.body);
}

export function t(source: string) {
  if (locale.value === "zh-CN") return source;
  if (messages[source]) return messages[source];
  let result = source;
  for (const [chinese, english] of Object.entries(messages).sort((a, b) => b[0].length - a[0].length)) {
    result = result.replaceAll(chinese, english);
  }
  return result
    .replace(/(\d+) 条/g, "$1 items")
    .replace(/(\d+) 个节点/g, "$1 nodes")
    .replace(/\s{2,}/g, " ");
}

export function installDomI18n() {
  document.documentElement.lang = locale.value;
  translateTree(document.body);
  observer?.disconnect();
  observer = new MutationObserver((records) => {
    for (const record of records) {
      if (record.type === "characterData") translateText(record.target);
      else if (record.type === "attributes") translateAttribute(record.target as Element, record.attributeName ?? "");
      else record.addedNodes.forEach(translateTree);
    }
  });
  observer.observe(document.body, {
    subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: attributes
  });
}

function translateTree(node: Node) {
  if (shouldSkip(node)) return;
  if (node.nodeType === Node.TEXT_NODE) {
    translateText(node);
    return;
  }
  if (!(node instanceof Element)) return;
  attributes.forEach((attribute) => translateAttribute(node, attribute));
  node.childNodes.forEach(translateTree);
}

function translateText(node: Node) {
  if (shouldSkip(node)) return;
  const current = node.nodeValue ?? "";
  if (!rendered.has(node) || current !== rendered.get(node)) sources.set(node, current);
  const source = sources.get(node) ?? current;
  const match = /^(\s*)(.*?)(\s*)$/s.exec(source);
  const next = match && match[2] ? `${match[1]}${t(match[2])}${match[3]}` : source;
  rendered.set(node, next);
  if (current !== next) node.nodeValue = next;
}

function translateAttribute(element: Element, attribute: string) {
  if (shouldSkip(element)) return;
  if (!attributes.includes(attribute) || !element.hasAttribute(attribute)) return;
  const current = element.getAttribute(attribute) ?? "";
  const sourceMap = attributeSources.get(element) ?? new Map<string, string>();
  const renderedMap = attributeRendered.get(element) ?? new Map<string, string>();
  if (!renderedMap.has(attribute) || current !== renderedMap.get(attribute)) sourceMap.set(attribute, current);
  const next = t(sourceMap.get(attribute) ?? current);
  sourceMap.set(attribute, sourceMap.get(attribute) ?? current);
  renderedMap.set(attribute, next);
  attributeSources.set(element, sourceMap);
  attributeRendered.set(element, renderedMap);
  if (current !== next) element.setAttribute(attribute, next);
}

function shouldSkip(node: Node) {
  const element = node instanceof Element ? node : node.parentElement;
  return Boolean(element?.closest(".log-line, .toml-highlight, .toml-editor"));
}
