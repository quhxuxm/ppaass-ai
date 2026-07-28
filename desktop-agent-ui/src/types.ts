import type { AppIconName } from "./components/AppIcon";

export type TabKey = "overview" | "forwarding" | "egress" | "routing" | "capture" | "diagnostics" | "logs" | "toml";
export type AgentTransportMode = "auto" | "udp" | "tcp";

export type AgentConfigSummary = {
  listen_addr: string;
  proxy_addrs: string[];
  transport_mode: AgentTransportMode;
  udp_session_pool_size: number;
  connect_timeout_secs: number;
  compression_mode: string;
  log_level: string;
  log_dir?: string | null;
  log_file: string;
  runtime_threads?: number | null;
  effective_runtime_threads: number;
  udp_yamux_sessions: number;
  udp_yamux_max_streams_per_session: number;
  udp_yamux_open_stream_timeout_secs: number;
  udp_yamux_keepalive_interval_secs: number;
  udp_yamux_connection_write_timeout_secs: number;
  udp_yamux_stream_window_size_kb: number;
  tun_enabled: boolean;
  tun_name: string;
  tun_ipv4: string;
  tun_mtu: number;
  tun_proxy_udp: boolean;
  tun_proxy_dns: boolean;
  tun_quic_policy: string;
  tun_packet_capture_file: string;
  direct_mode: string;
  direct_rules: string[];
};

export type LoadedAgentConfig = {
  path: string;
  raw: string;
  summary: AgentConfigSummary;
};

export type AgentAuthAccount = {
  username: string;
  key_version: number;
  expires_at: number | null;
};

export type AgentAuthState = {
  authenticated: boolean;
  account: AgentAuthAccount | null;
  config: LoadedAgentConfig | null;
};

export type AgentDeviceLoginStatus =
  | "authorization_pending"
  | "slow_down"
  | "authenticated";

export type AgentDeviceLoginProgress = {
  status: AgentDeviceLoginStatus;
  user_code: string;
  expires_at: number;
  retry_after_seconds: number;
  auth_state: AgentAuthState | null;
};

export type AgentDeviceLoginViewState = AgentDeviceLoginProgress;

export type AgentLoginRequest = {
  username: string;
  password: string;
  rememberCredentials: boolean;
};

export type AgentAuthPhase =
  | "checking"
  | "anonymous"
  | "authenticating"
  | "starting-device-login"
  | "device-authorizing"
  | "authenticated"
  | "logging-out";

export type AgentState = {
  running: boolean;
  managed?: boolean;
  pid?: number | null;
  config_path?: string | null;
  binary_path?: string | null;
  logs: string[];
};

export type ConnectivityCheck = {
  target: string;
  protocol: string;
  url: string;
  proxy_url: string;
  success: boolean;
  http_code?: number | null;
  duration_ms: number;
  error?: string | null;
};

export type ConnectivityReport = {
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

export type NetworkTrafficSnapshot = {
  sampled_at_ms: number;
  total_received_bytes: number;
  total_transmitted_bytes: number;
  interfaces: NetworkInterfaceTraffic[];
};

export type NetworkInterfaceTraffic = {
  name: string;
  received_bytes: number;
  transmitted_bytes: number;
};

export type CapturedPacket = {
  number: number;
  timestamp_ms: number;
  direction: "upload" | "download";
  ip_version: number;
  protocol: string;
  sub_protocol?: string | null;
  proxy_protocol?: string | null;
  source: string;
  source_port?: number | null;
  destination: string;
  destination_port?: number | null;
  length: number;
  summary: string;
  payload_length: number;
  payload_hex: string;
  payload_text: string;
  protocol_layers: ProtocolLayer[];
};

export type ProtocolLayer = {
  name: string;
  summary: string;
  fields: Array<{
    name: string;
    value: string;
  }>;
};

export type PacketCaptureReport = {
  file: string;
  exists: boolean;
  file_size: number;
  modified_at_ms?: number | null;
  total_packets: number;
  returned_packets: number;
  truncated: boolean;
  upload_packets: number;
  upload_bytes: number;
  download_packets: number;
  download_bytes: number;
  packets: CapturedPacket[];
};

export type PacketCaptureRuntimeStatus = {
  available: boolean;
  enabled: boolean;
  file?: string | null;
};

export type DnsResolutionRecord = {
  timestamp_ms: number;
  resolver?: string;
  client: string;
  upstream: string;
  query: string;
  record_type: string;
  status: string;
  answers: string[];
  duration_ms: number;
};

export type TrafficBaseline = {
  date: string;
  received: number;
  transmitted: number;
};

export type TrafficHourBucket = {
  hour: number;
  download_bytes: number;
  upload_bytes: number;
};

export type TrafficHourlyStore = {
  date: string;
  last_received: number;
  last_transmitted: number;
  last_sampled_at_ms: number;
  buckets: TrafficHourBucket[];
};

export type ToastKind = "info" | "success" | "error";

export type DirectRuleGroup = {
  key: string;
  label: string;
  icon: AppIconName;
  /** 当前规则类型在哪些入口或模式下可用，用于直连规则页给用户做配置提示。 */
  modes: string[];
  items: Array<{ rule: string; index: number }>;
};

export type OverviewCardKey = "status" | "proxy" | "egress" | "speed" | "traffic" | "dns" | "tun" | "policy";

export type OverviewCardDefinition = {
  key: OverviewCardKey;
  baseSpan: number;
};

export type OverviewCardView = OverviewCardDefinition & {
  span: number;
};

export type OverviewDragGhost = {
  x: number;
  y: number;
  width: number;
  height: number;
  offsetX: number;
  offsetY: number;
};

export type LogTokenKind =
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

export type LogToken = {
  value: string;
  kind: LogTokenKind;
};

export type HighlightedLogLine = {
  raw: string;
  level: string | null;
  tokens: LogToken[];
};

export type TomlTokenKind =
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

export type TomlToken = {
  value: string;
  kind: TomlTokenKind;
};

export type HighlightedTomlLine = {
  raw: string;
  tokens: TomlToken[];
};
