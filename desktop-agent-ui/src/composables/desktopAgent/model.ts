import { computed, reactive } from "vue";
import { fallbackRawConfig, summarizeRaw } from "../../configToml";
import { directModeLabels } from "../../constants";
import {
  dnsRecordTimestamp,
  isAgentOrSystemDnsRecord,
  normalizeDnsRecords
} from "../../formatters";
import { emptyTrafficBuckets } from "../../trafficStorage";
import type {
  AgentState,
  ConnectivityReport,
  DnsResolutionRecord,
  LoadedAgentConfig,
  NetworkTrafficSnapshot,
  PacketCaptureRuntimeStatus,
  TabKey,
  TrafficBaseline,
  ToastKind
} from "../../types";

export function createDesktopAgentModel() {
  const state = reactive({
    activeTab: "overview" as TabKey,
    loading: true,
    busy: false,
    diagnosticsRunning: false,
    dirty: false,
    ruleDraft: "",
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
    packetCapture: {
      available: false,
      enabled: false,
      file: null
    } as PacketCaptureRuntimeStatus,
    packetCaptureRefreshToken: 0,
    traffic: {
      snapshot: null as NetworkTrafficSnapshot | null,
      previous: null as NetworkTrafficSnapshot | null,
      baseline: null as TrafficBaseline | null,
      hourly_buckets: emptyTrafficBuckets(),
      download_bps: 0,
      upload_bps: 0,
      day_download_bytes: 0,
      day_upload_bytes: 0
    },
    dnsRecords: [] as DnsResolutionRecord[]
  });

  const summary = computed(
    () => state.config?.summary ?? summarizeRaw(fallbackRawConfig)
  );
  const running = computed(() => state.agent.running);
  const configLocked = computed(() => running.value);
  const runningLabel = computed(() => (running.value ? "运行中" : "已停止"));
  const runningSeverity = computed(() =>
    running.value ? "success" : "secondary"
  );
  const proxyDiagnosticResults = computed(
    () => state.diagnostics?.results ?? []
  );
  const tunDiagnosticResults = computed(
    () => state.diagnostics?.tun_results ?? []
  );
  const diagnosticsTotal = computed(
    () =>
      proxyDiagnosticResults.value.length + tunDiagnosticResults.value.length
  );
  const diagnosticsPassed = computed(
    () =>
      proxyDiagnosticResults.value.filter((item) => item.success).length +
      tunDiagnosticResults.value.filter((item) => item.success).length
  );
  const tunDiagnosticsLabel = computed(() => {
    if (!state.diagnostics) {
      return "待测试";
    }
    if (!state.diagnostics.tun_enabled) {
      return "未启用";
    }
    if (!state.diagnostics.tun_ready) {
      return "未就绪";
    }
    if (!tunDiagnosticResults.value.length) {
      return "无测试";
    }
    const passed = tunDiagnosticResults.value.filter(
      (item) => item.success
    ).length;
    return `${passed}/${tunDiagnosticResults.value.length}`;
  });
  const directModeLabel = computed(
    () =>
      directModeLabels[summary.value.direct_mode] ?? summary.value.direct_mode
  );
  const tunModeLabel = computed(() =>
    summary.value.tun_enabled ? "已启用" : "未启用"
  );
  const proxyEntryStateLabel = computed(() => "随代理启动");
  const activeForwardingLabel = computed(() =>
    summary.value.tun_enabled
      ? "TUN + HTTP / SOCKS5"
      : "HTTP / SOCKS5 代理"
  );
  const recentDnsRecords = computed(() =>
    normalizeDnsRecords(state.dnsRecords)
      .filter(isAgentOrSystemDnsRecord)
      .sort(
        (left, right) =>
          dnsRecordTimestamp(right) - dnsRecordTimestamp(left)
      )
      .slice(0, 80)
  );
  const dnsCardLabel = computed(() =>
    summary.value.tun_proxy_dns
      ? `${recentDnsRecords.value.length} 条`
      : "系统"
  );

  return {
    state,
    summary,
    running,
    configLocked,
    runningLabel,
    runningSeverity,
    diagnosticsTotal,
    diagnosticsPassed,
    tunDiagnosticsLabel,
    directModeLabel,
    tunModeLabel,
    proxyEntryStateLabel,
    activeForwardingLabel,
    recentDnsRecords,
    dnsCardLabel
  };
}

export type DesktopAgentModel = ReturnType<typeof createDesktopAgentModel>;

export function showToast(
  model: DesktopAgentModel,
  kind: ToastKind,
  message: string
) {
  model.state.toast = { kind, message };
  window.setTimeout(() => {
    model.state.toast = null;
  }, 2600);
}

export function latestAgentLog(model: DesktopAgentModel) {
  const logs = model.state.agent.logs ?? [];
  return logs.length > 0 ? logs[logs.length - 1] : null;
}
