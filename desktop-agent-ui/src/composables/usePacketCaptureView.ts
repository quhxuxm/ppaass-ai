import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { formatBytes } from "../formatters";
import type { AgentConfigSummary, CapturedPacket, PacketCaptureReport } from "../types";

type SortKey =
  | "number"
  | "timestamp"
  | "direction"
  | "protocol"
  | "source"
  | "destination"
  | "length"
  | "summary";
type SortDirection = "asc" | "desc";

const AUTO_REFRESH_INTERVAL_MS = 5_000;
const AUTO_REFRESH_MAX_FILE_BYTES = 32 * 1024 * 1024;

export interface PacketCaptureViewProps {
  summary: AgentConfigSummary;
  configPath: string;
  configLocked: boolean;
  agentRunning: boolean;
  captureEnabled: boolean;
  refreshToken: number;
  busy: boolean;
}

export type PacketCaptureViewEmit = {
  (event: "toggle-capture", enabled: boolean): void;
  (event: "clear-capture"): void;
  (event: "set-field", field: keyof AgentConfigSummary, value: unknown): void;
};

export function usePacketCaptureView(
  props: PacketCaptureViewProps,
  emit: PacketCaptureViewEmit
) {
  const state = reactive({
    loading: false,
    error: "",
    report: null as PacketCaptureReport | null
  });
  const query = ref("");
  const direction = ref("all");
  const protocol = ref("all");
  const minimumPacketSizeKb = ref<number | null>(null);
  const selectedPacket = ref<CapturedPacket | null>(null);
  const clearConfirmationVisible = ref(false);
  const sortKey = ref<SortKey>("number");
  const sortDirection = ref<SortDirection>("desc");
  let refreshTimer: number | undefined;
  let refreshInFlight = false;
  
  const directionOptions = [
    { label: "全部方向", value: "all" },
    { label: "Client → Agent / 目标", value: "upload" },
    { label: "Agent / 目标 → Client", value: "download" }
  ];
  
  const sortColumns: Array<{ key: SortKey; label: string }> = [
    { key: "number", label: "#" },
    { key: "timestamp", label: "时间" },
    { key: "direction", label: "方向" },
    { key: "protocol", label: "协议" },
    { key: "source", label: "源地址" },
    { key: "destination", label: "目标地址" },
    { key: "length", label: "长度" },
    { key: "summary", label: "摘要" }
  ];
  
  const protocolOptions = computed(() => [
    { label: "全部协议", value: "all" },
    ...Array.from(
      new Set([
        "proxy:HTTP",
        "proxy:SOCKS5",
        ...(state.report?.packets ?? []).flatMap(packetProtocolFilterValues)
      ])
    )
      .sort()
      .map((value) => ({
        label: value.startsWith("proxy:") ? `${value.slice("proxy:".length)} 代理` : value,
        value
      }))
  ]);
  
  watch(
    protocolOptions,
    (options) => {
      if (!options.some((option) => option.value === protocol.value)) {
        protocol.value = "all";
      }
    },
    { immediate: true }
  );
  
  watch(
    () => props.refreshToken,
    () => {
      void refresh();
    }
  );
  
  const hasCapturedPackets = computed(() => (state.report?.packets.length ?? 0) > 0);
  const captureFileHint = computed(() => {
    if (!state.report) {
      return "尚未读取";
    }
    if (!state.report.exists) {
      return "未生成";
    }
    return state.report.total_packets === 0 && state.report.file_size > 0
      ? "仅文件头"
      : "磁盘占用";
  });
  
  const filteredPackets = computed(() => {
    const normalizedQuery = query.value.trim().toLowerCase();
    const minimumPacketSizeBytes = Math.max(0, minimumPacketSizeKb.value ?? 0) * 1024;
    const selectedDirection = directionOptions.some((option) => option.value === direction.value)
      ? direction.value
      : "all";
    const selectedProtocol = protocolOptions.value.some((option) => option.value === protocol.value)
      ? protocol.value
      : "all";
    const packets = [...(state.report?.packets ?? [])]
      .filter((packet) => selectedDirection === "all" || packet.direction === selectedDirection)
      .filter(
        (packet) =>
          selectedProtocol === "all" ||
          packetProtocolFilterValues(packet).includes(selectedProtocol)
      )
      .filter((packet) => packet.length > minimumPacketSizeBytes)
      .filter((packet) => {
        if (!normalizedQuery) {
          return true;
        }
        return [
          packet.source,
          packet.destination,
          packet.source_port,
          packet.destination_port,
          packet.protocol,
          packet.sub_protocol,
          packet.proxy_protocol,
          packet.proxy_protocol ? `${packet.proxy_protocol} proxy 代理` : "",
          packet.summary,
          packet.payload_text,
          packet.payload_hex
        ]
          .join(" ")
          .toLowerCase()
          .includes(normalizedQuery);
      });
    return packets.sort(comparePackets);
  });
  
  const captureStatus = computed(() => {
    if (!props.agentRunning) {
      return { label: "Agent 已停止", severity: "secondary" as const };
    }
    if (!props.captureEnabled) {
      return { label: "抓包已关闭", severity: "warn" as const };
    }
    return { label: "正在抓包", severity: "success" as const };
  });
  
  onMounted(() => {
    void refresh();
    refreshTimer = window.setInterval(() => void refresh(false), AUTO_REFRESH_INTERVAL_MS);
  });
  
  onBeforeUnmount(() => {
    if (refreshTimer) {
      window.clearInterval(refreshTimer);
    }
  });
  
  async function refresh(showLoading = true) {
    if (refreshInFlight) {
      return;
    }
    if (!showLoading && (state.report?.file_size ?? 0) > AUTO_REFRESH_MAX_FILE_BYTES) {
      return;
    }
    refreshInFlight = true;
    if (showLoading) {
      state.loading = true;
    }
    try {
      if (!hasTauri()) {
        state.error = "抓包结果需要在桌面应用中查看";
        return;
      }
      state.report = await invoke<PacketCaptureReport>("get_packet_capture", {
        configPath: props.configPath,
        limit: 2000
      });
      state.error = "";
    } catch (error) {
      state.error = String(error);
    } finally {
      state.loading = false;
      refreshInFlight = false;
    }
  }
  
  function endpoint(address: string, port?: number | null) {
    const wrapped = address.includes(":") ? `[${address}]` : address;
    return port == null ? wrapped : `${wrapped}:${port}`;
  }
  
  function packetTime(timestampMs: number) {
    const date = new Date(timestampMs);
    const time = new Intl.DateTimeFormat("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }).format(date);
    return `${time}.${String(date.getMilliseconds()).padStart(3, "0")}`;
  }
  
  function directionLabel(value: CapturedPacket["direction"]) {
    return value === "upload" ? "Client → Agent / 目标" : "Agent / 目标 → Client";
  }
  
  function confirmClearCapture() {
    clearConfirmationVisible.value = false;
    selectedPacket.value = null;
    emit("clear-capture");
  }
  
  function comparePackets(left: CapturedPacket, right: CapturedPacket) {
    const leftValue = packetSortValue(left, sortKey.value);
    const rightValue = packetSortValue(right, sortKey.value);
    const comparison =
      typeof leftValue === "number" && typeof rightValue === "number"
        ? leftValue - rightValue
        : String(leftValue).localeCompare(String(rightValue), "zh-CN", {
            numeric: true,
            sensitivity: "base"
          });
    if (comparison !== 0) {
      return sortDirection.value === "asc" ? comparison : -comparison;
    }
    return right.number - left.number;
  }
  
  function packetSortValue(packet: CapturedPacket, key: SortKey): number | string {
    switch (key) {
      case "number":
        return packet.number;
      case "timestamp":
        return packet.timestamp_ms;
      case "direction":
        return directionLabel(packet.direction);
      case "protocol":
        return packetProtocolLabels(packet).join(" / ");
      case "source":
        return endpoint(packet.source, packet.source_port);
      case "destination":
        return endpoint(packet.destination, packet.destination_port);
      case "length":
        return packet.length;
      case "summary":
        return packet.summary;
    }
  }
  
  function packetProtocolFilterValues(packet: CapturedPacket) {
    return Array.from(
      new Set(
        [
          packet.protocol,
          packet.sub_protocol,
          packet.proxy_protocol ? `proxy:${packet.proxy_protocol}` : null
        ].filter((value): value is string => Boolean(value))
      )
    );
  }
  
  function packetProtocolLabels(packet: CapturedPacket) {
    const labels = [packet.protocol];
    if (packet.proxy_protocol) {
      labels.push(`${packet.proxy_protocol} 代理`);
    }
    if (packet.sub_protocol && packet.sub_protocol !== packet.proxy_protocol) {
      labels.push(packet.sub_protocol);
    }
    return labels;
  }
  
  function toggleSort(key: SortKey) {
    if (sortKey.value === key) {
      sortDirection.value = sortDirection.value === "asc" ? "desc" : "asc";
      return;
    }
    sortKey.value = key;
    sortDirection.value = "asc";
  }
  
  function sortIndicator(key: SortKey) {
    if (sortKey.value !== key) {
      return "↕";
    }
    return sortDirection.value === "asc" ? "↑" : "↓";
  }
  
  function sortAria(key: SortKey) {
    if (sortKey.value !== key) {
      return "none" as const;
    }
    return sortDirection.value === "asc" ? ("ascending" as const) : ("descending" as const);
  }
  
  function resetFilters() {
    query.value = "";
    direction.value = "all";
    protocol.value = "all";
    minimumPacketSizeKb.value = null;
  }
  
  function formatCaptureBytes(bytes?: number | null) {
    if (bytes == null) {
      return "—";
    }
    if (bytes < 1024) {
      return `${Math.max(0, Math.round(bytes))} 字节`;
    }
    return formatBytes(bytes);
  }
  
  function hasTauri() {
    return Boolean((window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
  }

  return {
    AUTO_REFRESH_MAX_FILE_BYTES,
    state,
    query,
    direction,
    protocol,
    minimumPacketSizeKb,
    selectedPacket,
    clearConfirmationVisible,
    sortKey,
    sortDirection,
    directionOptions,
    sortColumns,
    protocolOptions,
    hasCapturedPackets,
    captureFileHint,
    filteredPackets,
    captureStatus,
    refresh,
    endpoint,
    packetTime,
    directionLabel,
    confirmClearCapture,
    packetProtocolLabels,
    toggleSort,
    sortIndicator,
    sortAria,
    resetFilters,
    formatBytes,
    formatCaptureBytes
  };
}
