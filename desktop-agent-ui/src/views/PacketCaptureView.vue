<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import Button from "primevue/button";
import Card from "primevue/card";
import Dialog from "primevue/dialog";
import InputNumber from "primevue/inputnumber";
import InputText from "primevue/inputtext";
import Select from "primevue/select";
import Tag from "primevue/tag";
import AppIcon from "../components/AppIcon";
import { formatBytes, shortPath } from "../formatters";
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

const props = defineProps<{
  summary: AgentConfigSummary;
  configPath: string;
  configLocked: boolean;
  agentRunning: boolean;
  captureEnabled: boolean;
  refreshToken: number;
  busy: boolean;
}>();

const emit = defineEmits<{
  "toggle-capture": [enabled: boolean];
  "clear-capture": [];
  "set-field": [field: keyof AgentConfigSummary, value: unknown];
}>();

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

function hasTauri() {
  return Boolean((window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
}
</script>

<template>
  <div class="content-grid capture-page">
    <Card class="panel span-12 capture-settings">
      <template #title>
        <div class="panel-heading inline">
          <h2>明文抓包</h2>
          <Tag value="输出设置" severity="info" />
        </div>
      </template>
      <template #content>
        <label class="field">
          <span><AppIcon name="file-down" />PCAP 文件</span>
          <InputText
            :model-value="summary.tun_packet_capture_file"
            :disabled="configLocked"
            @update:model-value="
              emit('set-field', 'tun_packet_capture_file', $event)
            "
          />
          <small class="field-help">
            配置抓包输出路径；开启、关闭和清空均在本页立即完成，无需重启 Agent。
          </small>
        </label>
      </template>
    </Card>

    <Card class="panel span-12 capture-hero">
      <template #title>
        <div class="panel-heading inline">
          <div>
            <h2>明文抓包结果</h2>
            <p :title="state.report?.file || summary.tun_packet_capture_file">
              {{ shortPath(state.report?.file || summary.tun_packet_capture_file) }}
            </p>
          </div>
          <div class="capture-heading-actions">
            <Tag :value="captureStatus.label" :severity="captureStatus.severity" />
            <Button
              :label="captureEnabled ? '关闭抓包' : '开启抓包'"
              :severity="captureEnabled ? 'danger' : 'success'"
              :loading="busy"
              :disabled="busy || !agentRunning"
              @click="emit('toggle-capture', !captureEnabled)"
            >
              <template #icon="slotProps">
                <AppIcon :class="slotProps.class" :name="captureEnabled ? 'stop' : 'play'" />
              </template>
            </Button>
            <Button
              label="清空"
              severity="danger"
              outlined
              :disabled="busy"
              @click="clearConfirmationVisible = true"
            >
              <template #icon="slotProps">
                <AppIcon :class="slotProps.class" name="trash" />
              </template>
            </Button>
            <Button
              label="刷新"
              :loading="state.loading"
              severity="secondary"
              @click="refresh()"
            >
              <template #icon="slotProps">
                <AppIcon :class="slotProps.class" name="refresh" />
              </template>
            </Button>
          </div>
        </div>
      </template>
      <template #content>
        <div class="capture-metrics">
          <div class="metric-tile">
            <AppIcon name="file-down" />
            <span>数据包</span>
            <strong>{{ state.report?.total_packets ?? 0 }}</strong>
          </div>
          <div class="metric-tile">
            <AppIcon name="send" />
            <span>Client → Agent / 目标</span>
            <strong>{{ formatBytes(state.report?.upload_bytes ?? 0) }}</strong>
            <small>{{ state.report?.upload_packets ?? 0 }} 包</small>
          </div>
          <div class="metric-tile">
            <AppIcon name="cloud" />
            <span>Agent / 目标 → Client</span>
            <strong>{{ formatBytes(state.report?.download_bytes ?? 0) }}</strong>
            <small>{{ state.report?.download_packets ?? 0 }} 包</small>
          </div>
          <div class="metric-tile">
            <AppIcon name="database" />
            <span>PCAP 大小</span>
            <strong>{{ formatBytes(state.report?.file_size ?? 0) }}</strong>
          </div>
        </div>
        <p v-if="agentRunning && !captureEnabled" class="capture-notice warning">
          抓包默认关闭。点击“开启抓包”即可立即开始，无需重启 Agent。
        </p>
        <p v-else-if="state.report && !state.report.exists" class="capture-notice">
          尚未生成抓包文件。启动 Agent 并产生 TUN、HTTP 或 SOCKS5 流量后会自动显示。
        </p>
        <p
          v-if="(state.report?.file_size ?? 0) > AUTO_REFRESH_MAX_FILE_BYTES"
          class="capture-notice warning"
        >
          PCAP 已超过 {{ formatBytes(AUTO_REFRESH_MAX_FILE_BYTES) }}，为避免反复扫描大文件已暂停自动刷新。点击“刷新”查看最新数据，或清空抓包文件后恢复自动刷新。
        </p>
        <p v-if="state.error" class="capture-notice error">{{ state.error }}</p>
      </template>
    </Card>

    <Card class="panel span-12 capture-results">
      <template #title>
        <div class="panel-heading inline">
          <div>
            <h2>数据包列表</h2>
            <p>
              显示 {{ filteredPackets.length }} 包
              · 双击一行查看内容
              <template v-if="state.report?.truncated"> · PCAP 较大，仅载入最近 {{ state.report.returned_packets }} 包</template>
              <template v-if="(state.report?.file_size ?? 0) > AUTO_REFRESH_MAX_FILE_BYTES"> · 大文件已暂停自动刷新</template>
            </p>
          </div>
        </div>
      </template>
      <template #content>
        <div class="capture-filters">
          <label class="capture-search">
            <AppIcon name="search" />
            <InputText v-model="query" placeholder="搜索 IP、端口、协议或内容" />
          </label>
          <Select v-model="direction" :options="directionOptions" option-label="label" option-value="value" />
          <Select v-model="protocol" :options="protocolOptions" option-label="label" option-value="value" />
          <InputNumber
            v-model="minimumPacketSizeKb"
            class="capture-size-filter"
            input-id="capture-minimum-packet-size"
            placeholder="最小包大小"
            suffix=" KB"
            :min="0"
            :min-fraction-digits="0"
            :max-fraction-digits="2"
            show-buttons
            :step="0.1"
            aria-label="最小包大小，单位 KB"
          />
          <Button
            class="capture-reset-filter"
            label="重置筛选"
            severity="secondary"
            outlined
            @click="resetFilters"
          />
        </div>

        <div v-if="filteredPackets.length" class="capture-table-wrap">
          <table class="capture-table">
            <thead>
              <tr>
                <th
                  v-for="column in sortColumns"
                  :key="column.key"
                  :aria-sort="sortAria(column.key)"
                >
                  <button
                    type="button"
                    :class="['capture-sort-button', { active: sortKey === column.key }]"
                    :aria-label="`${column.label}，点击${sortKey === column.key && sortDirection === 'asc' ? '降序' : '升序'}排列`"
                    @click="toggleSort(column.key)"
                  >
                    <span>{{ column.label }}</span>
                    <span aria-hidden="true">{{ sortIndicator(column.key) }}</span>
                  </button>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="packet in filteredPackets"
                :key="packet.number"
                tabindex="0"
                title="双击查看数据包内容"
                @dblclick="selectedPacket = packet"
                @keydown.enter="selectedPacket = packet"
              >
                <td>{{ packet.number }}</td>
                <td class="capture-time">{{ packetTime(packet.timestamp_ms) }}</td>
                <td>
                  <span :class="['capture-direction', packet.direction]">
                    {{ directionLabel(packet.direction) }}
                  </span>
                </td>
                <td>
                  <div class="capture-protocol-stack">
                    <template
                      v-for="(label, index) in packetProtocolLabels(packet)"
                      :key="label"
                    >
                      <span v-if="index">/</span>
                      <Tag
                        :value="label"
                        :severity="index === 0 ? 'info' : label.endsWith('代理') ? 'success' : 'warn'"
                      />
                    </template>
                  </div>
                </td>
                <td><code>{{ endpoint(packet.source, packet.source_port) }}</code></td>
                <td><code>{{ endpoint(packet.destination, packet.destination_port) }}</code></td>
                <td>{{ packet.length }} B</td>
                <td class="capture-summary">{{ packet.summary }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="capture-empty">
          <AppIcon name="file-down" />
          <strong>{{ state.loading ? "正在读取抓包结果" : "没有符合条件的数据包" }}</strong>
          <span>产生 TUN、HTTP 或 SOCKS5 流量，或调整筛选条件后再查看。</span>
        </div>
      </template>
    </Card>

    <Dialog
      :visible="Boolean(selectedPacket)"
      modal
      dismissable-mask
      class="capture-packet-dialog"
      :header="selectedPacket ? `数据包 #${selectedPacket.number}` : '数据包内容'"
      @update:visible="!$event && (selectedPacket = null)"
    >
      <template v-if="selectedPacket">
        <p class="capture-dialog-subtitle">
          {{ directionLabel(selectedPacket.direction) }} · IPv{{ selectedPacket.ip_version }} ·
          {{ packetProtocolLabels(selectedPacket).join(" / ") }}
        </p>
        <div class="capture-detail-grid">
          <div><span>源地址</span><code>{{ endpoint(selectedPacket.source, selectedPacket.source_port) }}</code></div>
          <div><span>目标地址</span><code>{{ endpoint(selectedPacket.destination, selectedPacket.destination_port) }}</code></div>
          <div><span>时间</span><strong>{{ packetTime(selectedPacket.timestamp_ms) }}</strong></div>
          <div><span>包长度</span><strong>{{ selectedPacket.length }} B</strong></div>
        </div>
        <section class="capture-protocol-analysis">
          <h3>协议分析</h3>
          <details
            v-for="(layer, index) in selectedPacket.protocol_layers"
            :key="`${layer.name}-${index}`"
            open
          >
            <summary>
              <strong>{{ layer.name }}</strong>
              <span>{{ layer.summary }}</span>
            </summary>
            <dl>
              <template v-for="field in layer.fields" :key="`${field.name}-${field.value}`">
                <dt>{{ field.name }}</dt>
                <dd>{{ field.value }}</dd>
              </template>
            </dl>
          </details>
        </section>
        <div class="capture-payload">
          <div>
            <span>Payload Hex（完整 {{ selectedPacket.payload_length }} 字节）</span>
            <pre>{{ selectedPacket.payload_hex || "无 Payload" }}</pre>
          </div>
          <div>
            <span>ASCII</span>
            <pre>{{ selectedPacket.payload_text || "无 Payload" }}</pre>
          </div>
        </div>
      </template>
    </Dialog>

    <Dialog
      v-model:visible="clearConfirmationVisible"
      modal
      header="清空抓包文件"
      class="capture-clear-dialog"
    >
      <p>将永久删除当前列表中的全部抓包记录。Agent 无需重启，若抓包已开启，清空后会立即继续记录新数据包。</p>
      <template #footer>
        <Button label="取消" severity="secondary" @click="clearConfirmationVisible = false" />
        <Button
          label="确认清空"
          severity="danger"
          :loading="busy"
          @click="confirmClearCapture"
        />
      </template>
    </Dialog>
  </div>
</template>
