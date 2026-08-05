<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import Dialog from "primevue/dialog";
import InputNumber from "primevue/inputnumber";
import InputText from "primevue/inputtext";
import Select from "primevue/select";
import Tag from "primevue/tag";
import AppIcon from "../components/AppIcon";
import {
  usePacketCaptureView,
  type PacketCaptureViewEmit,
  type PacketCaptureViewProps
} from "../composables/usePacketCaptureView";

const props = defineProps<PacketCaptureViewProps>();
const emit = defineEmits<PacketCaptureViewEmit>();
const {
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
} = usePacketCaptureView(props, emit);
</script>

<template>
  <div class="content-grid capture-page">
    <Card class="panel span-12 capture-console">
      <template #title>
        <div class="panel-heading inline capture-console-heading">
          <h2>明文抓包</h2>
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
        <div class="capture-console-grid">
          <label class="field capture-output-setting">
            <span><AppIcon name="file-down" />PCAP 输出文件</span>
            <InputText
              id="capture-output-file"
              :model-value="summary.tun_packet_capture_file"
              :disabled="configLocked"
              @update:model-value="
                emit('set-field', 'tun_packet_capture_file', $event)
              "
            />
            <small class="field-help">
              保存抓包数据的磁盘路径；开关与清空立即生效，无需重启 Agent。
            </small>
          </label>

          <div class="capture-metrics">
            <div class="metric-tile">
              <AppIcon name="file-down" />
              <span>数据包总数</span>
              <div class="capture-metric-value">
                <strong>{{ state.report?.total_packets ?? "—" }}</strong>
                <small>{{ state.report ? "包" : "尚未读取" }}</small>
              </div>
            </div>
            <div class="metric-tile">
              <AppIcon name="send" />
              <span>上传流量</span>
              <div class="capture-metric-value">
                <strong>{{ formatCaptureBytes(state.report?.upload_bytes) }}</strong>
                <small>{{ state.report?.upload_packets ?? 0 }} 包</small>
              </div>
            </div>
            <div class="metric-tile">
              <AppIcon name="cloud" />
              <span>下载流量</span>
              <div class="capture-metric-value">
                <strong>{{ formatCaptureBytes(state.report?.download_bytes) }}</strong>
                <small>{{ state.report?.download_packets ?? 0 }} 包</small>
              </div>
            </div>
            <div class="metric-tile">
              <AppIcon name="database" />
              <span>文件大小</span>
              <div class="capture-metric-value">
                <strong>{{ formatCaptureBytes(state.report?.file_size) }}</strong>
                <small>{{ captureFileHint }}</small>
              </div>
            </div>
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
              <template v-if="hasCapturedPackets">
                显示 {{ filteredPackets.length }} 包 · 双击一行查看内容
                <template v-if="state.report?.truncated"> · PCAP 较大，仅载入最近 {{ state.report.returned_packets }} 包</template>
                <template v-if="(state.report?.file_size ?? 0) > AUTO_REFRESH_MAX_FILE_BYTES"> · 大文件已暂停自动刷新</template>
              </template>
              <template v-else>捕获到的数据包会显示在这里</template>
            </p>
          </div>
        </div>
      </template>
      <template #content>
        <div v-if="hasCapturedPackets" class="capture-filters">
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
          <strong>
            {{
              state.loading
                ? "正在读取抓包结果"
                : hasCapturedPackets
                  ? "没有符合筛选条件的数据包"
                  : "还没有捕获到数据包"
            }}
          </strong>
          <span>
            {{
              hasCapturedPackets
                ? "调整筛选条件后再查看。"
                : "启动 Agent 并开启抓包后，TUN、HTTP 或 SOCKS5 流量会显示在这里。"
            }}
          </span>
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
