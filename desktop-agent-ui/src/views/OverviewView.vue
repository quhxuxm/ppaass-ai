<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import Badge from "primevue/badge";
import Button from "primevue/button";
import Card from "primevue/card";
import Knob from "primevue/knob";
import Tag from "primevue/tag";
import AppIcon from "../components/AppIcon";
import {
  dnsAnswerLabel,
  dnsAnswers,
  formatBytes,
  formatRate,
  hourLabel,
  isAgentDnsCacheRecord,
  isAgentDirectDnsRecord,
  isSystemDnsRecord,
  localDateKey,
  shortPath
} from "../formatters";
import {
  buildOverviewCards,
  normalizeOverviewCardOrder,
  overviewCardByKey,
  readOverviewCardOrder,
  saveOverviewCardOrder
} from "../overviewLayout";
import {
  directRuleCoversDomain,
  domainsAndAddressesToDirectRules
} from "../directRuleDomains";
import type {
  AgentConfigSummary,
  AgentState,
  DnsResolutionRecord,
  OverviewCardKey,
  OverviewDragGhost,
  TrafficBaseline,
  TrafficHourBucket
} from "../types";

const props = defineProps<{
  summary: AgentConfigSummary;
  agent: AgentState;
  traffic: {
    baseline: TrafficBaseline | null;
    hourly_buckets: TrafficHourBucket[];
    download_bps: number;
    upload_bps: number;
    day_download_bytes: number;
    day_upload_bytes: number;
  };
  recentDnsRecords: DnsResolutionRecord[];
  proxyEntryStateLabel: string;
  activeForwardingLabel: string;
  directModeLabel: string;
  dnsCardLabel: string;
  agentRunning: boolean;
}>();

const emit = defineEmits<{
  "add-direct-rules": [rules: string[]];
}>();

const overviewCardOrder = ref(readOverviewCardOrder());
const draggingOverviewCard = ref<OverviewCardKey | null>(null);
const dragOverOverviewCard = ref<OverviewCardKey | null>(null);
const overviewDragGhost = ref<OverviewDragGhost | null>(null);
const selectedDnsDomains = ref<string[]>([]);
const dnsRecordListElement = ref<HTMLElement | null>(null);
const displayedDnsRecords = ref<DnsResolutionRecord[]>([]);
const latestDnsRecords = ref<DnsResolutionRecord[]>([]);
const pendingDnsRecordCount = ref(0);
const dnsListHovered = ref(false);
const dnsListFocused = ref(false);

const overviewCards = computed(() => buildOverviewCards(overviewCardOrder.value));
const speedGaugeMax = computed(() => Math.max(256 * 1024, props.traffic.download_bps, props.traffic.upload_bps) * 1.25);
const downloadGaugeValue = computed(() => Math.round((props.traffic.download_bps / speedGaugeMax.value) * 100));
const uploadGaugeValue = computed(() => Math.round((props.traffic.upload_bps / speedGaugeMax.value) * 100));
const transportModeLabel = computed(() => {
  if (props.summary.transport_mode === "auto") return "自动：加密 UDP → TCP";
  return props.summary.transport_mode === "udp" ? "TCP + 加密 UDP" : "全 TCP";
});
const hourlyTrafficMax = computed(() =>
  Math.max(
    1,
    ...props.traffic.hourly_buckets.map((bucket) => bucket.download_bytes + bucket.upload_bytes)
  )
);
const selectedDnsDomainKeys = computed(
  () => new Set(selectedDnsDomains.value.map((domain) => domain.toLowerCase()))
);
const selectedDnsRules = computed(() => {
  const addresses = displayedDnsRecords.value
    .filter((record) => selectedDnsDomainKeys.value.has(dnsRecordDomain(record).toLowerCase()))
    .flatMap(dnsAnswers);
  return domainsAndAddressesToDirectRules(selectedDnsDomains.value, addresses);
});
const selectableDnsDomains = computed(() => {
  const domains = new Map<string, string>();
  displayedDnsRecords.value.forEach((record) => {
    const domain = dnsRecordDomain(record);
    const key = domain.toLowerCase();
    if (domain && !dnsDomainIsDirect(record) && !domains.has(key)) {
      domains.set(key, domain);
    }
  });
  return [...domains.values()];
});
const allSelectableDnsSelected = computed(
  () =>
    selectableDnsDomains.value.length > 0 &&
    selectableDnsDomains.value.every((domain) => selectedDnsDomainKeys.value.has(domain.toLowerCase()))
);
const selectedDnsActionLabel = computed(() => {
  return props.agentRunning ? "添加并重启" : "添加";
});

watch(
  () => props.recentDnsRecords,
  (records) => {
    latestDnsRecords.value = [...records];
    if (shouldFreezeDnsRecords()) {
      pendingDnsRecordCount.value = countNewDnsRecords(records, displayedDnsRecords.value);
      return;
    }
    applyLatestDnsRecords();
  },
  { immediate: true }
);

onBeforeUnmount(() => {
  resetOverviewMouseDrag();
});

function overviewCardTitle(key: OverviewCardKey) {
  const titles: Record<OverviewCardKey, string> = {
    status: "运行状态",
    proxy: "HTTP / SOCKS5",
    egress: "公共远端出口",
    speed: "实时网速",
    traffic: "今日流量",
    dns: "代理 DNS",
    tun: "TUN",
    policy: "共享策略"
  };
  return titles[key];
}

function overviewCardSubtitle(key: OverviewCardKey) {
  if (key === "status") {
    return props.agent.binary_path ? shortPath(props.agent.binary_path) : "桌面代理";
  }
  return "";
}

function onOverviewMouseDown(event: MouseEvent, key: OverviewCardKey) {
  if (event.button !== 0) {
    return;
  }
  if (event.target instanceof Element && event.target.closest("input, textarea, select, a, button:not(.overview-drag-handle)")) {
    return;
  }
  event.preventDefault();
  document.body.classList.add("overview-dragging");
  draggingOverviewCard.value = key;
  dragOverOverviewCard.value = null;
  const cardElement =
    event.currentTarget instanceof HTMLElement
      ? event.currentTarget
      : document.querySelector<HTMLElement>(`[data-overview-card="${key}"]`);
  const cardBox = cardElement?.getBoundingClientRect();
  if (cardBox) {
    overviewDragGhost.value = {
      x: cardBox.left,
      y: cardBox.top,
      width: cardBox.width,
      height: cardBox.height,
      offsetX: event.clientX - cardBox.left,
      offsetY: event.clientY - cardBox.top
    };
  }

  window.addEventListener("mousemove", onOverviewMouseMove);
  window.addEventListener("mouseup", onOverviewMouseUp, { once: true });
}

function onOverviewMouseMove(event: MouseEvent) {
  if (!draggingOverviewCard.value) {
    return;
  }

  if (overviewDragGhost.value) {
    overviewDragGhost.value.x = event.clientX - overviewDragGhost.value.offsetX;
    overviewDragGhost.value.y = event.clientY - overviewDragGhost.value.offsetY;
  }

  const targetKey = overviewCardKeyFromPoint(event.clientX, event.clientY);
  if (!targetKey || targetKey === draggingOverviewCard.value) {
    dragOverOverviewCard.value = null;
    return;
  }

  dragOverOverviewCard.value = targetKey;
  moveOverviewCard(
    draggingOverviewCard.value,
    targetKey,
    overviewDropPlacement(event.clientX, event.clientY, targetKey)
  );
}

function onOverviewMouseUp(event: MouseEvent) {
  const source = draggingOverviewCard.value;
  const target = overviewCardKeyFromPoint(event.clientX, event.clientY);
  if (source && target && source !== target) {
    moveOverviewCard(source, target, overviewDropPlacement(event.clientX, event.clientY, target));
  }
  resetOverviewMouseDrag();
}

function overviewCardKeyFromPoint(x: number, y: number) {
  const element = document.elementFromPoint(x, y);
  const card = element instanceof Element ? element.closest<HTMLElement>("[data-overview-card]") : null;
  const key = card?.dataset.overviewCard as OverviewCardKey | undefined;
  return key && overviewCardByKey.has(key) ? key : null;
}

function overviewDropPlacement(x: number, y: number, targetKey: OverviewCardKey): "before" | "after" {
  const target = document.querySelector<HTMLElement>(`[data-overview-card="${targetKey}"]`);
  let placement: "before" | "after" = "before";
  if (target) {
    const box = target.getBoundingClientRect();
    const pastVerticalMidpoint = y > box.top + box.height / 2;
    const pastHorizontalMidpoint = x > box.left + box.width / 2;
    placement = pastVerticalMidpoint || pastHorizontalMidpoint ? "after" : "before";
  }
  return placement;
}

function resetOverviewMouseDrag() {
  window.removeEventListener("mousemove", onOverviewMouseMove);
  window.removeEventListener("mouseup", onOverviewMouseUp);
  document.body.classList.remove("overview-dragging");
  draggingOverviewCard.value = null;
  dragOverOverviewCard.value = null;
  overviewDragGhost.value = null;
}

function moveOverviewCard(source: OverviewCardKey, target: OverviewCardKey, placement: "before" | "after") {
  const next = [...overviewCardOrder.value];
  const sourceIndex = next.indexOf(source);
  if (sourceIndex === -1) {
    return;
  }
  next.splice(sourceIndex, 1);
  const targetIndex = next.indexOf(target);
  if (targetIndex === -1) {
    return;
  }
  next.splice(placement === "after" ? targetIndex + 1 : targetIndex, 0, source);
  overviewCardOrder.value = normalizeOverviewCardOrder(next);
  saveOverviewCardOrder(overviewCardOrder.value);
}

function hourlyBarHeight(bytes: number) {
  if (bytes <= 0) {
    return "3px";
  }
  return `${Math.max(5, (bytes / hourlyTrafficMax.value) * 100)}%`;
}

function dnsRecordDomain(record: DnsResolutionRecord) {
  return record.query.trim().replace(/\.$/, "");
}

function dnsDomainIsDirect(record: DnsResolutionRecord) {
  const domain = dnsRecordDomain(record);
  return props.summary.direct_rules.some((rule) => directRuleCoversDomain(rule, domain));
}

function dnsDomainIsSelected(record: DnsResolutionRecord) {
  return selectedDnsDomainKeys.value.has(dnsRecordDomain(record).toLowerCase());
}

function toggleDnsDomainSelection(record: DnsResolutionRecord) {
  const domain = dnsRecordDomain(record);
  const key = domain.toLowerCase();
  if (!domain || dnsDomainIsDirect(record)) {
    return;
  }
  selectedDnsDomains.value = selectedDnsDomainKeys.value.has(key)
    ? selectedDnsDomains.value.filter((item) => item.toLowerCase() !== key)
    : [...selectedDnsDomains.value, domain];
}

function toggleAllSelectableDnsDomains() {
  selectedDnsDomains.value = allSelectableDnsSelected.value ? [] : [...selectableDnsDomains.value];
}

function addSelectedDnsDomainsToDirectRules() {
  if (!selectedDnsRules.value.length) {
    return;
  }
  emit("add-direct-rules", [...selectedDnsRules.value]);
  selectedDnsDomains.value = [];
}

function dnsRecordKey(record: DnsResolutionRecord) {
  return `${record.timestamp_ms}-${record.client}-${record.query}-${record.record_type}`;
}

function dnsStatusLabel(status: string) {
  if (status === "NOERROR") return "成功";
  if (status === "NXDOMAIN") return "不存在";
  if (status === "TIMEOUT") return "超时";
  return status;
}

function countNewDnsRecords(incoming: DnsResolutionRecord[], displayed: DnsResolutionRecord[]) {
  const displayedKeys = new Set(displayed.map(dnsRecordKey));
  return incoming.filter((record) => !displayedKeys.has(dnsRecordKey(record))).length;
}

function shouldFreezeDnsRecords() {
  return (
    dnsListHovered.value ||
    dnsListFocused.value ||
    selectedDnsDomains.value.length > 0 ||
    (dnsRecordListElement.value?.scrollTop ?? 0) > 4
  );
}

function applyLatestDnsRecords() {
  displayedDnsRecords.value = [...latestDnsRecords.value];
  pendingDnsRecordCount.value = 0;
}

function maybeApplyLatestDnsRecords() {
  if (!shouldFreezeDnsRecords()) {
    applyLatestDnsRecords();
  }
}

function onDnsListScroll() {
  maybeApplyLatestDnsRecords();
}

function onDnsListMouseEnter() {
  dnsListHovered.value = true;
}

function onDnsListMouseLeave() {
  dnsListHovered.value = false;
  maybeApplyLatestDnsRecords();
}

function onDnsListFocusOut(event: FocusEvent) {
  const nextTarget = event.relatedTarget;
  if (!(nextTarget instanceof Node) || !dnsRecordListElement.value?.contains(nextTarget)) {
    dnsListFocused.value = false;
    maybeApplyLatestDnsRecords();
  }
}
</script>

<template>
  <div class="content-grid overview-grid">
    <Card
      v-for="card in overviewCards"
      :key="card.key"
      :class="[
        'panel',
        'overview-card',
        {
          dragging: draggingOverviewCard === card.key,
          'drop-target': dragOverOverviewCard === card.key
        }
      ]"
      :style="{ gridColumn: 'span ' + card.span }"
      :data-overview-card="card.key"
      @mousedown="onOverviewMouseDown($event, card.key)"
    >
      <template #title>
        <div class="panel-heading inline overview-card-heading">
          <div class="overview-card-title">
            <h2>{{ overviewCardTitle(card.key) }}</h2>
            <p v-if="overviewCardSubtitle(card.key)">{{ overviewCardSubtitle(card.key) }}</p>
          </div>
          <div class="overview-card-actions">
            <Badge
              v-if="card.key === 'status'"
              :value="agent.running ? '运行中' : '空闲'"
              :severity="agent.running ? 'success' : 'secondary'"
            />
            <Tag v-else-if="card.key === 'proxy'" :value="proxyEntryStateLabel" severity="success" />
            <Tag
              v-else-if="card.key === 'egress'"
              :value="transportModeLabel"
              severity="info"
            />
            <Tag v-else-if="card.key === 'speed'" value="系统" severity="info" />
            <span v-else-if="card.key === 'traffic'">{{ traffic.baseline?.date ?? localDateKey() }}</span>
            <Tag v-else-if="card.key === 'dns'" :value="dnsCardLabel" :severity="summary.tun_proxy_dns ? 'info' : 'secondary'" />
            <Tag
              v-else-if="card.key === 'tun'"
              :value="summary.tun_enabled ? '已启用' : '未启用'"
              :severity="summary.tun_enabled ? 'success' : 'secondary'"
            />
            <Tag v-else-if="card.key === 'policy'" :value="directModeLabel" severity="info" />
            <button
              type="button"
              class="overview-drag-handle"
              aria-label="拖动调整顺序"
              title="拖动调整顺序"
            >
              <AppIcon name="move" />
            </button>
          </div>
        </div>
      </template>
      <template #content>
        <div v-if="card.key === 'status'" class="status-board">
          <div class="metric-tile">
            <AppIcon name="network" />
            <span>当前转发</span>
            <strong>{{ activeForwardingLabel }}</strong>
          </div>
          <div class="metric-tile">
            <AppIcon name="globe" />
            <span>代理入口</span>
            <strong>{{ summary.listen_addr }}</strong>
          </div>
          <div class="metric-tile">
            <AppIcon name="server" />
            <span>公共出口</span>
            <strong>{{ summary.proxy_addrs.length }}</strong>
          </div>
          <div class="metric-tile">
            <AppIcon name="activity" />
            <span>传输策略</span>
            <strong>{{ transportModeLabel }}</strong>
          </div>
          <div class="metric-tile">
            <AppIcon name="package" />
            <span>压缩</span>
            <strong>{{ summary.compression_mode }}</strong>
          </div>
          <div class="metric-tile">
            <AppIcon name="scroll-text" />
            <span>日志</span>
            <strong>{{ summary.log_level }}</strong>
          </div>
        </div>
        <div v-else-if="card.key === 'proxy'" class="kv-list">
          <div class="kv-row"><span>监听</span><strong>{{ summary.listen_addr }}</strong></div>
          <div class="kv-row"><span>协议</span><strong>HTTP / SOCKS5</strong></div>
          <div class="kv-row"><span>公共出口</span><strong>{{ summary.proxy_addrs.length }} 个节点</strong></div>
        </div>
        <div v-else-if="card.key === 'egress'" class="endpoint-list">
          <div v-for="proxy in summary.proxy_addrs" :key="proxy" class="endpoint-row">
            <AppIcon name="server" />
            <span>{{ proxy }}</span>
          </div>
          <div v-if="!summary.proxy_addrs.length" class="endpoint-row muted">
            <AppIcon name="server" />
            <span>未配置</span>
          </div>
        </div>
        <div v-else-if="card.key === 'speed'" class="speed-gauges">
          <div class="speed-gauge">
            <Knob
              :model-value="downloadGaugeValue"
              :size="132"
              readonly
              value-color="var(--gauge-download)"
              range-color="var(--gauge-download-track)"
              text-color="var(--app-text-strong)"
            />
            <span>下载</span>
            <strong>{{ formatRate(traffic.download_bps) }}</strong>
          </div>
          <div class="speed-gauge">
            <Knob
              :model-value="uploadGaugeValue"
              :size="132"
              readonly
              value-color="var(--gauge-upload)"
              range-color="var(--gauge-upload-track)"
              text-color="var(--app-text-strong)"
            />
            <span>上传</span>
            <strong>{{ formatRate(traffic.upload_bps) }}</strong>
          </div>
        </div>
        <div v-else-if="card.key === 'traffic'" class="hourly-chart">
          <div class="hourly-totals">
            <Tag :value="`下载 ${formatBytes(traffic.day_download_bytes)}`" severity="info" rounded />
            <Tag :value="`上传 ${formatBytes(traffic.day_upload_bytes)}`" severity="success" rounded />
          </div>

          <div class="hourly-bars">
            <div v-for="bucket in traffic.hourly_buckets" :key="bucket.hour" class="hourly-column">
              <div class="hourly-stack" :title="`${bucket.hour}:00 下载 ${formatBytes(bucket.download_bytes)} / 上传 ${formatBytes(bucket.upload_bytes)}`">
                <div class="hourly-segment total" :style="{ height: hourlyBarHeight(bucket.download_bytes + bucket.upload_bytes) }"></div>
              </div>
              <span>{{ hourLabel(bucket.hour) }}</span>
            </div>
          </div>

          <div class="hourly-legend">
            <span><i class="legend-dot total"></i>每小时合计</span>
            <span><i class="legend-dot idle"></i>空闲小时</span>
          </div>
        </div>
        <div v-else-if="card.key === 'dns'" class="dns-records">
          <div v-if="!summary.tun_proxy_dns" class="dns-empty">
            <AppIcon name="info" />
            <span>代理 DNS 未启用</span>
          </div>
          <div v-else-if="!displayedDnsRecords.length" class="dns-empty">
            <AppIcon name="globe" />
            <span>等待经过代理的 DNS 请求</span>
          </div>
          <div v-else class="dns-record-content">
            <div class="dns-selection-toolbar">
              <span>
                已选 {{ selectedDnsDomains.length }} · 生成 {{ selectedDnsRules.length }} 条
                <em v-if="pendingDnsRecordCount"> · {{ pendingDnsRecordCount }} 条新记录待更新</em>
              </span>
              <Button
                :label="allSelectableDnsSelected ? '清空' : '全选'"
                severity="secondary"
                size="small"
                :disabled="!selectableDnsDomains.length"
                @click="toggleAllSelectableDnsDomains"
              />
              <Button
                :label="selectedDnsActionLabel"
                size="small"
                :disabled="!selectedDnsDomains.length"
                @click="addSelectedDnsDomainsToDirectRules"
              />
            </div>
            <div class="dns-record-frame">
              <div
                ref="dnsRecordListElement"
                class="dns-record-list"
                @scroll.passive="onDnsListScroll"
                @mouseenter="onDnsListMouseEnter"
                @mouseleave="onDnsListMouseLeave"
                @focusin="dnsListFocused = true"
                @focusout="onDnsListFocusOut"
              >
                <div
                  v-for="record in displayedDnsRecords"
                  :key="`${record.timestamp_ms}-${record.client}-${record.query}`"
                  :class="[
                    'dns-record-row',
                    'interactive',
                    {
                      selected: dnsDomainIsSelected(record),
                      direct: dnsDomainIsDirect(record)
                    }
                  ]"
                  role="checkbox"
                  :aria-checked="dnsDomainIsSelected(record)"
                  :aria-disabled="dnsDomainIsDirect(record)"
                  :tabindex="dnsDomainIsDirect(record) ? -1 : 0"
                  :title="dnsDomainIsDirect(record) ? '该域名已在直连规则中' : '点击选择该域名'"
                  @mousedown.stop
                  @click="toggleDnsDomainSelection(record)"
                  @keydown.enter.prevent="toggleDnsDomainSelection(record)"
                  @keydown.space.prevent="toggleDnsDomainSelection(record)"
                >
                  <input
                    class="dns-record-checkbox"
                    type="checkbox"
                    :checked="dnsDomainIsSelected(record)"
                    :disabled="dnsDomainIsDirect(record)"
                    tabindex="-1"
                    aria-hidden="true"
                    @click.stop
                    @change="toggleDnsDomainSelection(record)"
                  />
                  <div class="dns-record-main">
                    <strong :title="record.query">{{ record.query }}</strong>
                    <span :title="dnsAnswers(record).join(', ')">{{ dnsAnswerLabel(record) }}</span>
                  </div>
                  <div class="dns-record-meta">
                    <div class="dns-record-tags">
                      <Tag
                        v-if="dnsDomainIsDirect(record)"
                        value="已直连"
                        severity="info"
                        rounded
                      />
                      <Tag
                        v-if="isAgentDnsCacheRecord(record)"
                        value="缓存命中"
                        severity="success"
                        rounded
                        title="该 DNS 响应来自代理内部 DNS cache，未重新请求上游 DNS"
                      />
                      <Tag
                        v-if="isAgentDirectDnsRecord(record)"
                        value="直连解析"
                        severity="info"
                        rounded
                      />
                      <Tag
                        v-if="isSystemDnsRecord(record)"
                        value="系统 DNS"
                        severity="warn"
                        rounded
                        title="该请求绕过了代理内部 DNS，由代理所在机器的系统解析"
                      />
                      <Tag :value="record.record_type" severity="secondary" rounded />
                    </div>
                    <div class="dns-record-result">
                      <span :class="['dns-status', record.status === 'NOERROR' ? 'ok' : 'warn']">{{ dnsStatusLabel(record.status) }}</span>
                      <span>· {{ Math.max(1, Math.round(record.duration_ms)) }} ms</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div v-else-if="card.key === 'tun'" class="kv-list">
          <div class="kv-row"><span>设备</span><strong>{{ summary.tun_name }}</strong></div>
          <div class="kv-row"><span>地址</span><strong>{{ summary.tun_ipv4 }}</strong></div>
          <div class="kv-row">
            <span>MTU</span>
            <strong>{{ summary.tun_mtu }}</strong>
          </div>
          <div class="kv-row"><span>普通 UDP</span><strong>{{ summary.tun_proxy_udp ? "按规则分流" : "Agent 直连" }}</strong></div>
          <div class="kv-row"><span>QUIC 应用流量</span><strong>{{ summary.tun_quic_policy === "block" ? "全部阻断" : summary.transport_mode === "auto" ? "直连或自动回退代理" : summary.transport_mode === "udp" ? "直连或经加密 UDP 代理" : "直连或经 TCP 代理" }}</strong></div>
          <div class="kv-row"><span>DNS</span><strong>{{ summary.tun_proxy_dns ? "经 Proxy 解析" : "系统解析" }}</strong></div>
        </div>
        <div v-else-if="card.key === 'policy'" class="kv-list">
          <div class="kv-row"><span>服务对象</span><strong>代理入口与 TUN 模式</strong></div>
          <div class="kv-row"><span>规则</span><strong>{{ summary.direct_rules.length }} 条</strong></div>
        </div>
      </template>
    </Card>

    <div
      v-if="draggingOverviewCard && overviewDragGhost"
      class="overview-drag-ghost"
      :style="{
        left: `${overviewDragGhost.x}px`,
        top: `${overviewDragGhost.y}px`,
        width: `${overviewDragGhost.width}px`,
        height: `${overviewDragGhost.height}px`
      }"
    >
      <div class="overview-drag-ghost-heading">
        <strong>{{ overviewCardTitle(draggingOverviewCard) }}</strong>
        <AppIcon name="move" />
      </div>
      <div class="overview-drag-ghost-lines" aria-hidden="true">
        <span></span>
        <span></span>
        <span></span>
      </div>
    </div>
  </div>
</template>
