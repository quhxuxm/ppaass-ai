import { computed, ref, watch } from "vue";
import {
  dnsAnswerLabel,
  dnsAnswers,
  dnsRecordMatchesFilter,
  formatBytes,
  formatRate,
  hourLabel,
  isAgentDnsCacheRecord,
  isAgentDirectDnsRecord,
  isSystemDnsRecord,
  localDateKey
} from "../formatters";
import {
  directRuleCoversDomain,
  directRulesMatchingDomainsAndAddresses,
  selectedDomainsToNewDirectRules
} from "../directRuleDomains";
import type {
  AgentConfigSummary,
  AgentState,
  DnsResolutionRecord,
  TrafficBaseline,
  TrafficHourBucket
} from "../types";
import { useOverviewCardDrag } from "./useOverviewCardDrag";

export interface OverviewViewProps {
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
}

export type OverviewViewEmit = {
  (event: "add-direct-rules", rules: string[]): void;
  (event: "remove-direct-rules", rules: string[]): void;
};

export function useOverviewView(
  props: OverviewViewProps,
  emit: OverviewViewEmit
) {
  const overviewDrag = useOverviewCardDrag(props);
  const selectedDnsDomains = ref<string[]>([]);
  const dnsRecordListElement = ref<HTMLElement | null>(null);
  const displayedDnsRecords = ref<DnsResolutionRecord[]>([]);
  const latestDnsRecords = ref<DnsResolutionRecord[]>([]);
  const pendingDnsRecordCount = ref(0);
  const dnsListFocused = ref(false);
  const dnsFilterQuery = ref("");
  
  const speedGaugeMax = computed(() => Math.max(256 * 1024, props.traffic.download_bps, props.traffic.upload_bps) * 1.25);
  const downloadGaugeValue = computed(() => Math.round((props.traffic.download_bps / speedGaugeMax.value) * 100));
  const uploadGaugeValue = computed(() => Math.round((props.traffic.upload_bps / speedGaugeMax.value) * 100));
  const transportModeLabel = computed(() => {
    if (props.summary.transport_mode === "auto") return "自动：加密 UDP → TCP";
    return props.summary.transport_mode === "udp" ? "TCP + 加密 UDP" : "全 TCP";
  });
  const hourlyTrafficMax = computed(() =>
    Math.max(1, ...props.traffic.hourly_buckets.flatMap((bucket) => [bucket.download_bytes, bucket.upload_bytes]))
  );
  const downloadTrendPoints = computed(() => hourlyTrendPoints("download_bytes"));
  const uploadTrendPoints = computed(() => hourlyTrendPoints("upload_bytes"));
  const downloadAreaPath = computed(() => hourlyAreaPath(downloadTrendPoints.value));
  const uploadAreaPath = computed(() => hourlyAreaPath(uploadTrendPoints.value));
  const selectedDnsDomainKeys = computed(
    () => new Set(selectedDnsDomains.value.map((domain) => domain.toLowerCase()))
  );
  const filteredDnsRecords = computed(() =>
    displayedDnsRecords.value.filter((record) =>
      dnsRecordMatchesFilter(
        record,
        dnsFilterQuery.value,
        dnsDomainIsDirect(record) ? ["已直连 direct"] : []
      )
    )
  );
  const selectableDnsDomains = computed(() => {
    const domains = new Map<string, string>();
    filteredDnsRecords.value.forEach((record) => {
      const domain = dnsRecordDomain(record);
      const key = domain.toLowerCase();
      if (domain && !domains.has(key)) {
        domains.set(key, domain);
      }
    });
    return [...domains.values()];
  });
  const selectedDnsRecords = computed(() =>
    displayedDnsRecords.value.filter((record) =>
      selectedDnsDomainKeys.value.has(dnsRecordDomain(record).toLowerCase())
    )
  );
  const selectedDnsRulesToAdd = computed(() => {
    const addresses = selectedDnsRecords.value
      .filter((record) => !dnsDomainIsDirect(record))
      .flatMap(dnsAnswers);
    return selectedDomainsToNewDirectRules(
      selectedDnsDomains.value,
      addresses,
      props.summary.direct_rules
    );
  });
  const selectedDnsRulesToRemove = computed(() => {
    const addresses = selectedDnsRecords.value.flatMap(dnsAnswers);
    return directRulesMatchingDomainsAndAddresses(
      props.summary.direct_rules,
      selectedDnsDomains.value,
      addresses
    );
  });
  const allSelectableDnsSelected = computed(
    () =>
      selectableDnsDomains.value.length > 0 &&
      selectableDnsDomains.value.every((domain) => selectedDnsDomainKeys.value.has(domain.toLowerCase()))
  );
  const selectedDnsActionLabel = computed(() => {
    return props.agentRunning ? "添加并重启" : "添加";
  });
  const selectedDnsRemoveActionLabel = computed(() => {
    return props.agentRunning ? "移出并重启" : "移出";
  });
  const selectAllDnsLabel = computed(() => {
    if (!dnsFilterQuery.value.trim()) {
      return allSelectableDnsSelected.value ? "清空" : "全选";
    }
    return allSelectableDnsSelected.value ? "取消结果" : "全选结果";
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
  
  function hourlyTrendPoints(field: "download_bytes" | "upload_bytes") {
    return props.traffic.hourly_buckets.map((bucket, index) => ({
      x: 18 + (index / 23) * 684,
      y: 154 - (bucket[field] / hourlyTrafficMax.value) * 132,
      bucket
    }));
  }
  
  function hourlyAreaPath(points: Array<{ x: number; y: number }>) {
    if (!points.length) return "";
    return `M ${points[0].x} 154 L ${points.map((point) => `${point.x} ${point.y}`).join(" L ")} L ${points.at(-1)?.x ?? 702} 154 Z`;
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
    if (!domain) {
      return;
    }
    selectedDnsDomains.value = selectedDnsDomainKeys.value.has(key)
      ? selectedDnsDomains.value.filter((item) => item.toLowerCase() !== key)
      : [...selectedDnsDomains.value, domain];
  }
  
  function toggleAllSelectableDnsDomains() {
    const visibleDomainKeys = new Set(
      selectableDnsDomains.value.map((domain) => domain.toLowerCase())
    );
    if (allSelectableDnsSelected.value) {
      selectedDnsDomains.value = selectedDnsDomains.value.filter(
        (domain) => !visibleDomainKeys.has(domain.toLowerCase())
      );
      return;
    }
  
    const nextDomains = new Map(
      selectedDnsDomains.value.map((domain) => [domain.toLowerCase(), domain])
    );
    selectableDnsDomains.value.forEach((domain) => {
      nextDomains.set(domain.toLowerCase(), domain);
    });
    selectedDnsDomains.value = [...nextDomains.values()];
  }
  
  function addSelectedDnsDomainsToDirectRules() {
    if (!selectedDnsRulesToAdd.value.length) {
      return;
    }
    const rules = [...selectedDnsRulesToAdd.value];
    selectedDnsDomains.value = [];
    emit("add-direct-rules", rules);
  }
  
  function removeSelectedDnsDomainsFromDirectRules() {
    if (!selectedDnsRulesToRemove.value.length) {
      return;
    }
    const rules = [...selectedDnsRulesToRemove.value];
    selectedDnsDomains.value = [];
    emit("remove-direct-rules", rules);
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
  
  function onDnsListFocusOut(event: FocusEvent) {
    const nextTarget = event.relatedTarget;
    if (!(nextTarget instanceof Node) || !dnsRecordListElement.value?.contains(nextTarget)) {
      dnsListFocused.value = false;
      maybeApplyLatestDnsRecords();
    }
  }

  return {
    ...overviewDrag,
    selectedDnsDomains,
    dnsRecordListElement,
    displayedDnsRecords,
    pendingDnsRecordCount,
    dnsListFocused,
    dnsFilterQuery,
    speedGaugeMax,
    downloadGaugeValue,
    uploadGaugeValue,
    transportModeLabel,
    hourlyTrafficMax,
    downloadTrendPoints,
    uploadTrendPoints,
    downloadAreaPath,
    uploadAreaPath,
    filteredDnsRecords,
    selectableDnsDomains,
    selectedDnsRulesToAdd,
    selectedDnsRulesToRemove,
    allSelectableDnsSelected,
    selectedDnsActionLabel,
    selectedDnsRemoveActionLabel,
    selectAllDnsLabel,
    dnsRecordDomain,
    dnsDomainIsDirect,
    dnsDomainIsSelected,
    toggleDnsDomainSelection,
    toggleAllSelectableDnsDomains,
    addSelectedDnsDomainsToDirectRules,
    removeSelectedDnsDomainsFromDirectRules,
    dnsRecordKey,
    dnsStatusLabel,
    applyLatestDnsRecords,
    onDnsListScroll,
    onDnsListFocusOut,
    dnsAnswerLabel,
    dnsAnswers,
    formatBytes,
    formatRate,
    hourLabel,
    isAgentDnsCacheRecord,
    isAgentDirectDnsRecord,
    isSystemDnsRecord,
    localDateKey
  };
}
