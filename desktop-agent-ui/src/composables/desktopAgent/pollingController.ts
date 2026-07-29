import { fallbackTrafficSnapshot } from "../../fallbacks";
import {
  ensureTrafficBaseline,
  ensureTrafficHourlyStore,
  saveTrafficHourlyStore
} from "../../trafficStorage";
import type {
  DnsResolutionRecord,
  LoadedAgentConfig,
  NetworkTrafficSnapshot
} from "../../types";
import type { DesktopAgentModel } from "./model";
import { invokeOrFallback } from "./platform";

interface PollingDependencies {
  applyExternalConfig: (
    loaded: LoadedAgentConfig,
    notify: boolean
  ) => void;
  refreshAgentState: () => Promise<void>;
}

export function createPollingController(
  model: DesktopAgentModel,
  dependencies: PollingDependencies
) {
  const { state } = model;
  let trafficTimer: number | undefined;
  let agentTimer: number | undefined;
  let configTimer: number | undefined;
  let dnsTimer: number | undefined;
  let pollingActive = false;
  let trafficRefreshInFlight = false;
  let configRefreshInFlight = false;
  let dnsRefreshInFlight = false;

  function start() {
    pollingActive = true;
    void pollTraffic();
    void pollAgentState();
    void pollConfig();
    void pollDnsRecords();
  }

  function stop() {
    pollingActive = false;
    clearPollingTimer(trafficTimer);
    clearPollingTimer(agentTimer);
    clearPollingTimer(configTimer);
    clearPollingTimer(dnsTimer);
  }

  async function pollTraffic() {
    if (!pollingActive) {
      return;
    }
    if (!state.busy) {
      await refreshTraffic();
    }
    if (pollingActive) {
      trafficTimer = window.setTimeout(() => void pollTraffic(), 1000);
    }
  }

  async function refreshTraffic() {
    if (trafficRefreshInFlight) {
      return;
    }
    trafficRefreshInFlight = true;
    try {
      const snapshot = await invokeOrFallback<NetworkTrafficSnapshot>(
        "get_network_traffic_snapshot",
        {},
        fallbackTrafficSnapshot
      );
      updateTraffic(snapshot);
    } catch {
      // Keep the last visible telemetry sample if the OS counter read fails.
    } finally {
      trafficRefreshInFlight = false;
    }
  }

  async function pollAgentState() {
    if (!pollingActive) {
      return;
    }
    if (!state.busy) {
      await dependencies.refreshAgentState();
    }
    if (pollingActive) {
      agentTimer = window.setTimeout(
        () => void pollAgentState(),
        1200
      );
    }
  }

  async function pollConfig() {
    if (!pollingActive) {
      return;
    }
    if (!state.busy) {
      await refreshConfigFromDisk(false);
    }
    if (pollingActive) {
      configTimer = window.setTimeout(() => void pollConfig(), 1000);
    }
  }

  async function refreshConfigFromDisk(notify: boolean) {
    if (configRefreshInFlight || state.dirty || !state.config) {
      return;
    }
    configRefreshInFlight = true;
    try {
      const current = state.config;
      const loaded = await invokeOrFallback<LoadedAgentConfig>(
        "load_agent_config",
        { path: current.path },
        () => current
      );
      if (!state.config || state.dirty) {
        return;
      }
      if (
        loaded.path !== state.config.path ||
        loaded.raw !== state.config.raw
      ) {
        dependencies.applyExternalConfig(loaded, notify);
      }
    } catch {
      // External config refresh is best-effort.
    } finally {
      configRefreshInFlight = false;
    }
  }

  async function pollDnsRecords() {
    if (!pollingActive) {
      return;
    }
    if (!state.busy) {
      await refreshDnsRecords();
    }
    if (pollingActive) {
      dnsTimer = window.setTimeout(
        () => void pollDnsRecords(),
        2500
      );
    }
  }

  async function refreshDnsRecords() {
    if (dnsRefreshInFlight) {
      return;
    }
    dnsRefreshInFlight = true;
    try {
      const records = await invokeOrFallback<DnsResolutionRecord[]>(
        "get_dns_resolution_records",
        {},
        () => state.dnsRecords
      );
      if (Array.isArray(records)) {
        state.dnsRecords = records;
      }
    } catch {
      // Keep the last visible DNS records if the runtime status read fails.
    } finally {
      dnsRefreshInFlight = false;
    }
  }

  function updateTraffic(snapshot: NetworkTrafficSnapshot) {
    const previous = state.traffic.snapshot;
    state.traffic.previous = previous;
    state.traffic.snapshot = snapshot;
    if (previous && snapshot.sampled_at_ms > previous.sampled_at_ms) {
      const elapsedSeconds =
        (snapshot.sampled_at_ms - previous.sampled_at_ms) / 1000;
      state.traffic.download_bps = bytesPerSecond(
        snapshot.total_received_bytes,
        previous.total_received_bytes,
        elapsedSeconds
      );
      state.traffic.upload_bps = bytesPerSecond(
        snapshot.total_transmitted_bytes,
        previous.total_transmitted_bytes,
        elapsedSeconds
      );
    }
    state.traffic.baseline = ensureTrafficBaseline(snapshot);
    updateHourlyTraffic(snapshot);
  }

  function updateHourlyTraffic(snapshot: NetworkTrafficSnapshot) {
    const store = ensureTrafficHourlyStore(snapshot);
    const elapsedMs = snapshot.sampled_at_ms - store.last_sampled_at_ms;
    const currentHour = new Date().getHours();
    if (
      elapsedMs > 0 &&
      elapsedMs <= 90_000 &&
      snapshot.total_received_bytes >= store.last_received &&
      snapshot.total_transmitted_bytes >= store.last_transmitted
    ) {
      const bucket = store.buckets[currentHour];
      bucket.download_bytes +=
        snapshot.total_received_bytes - store.last_received;
      bucket.upload_bytes +=
        snapshot.total_transmitted_bytes - store.last_transmitted;
    }
    store.last_received = snapshot.total_received_bytes;
    store.last_transmitted = snapshot.total_transmitted_bytes;
    store.last_sampled_at_ms = snapshot.sampled_at_ms;
    saveTrafficHourlyStore(store);
    state.traffic.hourly_buckets = store.buckets.map((bucket) => ({
      ...bucket
    }));
    state.traffic.day_download_bytes = store.buckets.reduce(
      (total, bucket) => total + bucket.download_bytes,
      0
    );
    state.traffic.day_upload_bytes = store.buckets.reduce(
      (total, bucket) => total + bucket.upload_bytes,
      0
    );
  }

  return { refreshConfigFromDisk, start, stop };
}

function bytesPerSecond(
  current: number,
  previous: number,
  elapsedSeconds: number
) {
  if (elapsedSeconds <= 0 || current < previous) {
    return 0;
  }
  return Math.round((current - previous) / elapsedSeconds);
}

function clearPollingTimer(timer: number | undefined) {
  if (timer) {
    window.clearTimeout(timer);
  }
}
