import { localDateKey } from "./formatters";
import type { NetworkTrafficSnapshot, TrafficBaseline, TrafficHourBucket, TrafficHourlyStore } from "./types";

const trafficBaselineKey = "ppaass-agent-ui:traffic-baseline:v1";
const trafficHourlyKey = "ppaass-agent-ui:traffic-hourly:v1";

export function emptyTrafficBuckets() {
  return Array.from({ length: 24 }, (_, hour) => ({
    hour,
    download_bytes: 0,
    upload_bytes: 0
  }));
}

export function ensureTrafficBaseline(snapshot: NetworkTrafficSnapshot) {
  const today = localDateKey();
  const saved = readTrafficBaseline();
  if (
    saved?.date === today &&
    saved.received <= snapshot.total_received_bytes &&
    saved.transmitted <= snapshot.total_transmitted_bytes
  ) {
    return saved;
  }

  const baseline = {
    date: today,
    received: snapshot.total_received_bytes,
    transmitted: snapshot.total_transmitted_bytes
  };
  localStorage.setItem(trafficBaselineKey, JSON.stringify(baseline));
  return baseline;
}

export function ensureTrafficHourlyStore(snapshot: NetworkTrafficSnapshot) {
  const today = localDateKey();
  const saved = readTrafficHourlyStore();
  if (
    saved?.date === today &&
    saved.last_received <= snapshot.total_received_bytes &&
    saved.last_transmitted <= snapshot.total_transmitted_bytes
  ) {
    return saved;
  }

  const store = {
    date: today,
    last_received: snapshot.total_received_bytes,
    last_transmitted: snapshot.total_transmitted_bytes,
    last_sampled_at_ms: snapshot.sampled_at_ms,
    buckets: emptyTrafficBuckets()
  };
  localStorage.setItem(trafficHourlyKey, JSON.stringify(store));
  return store;
}

export function saveTrafficHourlyStore(store: TrafficHourlyStore) {
  localStorage.setItem(trafficHourlyKey, JSON.stringify(store));
}

function readTrafficBaseline() {
  try {
    const raw = localStorage.getItem(trafficBaselineKey);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as TrafficBaseline;
    if (!parsed.date || !Number.isFinite(parsed.received) || !Number.isFinite(parsed.transmitted)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function readTrafficHourlyStore() {
  try {
    const raw = localStorage.getItem(trafficHourlyKey);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as TrafficHourlyStore;
    if (
      !parsed.date ||
      !Number.isFinite(parsed.last_received) ||
      !Number.isFinite(parsed.last_transmitted) ||
      !Number.isFinite(parsed.last_sampled_at_ms)
    ) {
      return null;
    }
    return {
      ...parsed,
      buckets: normalizeTrafficBuckets(parsed.buckets)
    };
  } catch {
    return null;
  }
}

function normalizeTrafficBuckets(buckets: TrafficHourBucket[]) {
  const next = emptyTrafficBuckets();
  for (const bucket of buckets ?? []) {
    if (!Number.isInteger(bucket.hour) || bucket.hour < 0 || bucket.hour > 23) {
      continue;
    }
    next[bucket.hour] = {
      hour: bucket.hour,
      download_bytes: Number.isFinite(bucket.download_bytes) ? Math.max(0, bucket.download_bytes) : 0,
      upload_bytes: Number.isFinite(bucket.upload_bytes) ? Math.max(0, bucket.upload_bytes) : 0
    };
  }
  return next;
}
