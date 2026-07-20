import type { ConnectivityCheck, DnsResolutionRecord } from "./types";

export function delay(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export function shortPath(path?: string | null) {
  if (!path) {
    return "—";
  }
  const normalized = path.replaceAll("\\", "/");
  const parts = normalized.split("/");
  if (parts.length <= 2) {
    return normalized;
  }
  return `${parts.at(-2)}/${parts.at(-1)}`;
}

export function shortProxyUrl(value: string) {
  return value.replace(/^https?:\/\//, "").replace(/^socks5h:\/\//, "socks5h ").replace(/^tun:\/\//, "tun ");
}

export function connectivityResultLabel(result: Pick<ConnectivityCheck, "http_code" | "success">) {
  if (result.http_code != null) {
    return String(result.http_code);
  }
  return result.success ? "通过" : "失败";
}

export function dnsAnswerLabel(record: DnsResolutionRecord) {
  const answers = dnsAnswers(record);
  if (answers.length) {
    return answers.slice(0, 3).join(", ");
  }
  if (record.status === "NOERROR") {
    return "无返回记录";
  }
  if (record.status === "TIMEOUT") {
    return "解析超时";
  }
  return record.upstream;
}

export function dnsAnswers(record: DnsResolutionRecord) {
  return Array.isArray(record.answers) ? record.answers : [];
}

export function normalizeDnsRecords(records: unknown): DnsResolutionRecord[] {
  if (!Array.isArray(records)) {
    return [];
  }
  return records.filter((record): record is DnsResolutionRecord => Boolean(record && typeof record === "object"));
}

export function isAgentDnsRecord(record: DnsResolutionRecord) {
  return !record.resolver || record.resolver === "agent";
}

export function isAgentDnsCacheRecord(record: DnsResolutionRecord) {
  return record.resolver === "agent-cache";
}

export function isAgentDirectDnsRecord(record: DnsResolutionRecord) {
  return record.resolver === "agent-direct";
}

export function isAgentDnsCacheMissRecord(record: DnsResolutionRecord) {
  // 只有 Agent 内部 DNS 路径才有 cache 命中/未命中语义；系统解析绕过了 Agent cache。
  return isAgentDnsRecord(record) || isAgentDirectDnsRecord(record);
}

export function isSystemDnsRecord(record: DnsResolutionRecord) {
  return record.resolver === "system";
}

export function isAgentOrSystemDnsRecord(record: DnsResolutionRecord) {
  return (
    isAgentDnsRecord(record) ||
    isAgentDnsCacheRecord(record) ||
    isAgentDirectDnsRecord(record) ||
    isSystemDnsRecord(record)
  );
}

export function dnsRecordTimestamp(record: DnsResolutionRecord) {
  const timestamp = Number(record.timestamp_ms);
  return Number.isFinite(timestamp) ? timestamp : 0;
}

export function formatTimestamp(timestampMs: number) {
  if (!timestampMs) {
    return "—";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(timestampMs));
}

export function formatRate(bytesPerSecondValue: number) {
  return `${formatBytes(bytesPerSecondValue)}/s`;
}

export function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

export function hourLabel(hour: number) {
  if (hour === 0 || hour === 6 || hour === 12 || hour === 18 || hour === 23) {
    return String(hour).padStart(2, "0");
  }
  return "";
}

export function localDateKey() {
  const now = new Date();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${now.getFullYear()}-${month}-${day}`;
}

export function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
