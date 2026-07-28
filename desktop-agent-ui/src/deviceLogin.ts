import type { AgentDeviceLoginStatus } from "./types";

const MIN_POLL_SECONDS = 1;
const MAX_POLL_SECONDS = 120;

export function devicePollDelayMilliseconds(seconds: number): number {
  const normalized = Number.isFinite(seconds)
    ? Math.ceil(seconds)
    : MIN_POLL_SECONDS;
  return Math.min(MAX_POLL_SECONDS, Math.max(MIN_POLL_SECONDS, normalized)) * 1000;
}

export function deviceLoginRemainingSeconds(
  expiresAtSeconds: number,
  nowMilliseconds = Date.now()
): number {
  if (!Number.isFinite(expiresAtSeconds) || !Number.isFinite(nowMilliseconds)) {
    return 0;
  }
  return Math.max(0, Math.ceil(expiresAtSeconds - nowMilliseconds / 1000));
}

export function formatDeviceLoginCountdown(seconds: number): string {
  const normalized = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(normalized / 60);
  const remainder = normalized % 60;
  return `${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`;
}

export function deviceLoginStatusText(status: AgentDeviceLoginStatus): string {
  if (status === "slow_down") {
    return "认证服务繁忙，已自动放慢检查频率";
  }
  if (status === "authenticated") {
    return "授权成功，正在应用 Agent 凭据";
  }
  return "等待你在系统浏览器中确认";
}
