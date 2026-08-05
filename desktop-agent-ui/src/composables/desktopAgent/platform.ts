import { invoke } from "@tauri-apps/api/core";

export async function invokeOrFallback<T>(
  command: string,
  args: Record<string, unknown>,
  fallback: () => T
): Promise<T> {
  if (!hasTauri()) {
    return fallback();
  }
  return invoke<T>(command, args);
}

export function hasTauri() {
  return Boolean(
    (window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__
  );
}
