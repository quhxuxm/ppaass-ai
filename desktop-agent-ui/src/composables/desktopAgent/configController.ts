import { invoke } from "@tauri-apps/api/core";
import {
  applyFieldToToml,
  coerceField,
  redactManagedIdentityFromToml,
  summarizeRaw
} from "../../configToml";
import { loadFallbackConfig } from "../../fallbacks";
import { getErrorMessage, shortPath } from "../../formatters";
import type {
  AgentConfigSummary,
  LoadedAgentConfig,
  ToastKind
} from "../../types";
import { normalizeRules } from "./directRules";
import type { DesktopAgentModel } from "./model";
import { hasTauri, invokeOrFallback } from "./platform";

interface ConfigDependencies {
  canViewRawConfig: () => boolean;
  refreshAgentState: () => Promise<void>;
  showToast: (kind: ToastKind, message: string) => void;
}

export function createConfigController(
  model: DesktopAgentModel,
  dependencies: ConfigDependencies
) {
  const { state } = model;

  function applyExternalConfig(loaded: LoadedAgentConfig, notify: boolean) {
    if (!loaded?.summary) {
      return;
    }
    const enabled = loaded.summary.tun_enabled;
    const previousEnabled = state.config?.summary.tun_enabled;
    if (state.config && state.dirty) {
      state.config = {
        ...state.config,
        raw: dependencies.canViewRawConfig()
          ? applyFieldToToml(
              state.config.raw,
              "tun_enabled",
              enabled
            )
          : "",
        summary: {
          ...state.config.summary,
          tun_enabled: enabled
        }
      };
    } else {
      state.config = loaded;
      state.dirty = false;
    }
    state.diagnostics = null;
    if (notify && previousEnabled !== enabled) {
      dependencies.showToast(
        "success",
        `${enabled ? "已从系统菜单启用" : "已从系统菜单关闭"} TUN 模式${
          state.agent.running ? "，正在重启代理" : ""
        }`
      );
      void dependencies.refreshAgentState();
    }
  }

  async function boot() {
    try {
      state.config = await invokeOrFallback<LoadedAgentConfig>(
        "load_agent_config",
        {},
        loadFallbackConfig
      );
      await dependencies.refreshAgentState();
      state.statusText = "就绪";
    } catch (error) {
      state.statusText = "配置异常";
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.loading = false;
    }
  }

  async function reloadAll() {
    try {
      state.busy = true;
      const path = state.config?.path;
      state.config = await invokeOrFallback<LoadedAgentConfig>(
        "load_agent_config",
        path ? { path } : {},
        loadFallbackConfig
      );
      await dependencies.refreshAgentState();
      state.diagnostics = null;
      state.dirty = false;
      dependencies.showToast("success", "已重新载入");
    } catch (error) {
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function saveConfig() {
    if (!state.config || !ensureConfigEditable()) {
      return;
    }
    try {
      state.busy = true;
      await persistConfig();
      dependencies.showToast(
        "success",
        `已保存到 ${shortPath(state.config.path)}`
      );
    } catch (error) {
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function restoreDefaultConfig() {
    if (!state.config || !ensureConfigEditable()) {
      return;
    }
    if (!dependencies.canViewRawConfig()) {
      dependencies.showToast(
        "error",
        "当前账户没有查看原始配置的权限，无法恢复完整默认配置"
      );
      return;
    }
    if (!hasTauri()) {
      dependencies.showToast("error", "当前环境无法读取内置默认配置");
      return;
    }
    try {
      state.busy = true;
      state.config = await invoke<LoadedAgentConfig>(
        "load_default_agent_config",
        { path: state.config.path }
      );
      state.ruleDraft = "";
      state.diagnostics = null;
      state.dirty = true;
      dependencies.showToast("success", "已恢复默认配置，保存后生效");
    } catch (error) {
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  function setField(field: keyof AgentConfigSummary, value: unknown) {
    if (!state.config || !ensureConfigEditable(false)) {
      return;
    }
    const coerced = coerceField(field, value);
    (state.config.summary as Record<string, unknown>)[field] = coerced;
    if (field === "runtime_threads") {
      state.config.summary.effective_runtime_threads = Number(coerced);
    }
    if (dependencies.canViewRawConfig()) {
      state.config.raw = applyFieldToToml(
        state.config.raw,
        field,
        coerced
      );
    }
    state.diagnostics = null;
    state.dirty = true;
  }

  function setRawConfig(raw: string) {
    if (
      !state.config ||
      !dependencies.canViewRawConfig() ||
      !ensureConfigEditable(false)
    ) {
      return;
    }
    const editableRaw = redactManagedIdentityFromToml(raw);
    state.config.raw = editableRaw;
    try {
      state.config.summary = summarizeRaw(editableRaw);
    } catch {
      // Keep structured fields stable while the TOML text is mid-edit.
    }
    state.dirty = true;
  }

  async function persistConfig() {
    if (!state.config) {
      return;
    }
    const canViewRawConfig = dependencies.canViewRawConfig();
    state.config = await invokeOrFallback<LoadedAgentConfig>(
      canViewRawConfig
        ? "save_agent_config"
        : "save_agent_config_summary",
      canViewRawConfig
        ? { path: state.config.path, raw: state.config.raw }
        : { path: state.config.path, summary: state.config.summary },
      () => state.config as LoadedAgentConfig
    );
    state.dirty = false;
  }

  function updateDirectRules(
    rules: string[],
    allowWhileRunning = false
  ) {
    if (
      !state.config ||
      (!allowWhileRunning && !ensureConfigEditable(false))
    ) {
      return;
    }
    const directRules = normalizeRules(rules);
    state.config = {
      ...state.config,
      raw: dependencies.canViewRawConfig()
        ? applyFieldToToml(
            state.config.raw,
            "direct_rules",
            directRules
          )
        : "",
      summary: {
        ...state.config.summary,
        direct_rules: directRules
      }
    };
    state.diagnostics = null;
    state.dirty = true;
  }

  function ensureConfigEditable(notify = true) {
    if (!model.configLocked.value) {
      return true;
    }
    if (notify) {
      dependencies.showToast(
        "error",
        "代理运行中，停止后再修改配置"
      );
    }
    return false;
  }

  return {
    applyExternalConfig,
    boot,
    ensureConfigEditable,
    persistConfig,
    reloadAll,
    restoreDefaultConfig,
    saveConfig,
    setField,
    setRawConfig,
    updateDirectRules
  };
}

export type ConfigController = ReturnType<typeof createConfigController>;
