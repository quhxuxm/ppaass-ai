import { onBeforeUnmount, onMounted } from "vue";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { tabs } from "../constants";
import type {
  AgentState,
  LoadedAgentConfig,
  ToastKind
} from "../types";
import {
  createConfigController,
  type ConfigController
} from "./desktopAgent/configController";
import { createDirectRuleController } from "./desktopAgent/directRules";
import {
  guardIntegerBeforeInput,
  guardIntegerPaste,
  sanitizeIntegerInput
} from "./desktopAgent/integerInput";
import {
  createDesktopAgentModel,
  showToast
} from "./desktopAgent/model";
import { createPollingController } from "./desktopAgent/pollingController";
import { createRuntimeController } from "./desktopAgent/runtimeController";

export interface DesktopAgentAccess {
  canUsePacketCapture: () => boolean;
  canViewRawConfig: () => boolean;
}

const unrestrictedDesktopAgentAccess: DesktopAgentAccess = {
  canUsePacketCapture: () => true,
  canViewRawConfig: () => true
};

export function useDesktopAgent(
  access: DesktopAgentAccess = unrestrictedDesktopAgentAccess
) {
  const model = createDesktopAgentModel();
  const { state } = model;
  const notify = (kind: ToastKind, message: string) =>
    showToast(model, kind, message);

  let configController: ConfigController;
  const runtimeController = createRuntimeController(model, {
    canUsePacketCapture: access.canUsePacketCapture,
    persistConfig: () => configController.persistConfig(),
    showToast: notify
  });
  configController = createConfigController(model, {
    canViewRawConfig: access.canViewRawConfig,
    refreshAgentState: runtimeController.refreshAgentState,
    showToast: notify
  });
  const pollingController = createPollingController(model, {
    applyExternalConfig: configController.applyExternalConfig,
    refreshAgentState: runtimeController.refreshAgentState
  });
  const directRuleController = createDirectRuleController(model, {
    ensureConfigEditable: configController.ensureConfigEditable,
    persistConfig: configController.persistConfig,
    refreshAgentState: runtimeController.refreshAgentState,
    showToast: notify,
    updateDirectRules: configController.updateDirectRules
  });

  let mounted = false;
  let unlistenConfigUpdated: UnlistenFn | undefined;
  let unlistenTrayError: UnlistenFn | undefined;
  let unlistenAgentStateUpdated: UnlistenFn | undefined;
  let unlistenTrayInfo: UnlistenFn | undefined;

  onMounted(() => {
    mounted = true;
    void registerTauriEventListeners();
    void configController.boot().finally(() => {
      if (mounted) {
        pollingController.start();
      }
    });
  });

  onBeforeUnmount(() => {
    mounted = false;
    pollingController.stop();
    unlistenConfigUpdated?.();
    unlistenTrayError?.();
    unlistenAgentStateUpdated?.();
    unlistenTrayInfo?.();
  });

  async function registerTauriEventListeners() {
    try {
      unlistenConfigUpdated = await listen<LoadedAgentConfig>(
        "agent-config-updated",
        (event) => {
          configController.applyExternalConfig(event.payload, true);
        }
      );
      unlistenTrayError = await listen<string>(
        "agent-tray-error",
        (event) => {
          notify("error", event.payload);
        }
      );
      unlistenAgentStateUpdated = await listen<AgentState>(
        "agent-state-updated",
        (event) => {
          state.agent = event.payload;
          void pollingController.refreshConfigFromDisk(false);
        }
      );
      unlistenTrayInfo = await listen<string>(
        "agent-tray-info",
        (event) => {
          notify("success", event.payload);
        }
      );
    } catch {
      // The event API is only available inside Tauri.
    }
  }

  return {
    activeForwardingLabel: model.activeForwardingLabel,
    addDirectRules: directRuleController.addDirectRules,
    addDirectRulesAndRestart:
      directRuleController.addDirectRulesAndRestart,
    addDraftRules: directRuleController.addDraftRules,
    clearPacketCapture: runtimeController.clearPacketCapture,
    configLocked: model.configLocked,
    diagnosticsPassed: model.diagnosticsPassed,
    diagnosticsTotal: model.diagnosticsTotal,
    directModeLabel: model.directModeLabel,
    directRuleGroups: directRuleController.directRuleGroups,
    dnsCardLabel: model.dnsCardLabel,
    guardIntegerBeforeInput,
    recentDnsRecords: model.recentDnsRecords,
    proxyEntryStateLabel: model.proxyEntryStateLabel,
    refreshAgentState: runtimeController.refreshAgentState,
    reloadAll: configController.reloadAll,
    removeDirectRule: directRuleController.removeDirectRule,
    removeDirectRulesAndRestart:
      directRuleController.removeDirectRulesAndRestart,
    restoreDefaultConfig: configController.restoreDefaultConfig,
    runDiagnostics: runtimeController.runDiagnostics,
    running: model.running,
    runningLabel: model.runningLabel,
    runningSeverity: model.runningSeverity,
    sanitizeIntegerInput,
    saveConfig: configController.saveConfig,
    setField: configController.setField,
    setRawConfig: configController.setRawConfig,
    startAgent: runtimeController.startAgent,
    state,
    stopAgent: runtimeController.stopAgent,
    togglePacketCapture: runtimeController.togglePacketCapture,
    summary: model.summary,
    tabs,
    tunDiagnosticsLabel: model.tunDiagnosticsLabel,
    tunModeLabel: model.tunModeLabel,
    guardIntegerPaste
  };
}
