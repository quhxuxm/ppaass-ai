import { delay, getErrorMessage } from "../../formatters";
import {
  fallbackAgentState,
  fallbackConnectivityReport
} from "../../fallbacks";
import type {
  AgentState,
  ConnectivityReport,
  PacketCaptureRuntimeStatus,
  ToastKind
} from "../../types";
import type { DesktopAgentModel } from "./model";
import { latestAgentLog } from "./model";
import { invokeOrFallback } from "./platform";

interface RuntimeDependencies {
  canUsePacketCapture: () => boolean;
  persistConfig: () => Promise<void>;
  showToast: (kind: ToastKind, message: string) => void;
}

export function createRuntimeController(
  model: DesktopAgentModel,
  dependencies: RuntimeDependencies
) {
  const { state } = model;
  let agentRefreshInFlight = false;

  async function startAgent() {
    if (!state.config) {
      return;
    }
    try {
      state.busy = true;
      if (state.dirty) {
        await dependencies.persistConfig();
      }
      state.agent = await invokeOrFallback<AgentState>(
        "start_agent",
        { configPath: state.config.path },
        () => ({
          ...fallbackAgentState(),
          running: true,
          managed: true,
          pid: 4242,
          config_path: state.config?.path
        })
      );
      await delay(1800);
      await refreshAgentState();
      dependencies.showToast(
        state.agent.running ? "success" : "error",
        state.agent.running
          ? "代理已启动"
          : latestAgentLog(model) ?? "代理启动失败"
      );
    } catch (error) {
      await refreshAgentState();
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function stopAgent() {
    try {
      state.busy = true;
      state.agent = await invokeOrFallback<AgentState>(
        "stop_agent",
        {},
        () => ({
          ...fallbackAgentState(),
          running: false,
          pid: null,
          config_path: state.config?.path
        })
      );
      if (!state.agent.running) {
        state.packetCapture = {
          available: false,
          enabled: false,
          file: null
        };
      }
      dependencies.showToast(
        state.agent.running ? "error" : "success",
        state.agent.running ? "代理仍在运行" : "代理已停止"
      );
    } catch (error) {
      await refreshAgentState();
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function togglePacketCapture(enabled: boolean) {
    if (!dependencies.canUsePacketCapture()) {
      dependencies.showToast("error", "当前账户没有使用抓包功能的权限");
      return;
    }
    if (state.busy || state.packetCapture.enabled === enabled) {
      return;
    }
    if (!state.agent.running) {
      dependencies.showToast("error", "Agent 未运行，请先启动 Agent");
      return;
    }
    try {
      state.busy = true;
      state.packetCapture =
        await invokeOrFallback<PacketCaptureRuntimeStatus>(
          "set_packet_capture_enabled",
          { enabled },
          () => ({
            available: true,
            enabled,
            file: state.packetCapture.file
          })
        );
      state.packetCaptureRefreshToken += 1;
      dependencies.showToast(
        "success",
        enabled
          ? "抓包已开启，无需重启 Agent"
          : "抓包已关闭，无需重启 Agent"
      );
    } catch (error) {
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function clearPacketCapture() {
    if (!dependencies.canUsePacketCapture()) {
      dependencies.showToast("error", "当前账户没有使用抓包功能的权限");
      return;
    }
    if (!state.config || state.busy) {
      return;
    }
    try {
      state.busy = true;
      state.packetCapture =
        await invokeOrFallback<PacketCaptureRuntimeStatus>(
          "clear_packet_capture",
          { configPath: state.config.path },
          () => ({ ...state.packetCapture })
        );
      state.packetCaptureRefreshToken += 1;
      dependencies.showToast("success", "抓包文件已清空");
    } catch (error) {
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.busy = false;
    }
  }

  async function runDiagnostics() {
    if (!state.config) {
      return;
    }
    try {
      state.diagnosticsRunning = true;
      state.diagnostics = null;
      state.diagnostics = await invokeOrFallback<ConnectivityReport>(
        "run_connectivity_tests",
        { path: state.config.path },
        () => fallbackConnectivityReport(state.config?.summary)
      );
      const total = model.diagnosticsTotal.value;
      const passed = model.diagnosticsPassed.value;
      dependencies.showToast(
        total > 0 && passed === total ? "success" : "error",
        `诊断完成：${passed}/${total}`
      );
    } catch (error) {
      dependencies.showToast("error", getErrorMessage(error));
    } finally {
      state.diagnosticsRunning = false;
    }
  }

  async function refreshAgentState() {
    if (agentRefreshInFlight) {
      return;
    }
    agentRefreshInFlight = true;
    try {
      state.agent = await invokeOrFallback<AgentState>(
        "get_agent_state",
        {},
        () => state.agent
      );
      state.packetCapture =
        state.agent.running && dependencies.canUsePacketCapture()
        ? await invokeOrFallback<PacketCaptureRuntimeStatus>(
            "get_packet_capture_runtime_status",
            {},
            () => state.packetCapture
          )
        : { available: false, enabled: false, file: null };
    } catch {
      // Keep the last visible agent state if the runtime status read fails.
    } finally {
      agentRefreshInFlight = false;
    }
  }

  return {
    clearPacketCapture,
    refreshAgentState,
    runDiagnostics,
    startAgent,
    stopAgent,
    togglePacketCapture
  };
}

export type RuntimeController = ReturnType<typeof createRuntimeController>;
