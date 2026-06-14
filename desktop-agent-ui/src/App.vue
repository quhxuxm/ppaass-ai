<script setup lang="ts">
import { ref } from "vue";
import ProgressSpinner from "primevue/progressspinner";
import AppSidebar from "./components/AppSidebar.vue";
import AppTopbar from "./components/AppTopbar.vue";
import ToastHost from "./components/ToastHost.vue";
import { useDesktopAgent } from "./composables/useDesktopAgent";
import DiagnosticsView from "./views/DiagnosticsView.vue";
import EgressView from "./views/EgressView.vue";
import ForwardingView from "./views/ForwardingView.vue";
import LogsView from "./views/LogsView.vue";
import OverviewView from "./views/OverviewView.vue";
import RoutingView from "./views/RoutingView.vue";
import TomlView from "./views/TomlView.vue";

const {
  activeForwardingLabel,
  addDirectRules,
  addDraftRules,
  configLocked,
  diagnosticsPassed,
  diagnosticsTotal,
  directModeLabel,
  directRuleGroups,
  dnsCardLabel,
  guardIntegerBeforeInput,
  guardIntegerPaste,
  proxyEntryStateLabel,
  recentDnsRecords,
  refreshAgentState,
  reloadAll,
  removeDirectRule,
  runDiagnostics,
  running,
  runningLabel,
  runningSeverity,
  sanitizeIntegerInput,
  saveConfig,
  setField,
  setRawConfig,
  startAgent,
  state,
  stopAgent,
  summary,
  tabs,
  tunDiagnosticsLabel,
  tunModeLabel
} = useDesktopAgent();

const sidebarCollapsed = ref(false);
</script>

<template>
  <main
    class="app-frame"
    @beforeinput.capture="guardIntegerBeforeInput"
    @paste.capture="guardIntegerPaste"
    @input.capture="sanitizeIntegerInput"
  >
    <div :class="['shell', { 'sidebar-collapsed': sidebarCollapsed }]">
      <AppSidebar
        :tabs="tabs"
        :active-tab="state.activeTab"
        :collapsed="sidebarCollapsed"
        :running="running"
        :running-label="runningLabel"
        :running-severity="runningSeverity"
        :pid="state.agent.pid"
        :config-path="state.config?.path"
        @update:active-tab="state.activeTab = $event"
        @update:collapsed="sidebarCollapsed = $event"
      />

      <section class="workspace">
        <AppTopbar
          :subtitle="summary.listen_addr || state.statusText"
          :running="running"
          :config-locked="configLocked"
          :dirty="state.dirty"
          :busy="state.busy"
          @reload="reloadAll"
          @save="saveConfig"
          @start="startAgent"
          @stop="stopAgent"
        />

        <section v-if="state.loading" class="loading">
          <ProgressSpinner />
          <span>加载中</span>
        </section>

        <section v-else-if="!state.config" class="empty-state">
          <i class="pi pi-exclamation-triangle"></i>
          <h2>未载入配置</h2>
        </section>

        <OverviewView
          v-else-if="state.activeTab === 'overview'"
          :summary="summary"
          :agent="state.agent"
          :traffic="state.traffic"
          :recent-dns-records="recentDnsRecords"
          :proxy-entry-state-label="proxyEntryStateLabel"
          :active-forwarding-label="activeForwardingLabel"
          :direct-mode-label="directModeLabel"
          :dns-card-label="dnsCardLabel"
        />

        <ForwardingView
          v-else-if="state.activeTab === 'forwarding'"
          :summary="summary"
          :config-locked="configLocked"
          :proxy-entry-state-label="proxyEntryStateLabel"
          :active-forwarding-label="activeForwardingLabel"
          :tun-mode-label="tunModeLabel"
          @set-field="setField"
        />

        <EgressView
          v-else-if="state.activeTab === 'egress'"
          :summary="summary"
          :config-locked="configLocked"
          @set-field="setField"
        />

        <RoutingView
          v-else-if="state.activeTab === 'routing'"
          :summary="summary"
          :config-locked="configLocked"
          :direct-mode-label="directModeLabel"
          :active-forwarding-label="activeForwardingLabel"
          :tun-mode-label="tunModeLabel"
          :direct-rule-groups="directRuleGroups"
          :rule-draft="state.ruleDraft"
          @set-field="setField"
          @update:rule-draft="state.ruleDraft = $event"
          @add-direct-rules="addDirectRules"
          @add-draft-rules="addDraftRules"
          @remove-direct-rule="removeDirectRule"
        />

        <DiagnosticsView
          v-else-if="state.activeTab === 'diagnostics'"
          :summary="summary"
          :diagnostics="state.diagnostics"
          :diagnostics-running="state.diagnosticsRunning"
          :tun-diagnostics-label="tunDiagnosticsLabel"
          :diagnostics-passed="diagnosticsPassed"
          :diagnostics-total="diagnosticsTotal"
          @run="runDiagnostics"
        />

        <LogsView
          v-else-if="state.activeTab === 'logs'"
          :logs="state.agent.logs"
          @refresh="refreshAgentState"
        />

        <TomlView
          v-else-if="state.activeTab === 'toml'"
          :raw="state.config?.raw ?? ''"
          :path="state.config?.path"
          :config-locked="configLocked"
          @update:raw="setRawConfig"
        />
      </section>
    </div>

    <ToastHost :toast="state.toast" />
  </main>
</template>
