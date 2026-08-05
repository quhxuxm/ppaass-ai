<script setup lang="ts">
import { computed, ref, watchEffect } from "vue";
import ProgressSpinner from "primevue/progressspinner";
import AdminKeyRequestsView from "./views/AdminKeyRequestsView.vue";
import AppSidebar from "./components/AppSidebar.vue";
import AppIcon from "./components/AppIcon";
import AppTopbar from "./components/AppTopbar.vue";
import ToastHost from "./components/ToastHost.vue";
import { useDesktopAgent } from "./composables/useDesktopAgent";
import DiagnosticsView from "./views/DiagnosticsView.vue";
import EgressView from "./views/EgressView.vue";
import ForwardingView from "./views/ForwardingView.vue";
import LogsView from "./views/LogsView.vue";
import OverviewView from "./views/OverviewView.vue";
import RoutingView from "./views/RoutingView.vue";
import PacketCaptureView from "./views/PacketCaptureView.vue";
import TomlView from "./views/TomlView.vue";
import { applyColorTheme, colorThemes, loadColorTheme, type ColorTheme } from "./colorThemes";
import { languageOptions, useI18n, type AppLocale } from "./i18n";
import { resolveAgentCapabilities } from "./agentPermissions";
import type {
  AgentAdminKeyRequest,
  AgentAdminKeyRequestApproval,
  AgentAdminKeyRequestRejection,
  AgentAdminProxyAddress,
  AgentAuthAccount,
  AgentAuthState,
  TabKey
} from "./types";

const props = defineProps<{
  account: AgentAuthAccount;
  accountStatus: AgentAuthState["account_status"];
  accountManagementBusy: boolean;
  adminKeyRequests: AgentAdminKeyRequest[];
  adminProxyAddresses: AgentAdminProxyAddress[];
  adminRequestsLoading: boolean;
  adminRequestBusyId: string | null;
  adminRequestError: string;
  canRotateKey: boolean;
  keyRotationBusy: boolean;
  logoutBusy: boolean;
}>();

const emit = defineEmits<{
  manageAccount: [];
  refreshAdminRequests: [];
  approveAdminRequest: [request: AgentAdminKeyRequestApproval];
  rejectAdminRequest: [request: AgentAdminKeyRequestRejection];
  rotateKey: [];
  logout: [];
}>();

const capabilities = computed(() =>
  resolveAgentCapabilities(props.account)
);

const {
  activeForwardingLabel,
  addDirectRules,
  addDirectRulesAndRestart,
  addDraftRules,
  clearPacketCapture,
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
  removeDirectRulesAndRestart,
  restoreDefaultConfig,
  runDiagnostics,
  running,
  sanitizeIntegerInput,
  saveConfig,
  setField,
  setRawConfig,
  startAgent,
  state,
  stopAgent,
  togglePacketCapture,
  summary,
  tabs: allTabs,
  tunDiagnosticsLabel,
  tunModeLabel
} = useDesktopAgent({
  canUsePacketCapture: () =>
    capabilities.value.canCapturePackets,
  canViewRawConfig: () =>
    capabilities.value.canViewRawConfig
});

const sidebarCollapsed = ref(false);
const colorTheme = ref<ColorTheme>(loadColorTheme());
const { locale, setLocale } = useI18n();
const visibleTabs = computed(() =>
  allTabs.filter(
    (tab) =>
      (tab.key !== "capture" ||
        capabilities.value.canCapturePackets) &&
      (tab.key !== "admin-requests" ||
        (props.account.role === "admin" &&
          props.accountStatus === "active")) &&
      (tab.key !== "egress" ||
        capabilities.value.canEditEgress) &&
      (tab.key !== "toml" ||
        capabilities.value.canViewRawConfig)
  )
);

watchEffect(() => {
  if (
    !visibleTabs.value.some(
      (tab) => tab.key === state.activeTab
    )
  ) {
    state.activeTab = "overview";
  }
});

function setActiveTab(tab: TabKey) {
  if (visibleTabs.value.some((candidate) => candidate.key === tab)) {
    state.activeTab = tab;
  }
}

function togglePermittedPacketCapture(enabled: boolean) {
  if (capabilities.value.canCapturePackets) {
    void togglePacketCapture(enabled);
  }
}

function clearPermittedPacketCapture() {
  if (capabilities.value.canCapturePackets) {
    void clearPacketCapture();
  }
}

function setColorTheme(theme: ColorTheme) {
  colorTheme.value = theme;
  applyColorTheme(theme);
}

function setLanguage(language: AppLocale) {
  setLocale(language);
}
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
        :tabs="visibleTabs"
        :active-tab="state.activeTab"
        :collapsed="sidebarCollapsed"
        :account-username="account.username"
        :account-display-name="account.display_name"
        :account-avatar-url="account.avatar_url"
        :account-role="account.role"
        :account-management-busy="accountManagementBusy"
        :admin-request-count="adminKeyRequests.length"
        :can-rotate-key="canRotateKey"
        :key-rotation-busy="keyRotationBusy"
        :logout-busy="logoutBusy"
        :busy="state.busy"
        @update:active-tab="setActiveTab"
        @update:collapsed="sidebarCollapsed = $event"
        @manage-account="emit('manageAccount')"
        @rotate-key="emit('rotateKey')"
        @logout="emit('logout')"
      />

      <section class="workspace">
        <AppTopbar
          :subtitle="summary.listen_addr || state.statusText"
          :running="running"
          :config-locked="configLocked"
          :config-available="Boolean(state.config)"
          :can-restore-default-config="capabilities.canViewRawConfig"
          :dirty="state.dirty"
          :busy="state.busy"
          :color-theme="colorTheme"
          :color-themes="colorThemes"
          :language="locale"
          :languages="languageOptions"
          :pid="state.agent.pid"
          :config-path="state.config?.path"
          @reload="reloadAll"
          @restore-default-config="restoreDefaultConfig"
          @save="saveConfig"
          @start="startAgent"
          @stop="stopAgent"
          @update:color-theme="setColorTheme"
          @update:language="setLanguage"
        />

        <section v-if="state.loading" class="loading">
          <ProgressSpinner />
          <span>加载中</span>
        </section>

        <section v-else-if="!state.config" class="empty-state">
          <AppIcon class="semantic-warning" name="triangle-alert" />
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
          :agent-running="running"
          @add-direct-rules="addDirectRulesAndRestart"
          @remove-direct-rules="removeDirectRulesAndRestart"
        />

        <AdminKeyRequestsView
          v-else-if="
            state.activeTab === 'admin-requests' &&
            account.role === 'admin' &&
            accountStatus === 'active'
          "
          :requests="adminKeyRequests"
          :proxy-addresses="adminProxyAddresses"
          :loading="adminRequestsLoading"
          :busy-request-id="adminRequestBusyId"
          :error="adminRequestError"
          @refresh="emit('refreshAdminRequests')"
          @approve="emit('approveAdminRequest', $event)"
          @reject="emit('rejectAdminRequest', $event)"
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
          v-else-if="
            state.activeTab === 'egress' &&
            capabilities.canEditEgress
          "
          :summary="summary"
          :config-locked="configLocked"
          :can-edit-egress="capabilities.canEditEgress"
          @set-field="setField"
        />

        <RoutingView
          v-else-if="state.activeTab === 'routing'"
          :summary="summary"
          :config-locked="configLocked"
          :can-edit-runtime-threads="capabilities.canEditRuntimeThreads"
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

        <PacketCaptureView
          v-else-if="
            state.activeTab === 'capture' &&
            capabilities.canCapturePackets
          "
          :summary="summary"
          :config-path="state.config.path"
          :config-locked="configLocked"
          :agent-running="running"
          :capture-enabled="state.packetCapture.enabled"
          :refresh-token="state.packetCaptureRefreshToken"
          :busy="state.busy"
          @toggle-capture="togglePermittedPacketCapture"
          @clear-capture="clearPermittedPacketCapture"
          @set-field="setField"
        />

        <LogsView
          v-else-if="state.activeTab === 'logs'"
          :logs="state.agent.logs"
          @refresh="refreshAgentState"
        />

        <TomlView
          v-else-if="
            state.activeTab === 'toml' &&
            capabilities.canViewRawConfig
          "
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
