<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import { formatTimestamp, shortProxyUrl } from "../formatters";
import type { AgentConfigSummary, ConnectivityReport } from "../types";

defineProps<{
  summary: AgentConfigSummary;
  diagnostics: ConnectivityReport | null;
  diagnosticsRunning: boolean;
  tunDiagnosticsLabel: string;
  diagnosticsPassed: number;
  diagnosticsTotal: number;
}>();

const emit = defineEmits<{
  run: [];
}>();
</script>

<template>
  <div class="content-grid">
    <Card class="panel span-5">
      <template #title>
        <div class="panel-heading inline">
          <div>
            <h2>链路诊断</h2>
            <p>{{ summary.tun_enabled ? `${summary.tun_name} · TUN` : summary.listen_addr }}</p>
          </div>
          <Button
            :label="diagnosticsRunning ? '测试中' : '运行测试'"
            :icon="diagnosticsRunning ? 'pi pi-spin pi-spinner' : 'pi pi-play'"
            :disabled="diagnosticsRunning"
            @click="emit('run')"
          />
        </div>
      </template>
      <template #content>
        <div class="diagnostic-summary">
          <div class="metric-tile">
            <i :class="diagnostics?.agent_reachable ? 'pi pi-check-circle' : 'pi pi-exclamation-circle'"></i>
            <span>本地入口</span>
            <strong>
              {{
                diagnostics
                  ? diagnostics.tun_enabled
                    ? diagnostics.agent_reachable
                      ? "Proxy On"
                      : "Paused"
                    : diagnostics.agent_reachable
                      ? "Reachable"
                      : "Offline"
                  : "Pending"
              }}
            </strong>
          </div>
          <div class="metric-tile">
            <i class="pi pi-globe"></i>
            <span>站点</span>
            <strong>Google / YouTube</strong>
          </div>
          <div class="metric-tile">
            <i class="pi pi-compass"></i>
            <span>TUN</span>
            <strong>{{ tunDiagnosticsLabel }}</strong>
          </div>
          <div class="metric-tile">
            <i class="pi pi-shield"></i>
            <span>结果</span>
            <strong>{{ diagnostics ? `${diagnosticsPassed}/${diagnosticsTotal}` : "—" }}</strong>
          </div>
        </div>
      </template>
    </Card>

    <Card class="panel span-7">
      <template #title>
        <div class="panel-heading inline">
          <h2>链路结果</h2>
          <span>{{ diagnostics ? formatTimestamp(diagnostics.generated_at_ms) : "—" }}</span>
        </div>
      </template>
      <template #content>
        <div class="diagnostic-list">
          <div v-if="diagnosticsRunning" class="diagnostic-row muted">
            <div><strong>后台测试中</strong><span>Google / YouTube · HTTP / SOCKS5 / TUN</span></div>
            <span>等待结果</span>
          </div>
          <div v-if="!diagnostics && !diagnosticsRunning" class="diagnostic-row muted">
            <div><strong>Google</strong><span>HTTP / SOCKS5</span></div>
            <span>未测试</span>
          </div>
          <div v-if="!diagnostics && !diagnosticsRunning" class="diagnostic-row muted">
            <div><strong>YouTube</strong><span>HTTP / SOCKS5</span></div>
            <span>未测试</span>
          </div>
          <div v-if="!diagnostics && !diagnosticsRunning" class="diagnostic-row muted">
            <div><strong>TUN</strong><span>{{ summary.tun_enabled ? summary.tun_name : "未启用" }}</span></div>
            <span>{{ summary.tun_enabled ? "未测试" : "跳过" }}</span>
          </div>
          <div v-if="diagnostics && !diagnostics.tun_enabled" class="diagnostic-row muted">
            <div><strong>TUN</strong><span>未启用</span></div>
            <span>跳过</span>
          </div>
          <div v-for="item in diagnostics?.results ?? []" :key="`${item.target}-${item.protocol}`" :class="['diagnostic-row', item.success ? 'ok' : 'fail']">
            <div>
              <strong>{{ item.target }} · {{ item.protocol }}</strong>
              <span :title="item.proxy_url">{{ shortProxyUrl(item.proxy_url) }}</span>
            </div>
            <div class="diagnostic-result">
              <strong>{{ item.http_code ?? "—" }}</strong>
              <span>{{ Math.max(1, Math.round(item.duration_ms)) }} ms</span>
            </div>
            <p v-if="item.error">{{ item.error }}</p>
          </div>
          <div v-for="item in diagnostics?.tun_results ?? []" :key="`${item.target}-${item.protocol}`" :class="['diagnostic-row', item.success ? 'ok' : 'fail']">
            <div>
              <strong>{{ item.target }} · {{ item.protocol }}</strong>
              <span :title="item.proxy_url">{{ shortProxyUrl(item.proxy_url) }}</span>
            </div>
            <div class="diagnostic-result">
              <strong>{{ item.http_code ?? "—" }}</strong>
              <span>{{ Math.max(1, Math.round(item.duration_ms)) }} ms</span>
            </div>
            <p v-if="item.error">{{ item.error }}</p>
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>
