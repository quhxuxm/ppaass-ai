<script setup lang="ts">
import Card from "primevue/card";
import InputText from "primevue/inputtext";
import Select from "primevue/select";
import Tag from "primevue/tag";
import ToggleSwitch from "primevue/toggleswitch";
import { quicPolicyOptions } from "../constants";
import type { AgentConfigSummary } from "../types";

defineProps<{
  summary: AgentConfigSummary;
  configLocked: boolean;
  proxyEntryStateLabel: string;
  activeForwardingLabel: string;
  tunModeLabel: string;
}>();

const emit = defineEmits<{
  "set-field": [field: keyof AgentConfigSummary, value: unknown];
}>();
</script>

<template>
  <div class="content-grid">
    <section class="card-group span-12">
      <div class="card-group-heading">
        <div>
          <h2>HTTP / SOCKS5 代理</h2>
          <p>{{ summary.listen_addr }}</p>
        </div>
        <Tag :value="proxyEntryStateLabel" severity="success" />
      </div>
      <div class="card-group-grid">
        <Card class="panel">
          <template #title><h2>代理入口</h2></template>
          <template #content>
            <div class="method-summary">
              <div class="method-fact"><span>入站协议</span><strong>HTTP / SOCKS5</strong></div>
              <div class="method-fact"><span>监听状态</span><strong>{{ proxyEntryStateLabel }}</strong></div>
            </div>
            <label class="field">
              <span><i class="pi pi-wifi"></i>监听地址</span>
              <InputText :model-value="summary.listen_addr" :disabled="configLocked" @update:model-value="emit('set-field', 'listen_addr', $event)" />
            </label>
          </template>
        </Card>

        <Card class="panel">
          <template #title>
            <div class="panel-heading inline">
              <h2>代理状态</h2>
              <Tag :value="activeForwardingLabel" severity="info" />
            </div>
          </template>
          <template #content>
            <div class="kv-list">
              <div class="kv-row"><span>监听</span><strong>{{ summary.listen_addr }}</strong></div>
              <div class="kv-row"><span>协议</span><strong>HTTP / SOCKS5</strong></div>
              <div class="kv-row"><span>状态</span><strong>{{ proxyEntryStateLabel }}</strong></div>
              <div class="kv-row"><span>公共出口</span><strong>{{ summary.proxy_addrs.length }} 个节点</strong></div>
            </div>
          </template>
        </Card>
      </div>
    </section>

    <section class="card-group span-12">
      <div class="card-group-heading">
        <div>
          <h2>TUN 模式</h2>
          <p>{{ summary.tun_name }} · {{ summary.tun_ipv4 }}</p>
        </div>
        <ToggleSwitch :model-value="summary.tun_enabled" :disabled="configLocked" @update:model-value="emit('set-field', 'tun_enabled', $event)" />
      </div>
      <div class="card-group-grid">
        <Card class="panel">
          <template #title><h2>TUN 设备</h2></template>
          <template #content>
            <div class="method-summary">
              <div class="method-fact"><span>转发方式</span><strong>虚拟网卡</strong></div>
              <div class="method-fact"><span>当前状态</span><strong>{{ tunModeLabel }}</strong></div>
            </div>
            <label class="field">
              <span><i class="pi pi-desktop"></i>名称</span>
              <InputText :model-value="summary.tun_name" :disabled="configLocked" @update:model-value="emit('set-field', 'tun_name', $event)" />
            </label>
          </template>
        </Card>

        <Card class="panel">
          <template #title><h2>TUN 专属策略</h2></template>
          <template #content>
            <div class="toggle-list">
              <div class="switch-row">
                <span>代理 UDP</span>
                <ToggleSwitch :model-value="summary.tun_proxy_udp" :disabled="configLocked" @update:model-value="emit('set-field', 'tun_proxy_udp', $event)" />
              </div>
              <small class="field-help">关闭后普通 UDP 由 Agent 直接转发到目标；代理 DNS 仍由下方独立开关控制。</small>
              <div class="switch-row">
                <span>代理 DNS</span>
                <ToggleSwitch :model-value="summary.tun_proxy_dns" :disabled="configLocked" @update:model-value="emit('set-field', 'tun_proxy_dns', $event)" />
              </div>
            </div>
            <label class="field">
              <span><i class="pi pi-bolt"></i>QUIC 策略</span>
              <Select
                :model-value="summary.tun_quic_policy"
                :options="quicPolicyOptions"
                option-label="label"
                option-value="value"
                :disabled="configLocked"
                @update:model-value="emit('set-field', 'tun_quic_policy', $event)"
              />
              <small class="field-help">允许时，QUIC 会遵循上方“代理 UDP”开关和直连规则；阻断时应用可回退到 TCP/TLS。</small>
            </label>
          </template>
        </Card>
      </div>
    </section>
  </div>
</template>
