<script setup lang="ts">
import Card from "primevue/card";
import InputText from "primevue/inputtext";
import Tag from "primevue/tag";
import ToggleSwitch from "primevue/toggleswitch";
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
                <span>Proxy DNS</span>
                <ToggleSwitch :model-value="summary.tun_proxy_dns" :disabled="configLocked" @update:model-value="emit('set-field', 'tun_proxy_dns', $event)" />
              </div>
              <div class="switch-row">
                <span>阻断 QUIC</span>
                <ToggleSwitch :model-value="summary.tun_block_quic" :disabled="configLocked" @update:model-value="emit('set-field', 'tun_block_quic', $event)" />
              </div>
            </div>
          </template>
        </Card>
      </div>
    </section>
  </div>
</template>
