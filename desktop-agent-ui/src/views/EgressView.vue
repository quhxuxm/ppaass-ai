<script setup lang="ts">
import Card from "primevue/card";
import ConfigNumberInput from "../components/ConfigNumberInput.vue";
import InputText from "primevue/inputtext";
import Select from "primevue/select";
import SelectButton from "primevue/selectbutton";
import Tag from "primevue/tag";
import Textarea from "primevue/textarea";
import { compressionOptions, transportModeLabel, transportModeOptions } from "../constants";
import type { AgentConfigSummary } from "../types";

defineProps<{
  summary: AgentConfigSummary;
  configLocked: boolean;
}>();

const emit = defineEmits<{
  "set-field": [field: keyof AgentConfigSummary, value: unknown];
}>();

function usesYamux(mode: string) {
  return mode === "yamux" || mode === "auto";
}

function usesDirectPool(mode: string) {
  return mode === "legacy" || mode === "auto";
}
</script>

<template>
  <div class="content-grid">
    <Card class="panel span-6">
      <template #title>
        <div class="panel-heading inline">
          <h2>公共远端出口</h2>
          <span>{{ summary.proxy_addrs.length }} 个节点</span>
        </div>
      </template>
      <template #content>
        <label class="field">
          <span><i class="pi pi-server"></i>节点</span>
          <Textarea
            :model-value="summary.proxy_addrs.join('\n')"
            :disabled="configLocked"
            rows="5"
            auto-resize
            @update:model-value="emit('set-field', 'proxy_addrs', $event)"
          />
        </label>
      </template>
    </Card>

    <Card class="panel span-6">
      <template #title><h2>身份凭据</h2></template>
      <template #content>
        <label class="field">
          <span><i class="pi pi-user"></i>用户</span>
          <InputText :model-value="summary.username" :disabled="configLocked" @update:model-value="emit('set-field', 'username', $event)" />
        </label>
        <label class="field">
          <span><i class="pi pi-key"></i>私钥</span>
          <InputText :model-value="summary.private_key_path" :disabled="configLocked" @update:model-value="emit('set-field', 'private_key_path', $event)" />
        </label>
      </template>
    </Card>

    <Card class="panel span-12">
      <template #title>
        <div class="panel-heading inline">
          <h2>公共通道参数</h2>
          <Tag :value="`${transportModeLabel(summary.tcp_mode)} / ${transportModeLabel(summary.udp_mode)}`" severity="info" />
        </div>
      </template>
      <template #content>
        <div class="field-pair">
          <label class="field">
            <span><i class="pi pi-clock"></i>控制连接超时</span>
            <ConfigNumberInput
              :model-value="summary.connect_timeout_secs"
              :min="0"
              :allow-empty="false"
              :disabled="configLocked"
              :use-grouping="false"
              @update:model-value="emit('set-field', 'connect_timeout_secs', $event)"
            />
          </label>
          <label class="field">
            <span><i class="pi pi-box"></i>消息压缩</span>
            <Select
              :model-value="summary.compression_mode"
              :options="compressionOptions"
              :disabled="configLocked"
              @update:model-value="emit('set-field', 'compression_mode', $event)"
            />
          </label>
          <label class="field">
            <span><i class="pi pi-arrows-h"></i>TCP relay buffer</span>
            <ConfigNumberInput
              :model-value="summary.tcp_relay_buffer_size_kb"
              suffix=" KB"
              :min="0"
              :allow-empty="false"
              :disabled="configLocked"
              :use-grouping="false"
              @update:model-value="emit('set-field', 'tcp_relay_buffer_size_kb', $event)"
            />
          </label>
        </div>
      </template>
    </Card>

    <Card class="panel span-6">
      <template #title>
        <div class="panel-heading inline">
          <h2>TCP</h2>
          <Tag :value="transportModeLabel(summary.tcp_mode)" severity="info" />
        </div>
      </template>
      <template #content>
        <label class="field">
          <span><i class="pi pi-sliders-h"></i>传输</span>
          <SelectButton
            :model-value="summary.tcp_mode"
            :options="transportModeOptions"
            option-label="label"
            option-value="value"
            :allow-empty="false"
            :disabled="configLocked"
            @update:model-value="emit('set-field', 'tcp_mode', $event)"
          />
        </label>
        <label v-if="usesDirectPool(summary.tcp_mode)" class="field dependent-field">
          <span>
            <i class="pi pi-clone"></i>
            连接池
            <Tag class="mode-effect-tag" value="常规通道、自动时生效" severity="secondary" />
          </span>
          <ConfigNumberInput :model-value="summary.tcp_pool_size" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_pool_size', $event)" />
        </label>

        <section v-if="usesYamux(summary.tcp_mode)" class="policy-section yamux-settings">
          <div class="section-heading">
            <div class="section-title">
              <span>TCP Yamux</span>
              <Tag class="mode-effect-tag" value="yamux / auto 生效" severity="secondary" />
            </div>
            <strong>{{ summary.tcp_yamux_sessions }} sessions</strong>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><i class="pi pi-share-alt"></i>外层连接</span>
              <ConfigNumberInput :model-value="summary.tcp_yamux_sessions" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_yamux_sessions', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-sitemap"></i>并发子流</span>
              <ConfigNumberInput :model-value="summary.tcp_yamux_max_streams_per_session" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_yamux_max_streams_per_session', $event)" />
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><i class="pi pi-stopwatch"></i>打开子流超时</span>
              <ConfigNumberInput :model-value="summary.tcp_yamux_open_stream_timeout_secs" suffix=" s" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_yamux_open_stream_timeout_secs', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-heart"></i>Keepalive</span>
              <ConfigNumberInput :model-value="summary.tcp_yamux_keepalive_interval_secs" suffix=" s" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_yamux_keepalive_interval_secs', $event)" />
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><i class="pi pi-send"></i>写超时</span>
              <ConfigNumberInput :model-value="summary.tcp_yamux_connection_write_timeout_secs" suffix=" s" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_yamux_connection_write_timeout_secs', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-window-maximize"></i>流控窗口</span>
              <ConfigNumberInput :model-value="summary.tcp_yamux_stream_window_size_kb" suffix=" KB" :min="256" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_yamux_stream_window_size_kb', $event)" />
            </label>
          </div>
        </section>
      </template>
    </Card>

    <Card class="panel span-6">
      <template #title>
        <div class="panel-heading inline">
          <h2>UDP</h2>
          <Tag :value="transportModeLabel(summary.udp_mode)" severity="info" />
        </div>
      </template>
      <template #content>
        <label class="field">
          <span><i class="pi pi-sliders-h"></i>传输</span>
          <SelectButton
            :model-value="summary.udp_mode"
            :options="transportModeOptions"
            option-label="label"
            option-value="value"
            :allow-empty="false"
            :disabled="configLocked"
            @update:model-value="emit('set-field', 'udp_mode', $event)"
          />
        </label>
        <label v-if="usesDirectPool(summary.udp_mode)" class="field dependent-field">
          <span>
            <i class="pi pi-wave-pulse"></i>
            连接池
            <Tag class="mode-effect-tag" value="常规通道、自动时生效" severity="secondary" />
          </span>
          <ConfigNumberInput :model-value="summary.udp_pool_size" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_pool_size', $event)" />
        </label>

        <section v-if="usesYamux(summary.udp_mode)" class="policy-section yamux-settings">
          <div class="section-heading">
            <div class="section-title">
              <span>UDP Yamux</span>
              <Tag class="mode-effect-tag" value="yamux / auto 生效" severity="secondary" />
            </div>
            <strong>{{ summary.udp_yamux_sessions }} sessions</strong>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><i class="pi pi-share-alt"></i>外层连接</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_sessions" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_sessions', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-sitemap"></i>并发子流</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_max_streams_per_session" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_max_streams_per_session', $event)" />
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><i class="pi pi-stopwatch"></i>打开子流超时</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_open_stream_timeout_secs" suffix=" s" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_open_stream_timeout_secs', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-heart"></i>Keepalive</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_keepalive_interval_secs" suffix=" s" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_keepalive_interval_secs', $event)" />
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><i class="pi pi-send"></i>写超时</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_connection_write_timeout_secs" suffix=" s" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_connection_write_timeout_secs', $event)" />
            </label>
            <label class="field">
              <span><i class="pi pi-window-maximize"></i>流控窗口</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_stream_window_size_kb" suffix=" KB" :min="256" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_stream_window_size_kb', $event)" />
            </label>
          </div>
        </section>
      </template>
    </Card>
  </div>
</template>
