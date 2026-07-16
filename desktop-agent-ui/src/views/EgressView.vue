<script setup lang="ts">
import Card from "primevue/card";
import ConfigNumberInput from "../components/ConfigNumberInput.vue";
import AppIcon from "../components/AppIcon";
import InputText from "primevue/inputtext";
import Select from "primevue/select";
import Tag from "primevue/tag";
import Textarea from "primevue/textarea";
import { compressionOptions, transportModeOptions } from "../constants";
import type { AgentConfigSummary } from "../types";

defineProps<{
  summary: AgentConfigSummary;
  configLocked: boolean;
}>();

const emit = defineEmits<{
  "set-field": [field: keyof AgentConfigSummary, value: unknown];
}>();
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
          <span><AppIcon name="server" />节点</span>
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
          <span><AppIcon name="user" />用户</span>
          <InputText :model-value="summary.username" :disabled="configLocked" @update:model-value="emit('set-field', 'username', $event)" />
        </label>
        <label class="field">
          <span><AppIcon name="key" />私钥</span>
          <InputText :model-value="summary.private_key_path" :disabled="configLocked" @update:model-value="emit('set-field', 'private_key_path', $event)" />
        </label>
      </template>
    </Card>

    <Card class="panel span-12">
      <template #title>
        <div class="panel-heading inline">
          <h2>传输策略</h2>
          <Tag value="TCP 始终走 TCP" severity="info" />
        </div>
      </template>
      <template #content>
        <div class="field-pair channel-parameters-grid">
          <label class="field">
            <span><AppIcon name="waypoints" />UDP 代理通道</span>
            <Select
              :model-value="summary.transport_mode"
              :options="transportModeOptions"
              option-label="label"
              option-value="value"
              :disabled="configLocked"
              @update:model-value="emit('set-field', 'transport_mode', $event)"
            />
            <small>自动：原生 UDP 超时后仅该 session 转 TCP/Yamux；TCP 始终走 TCP。</small>
          </label>
          <label class="field">
            <span><AppIcon name="clock" />控制连接超时</span>
            <ConfigNumberInput
              :model-value="summary.connect_timeout_secs"
              suffix=" s"
              :min="0"
              :allow-empty="false"
              :disabled="configLocked"
              :use-grouping="false"
              @update:model-value="emit('set-field', 'connect_timeout_secs', $event)"
            />
          </label>
          <label class="field">
            <span><AppIcon name="package" />消息压缩</span>
            <Select
              :model-value="summary.compression_mode"
              :options="compressionOptions"
              :disabled="configLocked"
              @update:model-value="emit('set-field', 'compression_mode', $event)"
            />
          </label>
        </div>
      </template>
    </Card>

    <Card class="panel span-12">
      <template #title>
        <div class="panel-heading inline">
          <h2>TCP 数据</h2>
          <Tag value="两种模式均使用 TCP" severity="success" />
        </div>
      </template>
      <template #content>
        <section class="policy-section tcp-transport-note">
          <div class="section-heading">
            <div class="section-title">
              <span>TCP 转发</span>
              <Tag class="mode-effect-tag" value="HTTP / SOCKS5 / TUN TCP" severity="secondary" />
            </div>
          </div>
          <p>TCP 目标始终使用独立 TCP 连接。</p>
        </section>
      </template>
    </Card>

    <Card v-if="summary.transport_mode !== 'tcp'" class="panel span-12">
      <template #title>
        <div class="panel-heading inline">
          <h2>UDP 数据 · 原生加密 UDP</h2>
          <Tag :value="summary.transport_mode === 'auto' ? '自动模式首选' : 'UDP 模式'" severity="success" />
        </div>
      </template>
      <template #content>
        <section class="policy-section yamux-settings">
          <div class="section-heading">
            <div class="section-title">
              <span>加密 UDP 会话池</span>
              <Tag class="mode-effect-tag" value="仅作用于 UDP relay" severity="secondary" />
            </div>
            <strong>{{ summary.udp_session_pool_size }} 条</strong>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><AppIcon name="share" />UDP 会话数</span>
              <ConfigNumberInput
                :model-value="summary.udp_session_pool_size"
                :min="1"
                :max="8"
                :allow-empty="false"
                :disabled="configLocked"
                :use-grouping="false"
                @update:model-value="emit('set-field', 'udp_session_pool_size', $event)"
              />
              <small>已认证 UDP 会话数，范围 1–8，默认 4。</small>
            </label>
          </div>
          <p>RSA 认证，UDP 数据使用 AES-256-GCM；不重传、不保序。</p>
        </section>
      </template>
    </Card>

    <Card v-if="summary.transport_mode !== 'udp'" class="panel span-12">
      <template #title>
        <div class="panel-heading inline">
          <h2>UDP 数据 · TCP/Yamux</h2>
          <Tag :value="summary.transport_mode === 'auto' ? '自动回退通道' : '全 TCP 模式'" severity="info" />
        </div>
      </template>
      <template #content>
        <section class="policy-section yamux-settings">
          <div class="section-heading">
            <div class="section-title">
              <span>UDP Yamux</span>
              <Tag class="mode-effect-tag" value="作用于 UDP relay 子流" severity="secondary" />
            </div>
            <strong>{{ summary.udp_yamux_sessions }} max sessions</strong>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><AppIcon name="share" />外层连接</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_sessions" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_sessions', $event)" />
              <small>Yamux 外层连接上限。</small>
            </label>
            <label class="field">
              <span><AppIcon name="network" />并发子流</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_max_streams_per_session" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_max_streams_per_session', $event)" />
              <small>单连接最大 UDP 子流数。</small>
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><AppIcon name="timer" />打开子流超时</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_open_stream_timeout_secs" suffix=" s" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_open_stream_timeout_secs', $event)" />
              <small>申请 Yamux 子流的超时。</small>
            </label>
            <label class="field">
              <span><AppIcon name="heart-pulse" />Keepalive</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_keepalive_interval_secs" suffix=" s" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_keepalive_interval_secs', $event)" />
              <small>Yamux 保活间隔；0 为关闭。</small>
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><AppIcon name="send" />写超时</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_connection_write_timeout_secs" suffix=" s" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_connection_write_timeout_secs', $event)" />
              <small>Yamux 写入超时。</small>
            </label>
            <label class="field">
              <span><AppIcon name="panels" />流控窗口</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_stream_window_size_kb" suffix=" KB" :min="256" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_stream_window_size_kb', $event)" />
              <small>单个 UDP 子流缓冲窗口。</small>
            </label>
          </div>
        </section>
      </template>
    </Card>
  </div>
</template>
