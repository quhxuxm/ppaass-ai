<script setup lang="ts">
import Card from "primevue/card";
import ConfigNumberInput from "../components/ConfigNumberInput.vue";
import InputText from "primevue/inputtext";
import Select from "primevue/select";
import Tag from "primevue/tag";
import Textarea from "primevue/textarea";
import { compressionOptions } from "../constants";
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
          <Tag value="TCP / UDP 共用" severity="info" />
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
        </div>
      </template>
    </Card>

    <Card class="panel span-12">
      <template #title>
        <div class="panel-heading inline">
          <h2>TCP</h2>
          <Tag value="普通 TCP 连接" severity="success" />
        </div>
      </template>
      <template #content>
        <section class="policy-section tcp-transport-note">
          <div class="section-heading">
            <div class="section-title">
              <span>TCP 转发</span>
              <Tag class="mode-effect-tag" value="HTTP / SOCKS5 / TUN" severity="secondary" />
            </div>
          </div>
          <p>TCP 目标连接使用独立的普通 TCP 连接承载。</p>
        </section>
      </template>
    </Card>

    <Card class="panel span-12">
      <template #title>
        <div class="panel-heading inline">
          <h2>UDP</h2>
          <Tag value="独立 UDP Yamux 池" severity="info" />
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
              <span><i class="pi pi-share-alt"></i>外层连接</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_sessions" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_sessions', $event)" />
              <small>限制 UDP relay raw Yamux 外层连接上限；实际连接数按需增长。</small>
            </label>
            <label class="field">
              <span><i class="pi pi-sitemap"></i>并发子流</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_max_streams_per_session" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_max_streams_per_session', $event)" />
              <small>限制单条 UDP Yamux session 同时承载的 UDP relay 子流数。</small>
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><i class="pi pi-stopwatch"></i>打开子流超时</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_open_stream_timeout_secs" suffix=" s" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_open_stream_timeout_secs', $event)" />
              <small>影响新 UDP relay 通道申请 Yamux 子流的等待时间。</small>
            </label>
            <label class="field">
              <span><i class="pi pi-heart"></i>Keepalive</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_keepalive_interval_secs" suffix=" s" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_keepalive_interval_secs', $event)" />
              <small>影响 UDP Yamux 外层连接的保活探测；0 表示关闭。</small>
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span><i class="pi pi-send"></i>写超时</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_connection_write_timeout_secs" suffix=" s" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_connection_write_timeout_secs', $event)" />
              <small>影响 UDP Yamux 外层连接写入帧的超时判断。</small>
            </label>
            <label class="field">
              <span><i class="pi pi-window-maximize"></i>流控窗口</span>
              <ConfigNumberInput :model-value="summary.udp_yamux_stream_window_size_kb" suffix=" KB" :min="256" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_stream_window_size_kb', $event)" />
              <small>影响每个 UDP relay Yamux 子流可缓冲的窗口大小。</small>
            </label>
          </div>
        </section>
      </template>
    </Card>
  </div>
</template>
