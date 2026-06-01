<script setup lang="ts">
import Card from "primevue/card";
import InputNumber from "primevue/inputnumber";
import InputText from "primevue/inputtext";
import Select from "primevue/select";
import SelectButton from "primevue/selectbutton";
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
          <span><i class="pi pi-server"></i>节点</span>
          <Textarea
            :model-value="summary.proxy_addrs.join('\n')"
            :disabled="configLocked"
            rows="5"
            auto-resize
            @update:model-value="emit('set-field', 'proxy_addrs', $event)"
          />
        </label>
        <div class="field-pair">
          <label class="field">
            <span><i class="pi pi-clock"></i>连接超时</span>
            <InputNumber
              :model-value="summary.connect_timeout_secs"
              :min="0"
              :allow-empty="false"
              :disabled="configLocked"
              :use-grouping="false"
              @update:model-value="emit('set-field', 'connect_timeout_secs', $event)"
            />
          </label>
          <label class="field">
            <span><i class="pi pi-box"></i>压缩</span>
            <Select :model-value="summary.compression_mode" :options="compressionOptions" :disabled="configLocked" @update:model-value="emit('set-field', 'compression_mode', $event)" />
          </label>
        </div>
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
      <template #title><h2>出口通道</h2></template>
      <template #content>
        <div class="field-pair">
          <label class="field">
            <span><i class="pi pi-clone"></i>TCP</span>
            <InputNumber :model-value="summary.tcp_pool_size" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_pool_size', $event)" />
          </label>
          <label class="field">
            <span><i class="pi pi-wave-pulse"></i>UDP</span>
            <InputNumber :model-value="summary.udp_pool_size" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_pool_size', $event)" />
          </label>
        </div>
        <div class="field-pair">
          <label class="field">
            <span><i class="pi pi-sliders-h"></i>TCP 传输</span>
            <SelectButton :model-value="summary.tcp_mode" :options="transportModeOptions" :allow-empty="false" :disabled="configLocked" @update:model-value="emit('set-field', 'tcp_mode', $event)" />
          </label>
          <label class="field">
            <span><i class="pi pi-sliders-h"></i>UDP 传输</span>
            <SelectButton :model-value="summary.udp_mode" :options="transportModeOptions" :allow-empty="false" :disabled="configLocked" @update:model-value="emit('set-field', 'udp_mode', $event)" />
          </label>
        </div>
        <div class="field-pair">
          <label class="field">
            <span><i class="pi pi-share-alt"></i>TCP Yamux</span>
            <InputNumber :model-value="summary.tcp_yamux_sessions" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'tcp_yamux_sessions', $event)" />
          </label>
          <label class="field">
            <span><i class="pi pi-share-alt"></i>UDP Yamux</span>
            <InputNumber :model-value="summary.udp_yamux_sessions" :min="0" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'udp_yamux_sessions', $event)" />
          </label>
        </div>
      </template>
    </Card>
  </div>
</template>
