<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import AppIcon from "../components/AppIcon";
import ConfigNumberInput from "../components/ConfigNumberInput.vue";
import InputText from "primevue/inputtext";
import Select from "primevue/select";
import SelectButton from "primevue/selectbutton";
import Tag from "primevue/tag";
import { directModeOptions, directRulePresets, logLevelOptions } from "../constants";
import type { AgentConfigSummary, DirectRuleGroup } from "../types";

defineProps<{
  summary: AgentConfigSummary;
  configLocked: boolean;
  directModeLabel: string;
  activeForwardingLabel: string;
  tunModeLabel: string;
  directRuleGroups: DirectRuleGroup[];
  ruleDraft: string;
}>();

const emit = defineEmits<{
  "set-field": [field: keyof AgentConfigSummary, value: unknown];
  "update:ruleDraft": [value: string];
  "add-direct-rules": [rules: string[]];
  "add-draft-rules": [];
  "remove-direct-rule": [index: number];
}>();
</script>

<template>
  <div class="content-grid">
    <section class="card-group span-12">
      <div class="card-group-heading">
        <div>
          <h2>系统运行参数</h2>
          <p>{{ summary.log_level }} · {{ summary.effective_runtime_threads }} 线程</p>
        </div>
        <Tag value="全局" severity="secondary" />
      </div>
      <div class="content-grid">
        <Card class="panel span-12">
          <template #title><h2>运行参数</h2></template>
          <template #content>
            <div class="field-pair">
              <label class="field">
                <span><AppIcon name="scroll-text" />日志</span>
                <Select :model-value="summary.log_level" :options="logLevelOptions" :disabled="configLocked" @update:model-value="emit('set-field', 'log_level', $event)" />
              </label>
              <label class="field">
                <span><AppIcon name="cpu" />线程</span>
                <ConfigNumberInput :model-value="summary.effective_runtime_threads" :min="1" :allow-empty="false" :disabled="configLocked" :use-grouping="false" @update:model-value="emit('set-field', 'runtime_threads', $event)" />
              </label>
            </div>
          </template>
        </Card>
      </div>
    </section>

    <section class="card-group span-12">
      <div class="card-group-heading">
        <div>
          <h2>流量策略</h2>
          <p>direct_access</p>
        </div>
        <Tag :value="directModeLabel" severity="info" />
      </div>
      <div class="content-grid">
        <Card class="panel span-12">
          <template #title>
            <div class="panel-heading inline">
              <h2>共享直连策略</h2>
              <Tag :value="directModeLabel" severity="info" />
            </div>
          </template>
          <template #content>
            <div class="policy-grid">
              <label class="field direct-mode-field">
                <span><AppIcon name="route" />模式</span>
                <SelectButton
                  :model-value="summary.direct_mode"
                  :options="directModeOptions"
                  option-label="label"
                  option-value="value"
                  :allow-empty="false"
                  :disabled="configLocked"
                  @update:model-value="emit('set-field', 'direct_mode', $event)"
                />
              </label>
              <div class="policy-facts">
                <div class="policy-fact"><span>当前转发</span><strong>{{ activeForwardingLabel }}</strong></div>
                <div class="policy-fact"><span>规则数量</span><strong>{{ summary.direct_rules.length }} 条</strong></div>
                <div class="policy-fact"><span>配置段</span><strong>direct_access</strong></div>
              </div>
            </div>
            <div class="forwarding-methods">
              <div class="forwarding-method">
                <AppIcon name="server" />
                <div>
                  <span>HTTP / SOCKS5 代理</span>
                  <strong>{{ summary.listen_addr }}</strong>
                </div>
              </div>
              <div class="forwarding-method">
                <AppIcon name="compass" />
                <div>
                  <span>TUN 模式</span>
                  <strong>{{ tunModeLabel }} · {{ summary.tun_name }}</strong>
                </div>
              </div>
            </div>
            <!-- 直连规则的页面说明以“怎么配置、何时生效”为主，避免把实现细节当成用户操作指南。 -->
            <div class="rule-scope-grid">
              <div class="rule-scope-item">
                <AppIcon name="globe" />
                <div>
                  <span>代理入口填域名</span>
                  <div class="rule-scope-modes">
                    <Tag value="HTTP" severity="info" rounded />
                    <Tag value="SOCKS5" severity="info" rounded />
                  </div>
                  <p>使用 HTTP / SOCKS5 时，可添加 example.com 或 *.example.com，让这些域名直接访问。</p>
                </div>
              </div>
              <div class="rule-scope-item">
                <AppIcon name="hash" />
                <div>
                  <span>TUN 优先填 IP/CIDR</span>
                  <div class="rule-scope-modes">
                    <Tag value="TUN" severity="success" rounded />
                    <Tag value="IP/CIDR" severity="secondary" rounded />
                  </div>
                  <p>TUN 模式下更适合添加固定 IP 或网段，例如 192.168.0.0/16、10.0.0.0/8。</p>
                </div>
              </div>
              <div class="rule-scope-item">
                <AppIcon name="database" />
                <div>
                  <span>TUN 域名规则</span>
                  <div class="rule-scope-modes">
                    <Tag value="TUN" severity="success" rounded />
                    <Tag value="需代理 DNS" severity="warn" rounded />
                  </div>
                  <p>需要先开启代理 DNS；浏览器或应用完成 DNS 查询后，命中缓存的域名规则才会生效。</p>
                </div>
              </div>
            </div>
          </template>
        </Card>

        <Card class="panel span-5">
          <template #title><h2>快捷预设</h2></template>
          <template #content>
            <div class="preset-list">
              <Button
                v-for="preset in directRulePresets"
                :key="preset.label"
                :label="preset.label"
                severity="secondary"
                outlined
                :disabled="configLocked"
                @click="emit('add-direct-rules', preset.rules)"
              >
                <template #icon="slotProps"><AppIcon :class="slotProps.class" :name="preset.icon" /></template>
              </Button>
            </div>
          </template>
        </Card>

        <Card class="panel span-7">
          <template #title>
            <div class="panel-heading inline">
              <h2>规则管理</h2>
              <Tag :value="`${summary.direct_rules.length} 条`" severity="info" />
            </div>
          </template>
          <template #content>
            <div class="rule-manager">
              <section class="rule-create">
                <div class="section-heading">
                  <span>添加规则</span>
                  <strong>{{ directModeLabel }}</strong>
                </div>
                <div class="rule-scope-note">
                  <AppIcon name="info" />
                  <span>添加前先看入口：HTTP / SOCKS5 可填域名；TUN 优先填 IP/CIDR；TUN 域名规则需要开启代理 DNS 并等待 DNS 缓存命中。</span>
                </div>
                <div class="rule-compose">
                  <label class="field rule-input-field">
                    <span><AppIcon name="circle-plus" />规则值</span>
                    <InputText
                      :model-value="ruleDraft"
                      placeholder="example.com / *.example.com / 10.0.0.0/8"
                      :disabled="configLocked"
                      @keydown.enter.prevent="emit('add-draft-rules')"
                      @update:model-value="emit('update:ruleDraft', String($event))"
                    />
                  </label>
                  <Button label="添加" severity="primary" :disabled="configLocked" @click="emit('add-draft-rules')">
                    <template #icon="slotProps"><AppIcon :class="slotProps.class" name="plus" /></template>
                  </Button>
                </div>
              </section>

              <section class="rule-inventory">
                <div class="section-heading">
                  <span>当前规则</span>
                  <strong>{{ directRuleGroups.length }} 组</strong>
                </div>
                <div v-if="!summary.direct_rules.length" class="empty-rules">未配置</div>
                <div v-else class="rule-group-list">
                  <section v-for="group in directRuleGroups" :key="group.key" class="rule-group">
                    <div class="rule-group-heading">
                      <div>
                        <AppIcon :name="group.icon" />
                        <span>{{ group.label }}</span>
                      </div>
                      <div class="rule-group-modes">
                        <Tag v-for="mode in group.modes" :key="`${group.key}-${mode}`" :value="mode" severity="secondary" rounded />
                      </div>
                      <strong>{{ group.items.length }}</strong>
                    </div>
                    <div class="rule-chip-list grouped">
                      <div v-for="item in group.items" :key="`${group.key}-${item.rule}-${item.index}`" class="rule-chip">
                        <span :title="item.rule">{{ item.rule }}</span>
                        <button type="button" class="rule-chip-remove" aria-label="删除" :disabled="configLocked" @click="emit('remove-direct-rule', item.index)">
                          <span class="rule-chip-remove-mark" aria-hidden="true"></span>
                        </button>
                      </div>
                    </div>
                  </section>
                </div>
              </section>
            </div>
          </template>
        </Card>
      </div>
    </section>
  </div>
</template>
