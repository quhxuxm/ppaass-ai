<script setup lang="ts">
import { computed, ref } from "vue";
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

const props = defineProps<{
  summary: AgentConfigSummary;
  configLocked: boolean;
  directModeLabel: string;
  activeForwardingLabel: string;
  tunModeLabel: string;
  directRuleGroups: DirectRuleGroup[];
  ruleDraft: string;
}>();

const activeRuleGroupKey = ref("");
const activeRuleGroup = computed(
  () =>
    props.directRuleGroups.find((group) => group.key === activeRuleGroupKey.value) ??
    props.directRuleGroups[0] ??
    null
);
const populatedRuleGroupCount = computed(
  () => props.directRuleGroups.filter((group) => group.items.length > 0).length
);

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
                  <p>HTTP/SOCKS5 支持域名规则，如 example.com、*.example.com。</p>
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
                  <p>TUN 建议使用固定 IP/CIDR，如 192.168.0.0/16。</p>
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
                  <p>域名规则需开启代理 DNS，并在 DNS 缓存命中后生效。</p>
                </div>
              </div>
            </div>
          </template>
        </Card>

        <Card class="panel span-12">
          <template #title>
            <div class="panel-heading inline">
              <h2>规则管理</h2>
              <Tag :value="`${summary.direct_rules.length} 条`" severity="info" />
            </div>
          </template>
          <template #content>
            <div class="rule-manager">
              <div class="rule-editor-grid">
                <section class="rule-presets">
                  <div class="section-heading">
                    <span>快捷预设</span>
                    <strong>{{ directRulePresets.length }} 项</strong>
                  </div>
                  <div class="preset-list compact">
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
                </section>

                <section class="rule-create">
                  <div class="section-heading">
                    <span>添加规则</span>
                    <strong>{{ directModeLabel }}</strong>
                  </div>
                  <div class="rule-scope-note">
                    <AppIcon name="info" />
                    <span>HTTP / SOCKS5 可填域名；TUN 优先填 IP/CIDR；TUN 域名规则需开启代理 DNS。</span>
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
              </div>

              <section class="rule-inventory">
                <div class="section-heading">
                  <span>当前规则</span>
                  <strong>{{ populatedRuleGroupCount }} 组 · {{ summary.direct_rules.length }} 条</strong>
                </div>
                <div v-if="!summary.direct_rules.length" class="empty-rules">未配置</div>
                <template v-else>
                  <div class="rule-type-tabs" role="tablist" aria-label="直连规则类型">
                    <button
                      v-for="group in directRuleGroups"
                      :key="group.key"
                      type="button"
                      role="tab"
                      :aria-selected="activeRuleGroup?.key === group.key"
                      :class="{ active: activeRuleGroup?.key === group.key }"
                      @click="activeRuleGroupKey = group.key"
                    >
                      <AppIcon :name="group.icon" />
                      <span>{{ group.label }}</span>
                      <strong>{{ group.items.length }}</strong>
                    </button>
                  </div>
                  <div
                    v-if="activeRuleGroup"
                    :key="activeRuleGroup.key"
                    class="rule-table"
                    role="table"
                    :aria-label="`${activeRuleGroup.label}直连规则`"
                  >
                    <section class="rule-table-group" role="rowgroup">
                    <div class="rule-table-group-heading">
                      <div class="rule-table-group-title">
                        <AppIcon :name="activeRuleGroup.icon" />
                        <span>{{ activeRuleGroup.label }}</span>
                        <strong>{{ activeRuleGroup.items.length }}</strong>
                      </div>
                      <span>{{ activeRuleGroup.modes.join(" · ") }}</span>
                    </div>
                    <div v-if="!activeRuleGroup.items.length" class="rule-table-empty">
                      暂无{{ activeRuleGroup.label }}规则
                    </div>
                    <div
                      v-for="item in activeRuleGroup.items"
                      :key="`${activeRuleGroup.key}-${item.rule}-${item.index}`"
                      class="rule-table-row"
                      role="row"
                    >
                      <code :title="item.rule" role="cell">{{ item.rule }}</code>
                      <span class="rule-table-scope" role="cell">{{ activeRuleGroup.modes.join(" / ") }}</span>
                      <div class="rule-table-action" role="cell">
                        <button
                          type="button"
                          class="rule-table-remove"
                          :aria-label="`删除规则 ${item.rule}`"
                          :disabled="configLocked"
                          @click="emit('remove-direct-rule', item.index)"
                        >
                          <span class="rule-chip-remove-mark" aria-hidden="true"></span>
                        </button>
                      </div>
                    </div>
                  </section>
                  </div>
                </template>
              </section>
            </div>
          </template>
        </Card>
      </div>
    </section>
  </div>
</template>
