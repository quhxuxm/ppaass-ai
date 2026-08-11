<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import ProgressSpinner from "primevue/progressspinner";
import AppIcon, { type AppIconName } from "./AppIcon";
import { useProxyEntrySelection } from "../composables/useProxyEntrySelection";
import type { AgentProxyEntry } from "../types";

const emit = defineEmits<{ switched: [] }>();
const controller = useProxyEntrySelection();
const {
  canConfirm,
  choose,
  close,
  confirm,
  error,
  loading,
  open,
  orderedEntries,
  pendingId,
  runSpeedTest,
  selection,
  speedResults,
  switching,
  testingId,
  visible
} = controller;

async function confirmSelection() {
  if (await confirm()) emit("switched");
}

function stateLabel(entry: AgentProxyEntry) {
  if (entry.proxy_entry_id === selection.value.selected_proxy_entry_id) return "当前";
  if (entry.proxy_entry_id === pendingId.value) return "待切换";
  return "";
}

const entryIcons: readonly AppIconName[] = [
  "building",
  "globe",
  "cloud",
  "radio-tower",
  "map-pin",
  "server"
];

function hashIcon(value: string) {
  let hash = 0;
  for (const character of value) {
    hash = (hash * 31 + character.codePointAt(0)!) | 0;
  }
  return Math.abs(hash) % entryIcons.length;
}

function entryIconName(entry: AgentProxyEntry) {
  return entryIcons[hashIcon(entry.icon_key)] ?? "server";
}
</script>

<template>
  <Button
    class="proxy-entry-trigger"
    label="节点"
    severity="secondary"
    outlined
    :loading="loading && !visible"
    @click="open"
  >
    <template #icon="slotProps">
      <AppIcon :class="slotProps.class" name="server" />
    </template>
  </Button>

  <Dialog
    v-model:visible="visible"
    modal
    class="proxy-entry-dialog"
    :style="{ width: 'min(94vw, 860px)' }"
    :closable="!switching"
    :close-on-escape="!switching"
    @hide="close"
  >
    <template #header>
      <div class="proxy-entry-dialog-heading">
        <span><AppIcon name="network" /></span>
        <div>
          <h2>选择 Proxy Entry</h2>
          <p>当前节点已置顶；选择后点击确认才会切换</p>
        </div>
      </div>
    </template>

    <div v-if="loading" class="proxy-entry-loading">
      <ProgressSpinner />
      <span>正在同步可用节点</span>
    </div>
    <div v-else-if="!orderedEntries.length" class="proxy-entry-empty">
      <AppIcon name="server" />
      <strong>暂无可用 Proxy Entry</strong>
    </div>
    <div v-else class="proxy-entry-list" role="radiogroup" aria-label="可用 Proxy Entry">
      <div
        v-for="entry in orderedEntries"
        :key="entry.proxy_entry_id"
        class="proxy-entry-option"
        :class="{
          current: entry.proxy_entry_id === selection.selected_proxy_entry_id,
          pending:
            entry.proxy_entry_id === pendingId &&
            entry.proxy_entry_id !== selection.selected_proxy_entry_id
        }"
        role="radio"
        :aria-checked="entry.proxy_entry_id === pendingId"
        tabindex="0"
        @click="choose(entry)"
        @keydown.enter.prevent="choose(entry)"
        @keydown.space.prevent="choose(entry)"
      >
        <span class="proxy-entry-icon large">
          <AppIcon :name="entryIconName(entry)" />
        </span>
        <span class="proxy-entry-option-copy">
          <strong>{{ entry.label }}</strong>
          <span>{{ entry.description }}</span>
          <span class="proxy-entry-meta-line">
            <i :class="{ offline: entry.online === false }" />
            {{ entry.online === false ? "状态未知" : "在线" }}
            <em :class="{ visible: Boolean(stateLabel(entry)) }">
              {{ stateLabel(entry) || "节点状态" }}
            </em>
          </span>
          <span
            class="proxy-entry-speed-result"
            :class="{
              visible:
                entry.proxy_entry_id === testingId ||
                Boolean(speedResults[entry.proxy_entry_id])
            }"
          >
            {{
              entry.proxy_entry_id === testingId
                ? "正在测速…"
                : speedResults[entry.proxy_entry_id] || "测速结果"
            }}
          </span>
        </span>
        <span class="proxy-entry-actions">
          <Button
            :label="entry.proxy_entry_id === testingId ? '测速中' : '测速'"
            size="small"
            severity="info"
            outlined
            :loading="entry.proxy_entry_id === testingId"
            :disabled="Boolean(testingId) || switching"
            @click.stop="runSpeedTest(entry)"
          />
        </span>
      </div>
    </div>

    <p v-if="error" class="proxy-entry-error" role="alert">{{ error }}</p>

    <template #footer>
      <Button label="取消" severity="secondary" text :disabled="switching" @click="close" />
      <Button
        :label="switching ? '正在切换…' : '确认切换'"
        :loading="switching"
        :disabled="!canConfirm"
        @click="confirmSelection"
      />
    </template>
  </Dialog>
</template>

<style scoped src="../styles/proxy-entry-selector.css"></style>
