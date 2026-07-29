<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";
import Button from "primevue/button";
import Select from "primevue/select";
import AppIcon from "./AppIcon";
import type { ColorTheme } from "../colorThemes";
import type { AppLocale } from "../i18n";
import { shortPath } from "../formatters";

defineProps<{
  subtitle: string;
  running: boolean;
  configLocked: boolean;
  configAvailable: boolean;
  canRestoreDefaultConfig: boolean;
  dirty: boolean;
  busy: boolean;
  colorTheme: ColorTheme;
  colorThemes: readonly { value: ColorTheme; label: string; mode: "dark" | "light" }[];
  language: AppLocale;
  languages: ReadonlyArray<{ value: AppLocale; label: string }>;
  pid?: number | null;
  configPath?: string | null;
}>();

const emit = defineEmits<{
  reload: [];
  "restore-default-config": [];
  save: [];
  start: [];
  stop: [];
  "update:color-theme": [theme: ColorTheme];
  "update:language": [language: AppLocale];
}>();

const morePanel = ref<HTMLDetailsElement | null>(null);

function closeMorePanel() {
  if (morePanel.value) morePanel.value.open = false;
}

function handleOutsidePointer(event: PointerEvent) {
  if (morePanel.value?.open && !morePanel.value.contains(event.target as Node)) closeMorePanel();
}

function handleEscape(event: KeyboardEvent) {
  if (event.key === "Escape") closeMorePanel();
}

onMounted(() => {
  document.addEventListener("pointerdown", handleOutsidePointer);
  document.addEventListener("keydown", handleEscape);
});

onBeforeUnmount(() => {
  document.removeEventListener("pointerdown", handleOutsidePointer);
  document.removeEventListener("keydown", handleEscape);
});
</script>

<template>
  <header class="topbar">
    <div class="topbar-identity">
      <h1>桌面代理</h1>
      <p>{{ subtitle }}</p>
    </div>

    <div class="toolbar topbar-primary-actions">
      <div class="topbar-runtime-control">
        <div class="topbar-runtime-copy">
          <span>代理服务</span>
          <strong :class="{ running }">
            <i aria-hidden="true"></i>
            {{ running ? "运行中" : "已停止" }}
          </strong>
        </div>
        <Button
          v-if="running"
          class="topbar-power"
          severity="danger"
          rounded
          aria-label="停止代理"
          title="停止代理"
          :disabled="busy"
          @click="emit('stop')"
        >
          <template #icon="slotProps"><AppIcon :class="slotProps.class" name="stop" /></template>
        </Button>
        <Button
          v-else
          class="topbar-power"
          severity="primary"
          rounded
          aria-label="启动代理"
          title="启动代理"
          :disabled="busy"
          @click="emit('start')"
        >
          <template #icon="slotProps"><AppIcon :class="slotProps.class" name="play" /></template>
        </Button>
      </div>
      <details ref="morePanel" class="topbar-more">
        <summary title="更多" aria-label="更多">
          <AppIcon name="ellipsis" />
          <i v-if="dirty" class="topbar-more-alert" aria-label="有未保存的更改"></i>
        </summary>

        <div class="topbar-more-panel">
          <section class="topbar-more-section topbar-runtime-info">
            <div class="topbar-more-heading">
              <div>
                <strong>运行信息</strong>
                <span>当前代理进程与配置</span>
              </div>
              <i :class="{ running }" aria-hidden="true"></i>
            </div>
            <dl class="topbar-runtime-facts">
              <div>
                <dt>服务状态</dt>
                <dd :class="{ running }">{{ running ? "运行中" : "已停止" }}</dd>
              </div>
              <div>
                <dt>进程 ID</dt>
                <dd>{{ running && pid ? pid : "—" }}</dd>
              </div>
              <div>
                <dt>配置文件</dt>
                <dd :title="configPath ?? ''">{{ shortPath(configPath) }}</dd>
              </div>
            </dl>
          </section>

          <section class="topbar-more-section">
            <div class="topbar-more-heading">
              <div>
                <strong>配置管理</strong>
                <span>{{ dirty ? "有未保存的更改" : "配置已同步" }}</span>
              </div>
              <i :class="{ dirty }" aria-hidden="true"></i>
            </div>
            <div class="topbar-config-primary">
              <Button
                label="保存更改"
                :severity="dirty ? 'primary' : 'secondary'"
                :outlined="!dirty"
                :disabled="configLocked || !dirty || busy"
                @click="emit('save')"
              >
                <template #icon="slotProps"><AppIcon :class="slotProps.class" name="save" /></template>
              </Button>
            </div>
            <div class="topbar-config-secondary">
              <Button label="重新载入" severity="secondary" text :disabled="busy" @click="emit('reload')">
                <template #icon="slotProps"><AppIcon :class="slotProps.class" name="refresh" /></template>
              </Button>
              <Button
                label="恢复默认"
                severity="secondary"
                text
                :title="canRestoreDefaultConfig ? '恢复默认' : '当前账户没有查看原始配置的权限'"
                :disabled="!canRestoreDefaultConfig || !configAvailable || configLocked || busy"
                @click="emit('restore-default-config')"
              >
                <template #icon="slotProps"><AppIcon :class="slotProps.class" name="restore" /></template>
              </Button>
            </div>
          </section>

          <section class="topbar-more-section">
            <div class="topbar-more-heading">
              <div>
                <strong>界面设置</strong>
                <span>语言与外观</span>
              </div>
            </div>
            <div class="topbar-settings-fields">
              <label class="theme-picker" title="选择界面配色">
                <span class="theme-picker-dot" aria-hidden="true"></span>
                <span class="theme-picker-label">配色</span>
                <Select
                  :model-value="colorTheme"
                  :options="colorThemes"
                  option-label="label"
                  option-value="value"
                  aria-label="配色风格"
                  @update:model-value="emit('update:color-theme', $event as ColorTheme)"
                />
              </label>
              <label class="theme-picker" title="选择界面语言">
                <AppIcon name="languages" />
                <span class="theme-picker-label">语言</span>
                <Select
                  :model-value="language"
                  :options="languages"
                  option-label="label"
                  option-value="value"
                  aria-label="选择界面语言"
                  @update:model-value="emit('update:language', $event as AppLocale)"
                />
              </label>
            </div>
          </section>
        </div>
      </details>
    </div>
  </header>
</template>
