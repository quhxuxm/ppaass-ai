<script setup lang="ts">
import { computed, ref } from "vue";
import Card from "primevue/card";
import Textarea from "primevue/textarea";
import { shortPath } from "../formatters";
import { tokenizeToml } from "../highlighters";

const props = defineProps<{
  raw: string;
  path?: string | null;
  configLocked: boolean;
}>();

const emit = defineEmits<{
  "update:raw": [value: string];
}>();

const tomlHighlightRef = ref<HTMLElement | null>(null);
const highlightedToml = computed(() => tokenizeToml(props.raw));

function syncTomlHighlightScroll(event: Event) {
  const target = event.currentTarget as HTMLTextAreaElement | null;
  const highlighter = tomlHighlightRef.value;
  if (!target || !highlighter) {
    return;
  }
  highlighter.scrollTop = target.scrollTop;
  highlighter.scrollLeft = target.scrollLeft;
}
</script>

<template>
  <Card class="panel full-height">
    <template #title>
      <div class="panel-heading inline">
        <h2>TOML</h2>
        <span :title="path ?? ''">{{ shortPath(path) }}</span>
      </div>
    </template>
    <template #content>
      <div class="toml-editor-shell">
        <pre ref="tomlHighlightRef" class="toml-highlight" aria-hidden="true"><code><span
          v-for="(line, lineIndex) in highlightedToml"
          :key="lineIndex"
          class="toml-line"
        ><span
          v-for="(token, tokenIndex) in line.tokens"
          :key="tokenIndex"
          :class="['toml-token', `toml-${token.kind}`]"
        >{{ token.value }}</span>{{ lineIndex < highlightedToml.length - 1 ? "\n" : "" }}</span></code></pre>
        <Textarea
          class="toml-editor"
          :model-value="raw"
          :readonly="configLocked"
          spellcheck="false"
          autocapitalize="off"
          autocomplete="off"
          autocorrect="off"
          wrap="off"
          @scroll="syncTomlHighlightScroll"
          @update:model-value="emit('update:raw', String($event))"
        />
      </div>
    </template>
  </Card>
</template>
