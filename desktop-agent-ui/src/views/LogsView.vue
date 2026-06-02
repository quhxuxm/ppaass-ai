<script setup lang="ts">
import { computed } from "vue";
import Button from "primevue/button";
import Card from "primevue/card";
import { tokenizeLogLine } from "../highlighters";

const props = defineProps<{
  logs: string[];
}>();

const emit = defineEmits<{
  refresh: [];
}>();

const highlightedLogs = computed(() => props.logs.map(tokenizeLogLine));
</script>

<template>
  <Card class="panel full-height">
    <template #title>
      <div class="panel-heading inline">
        <h2>日志</h2>
        <Button icon="pi pi-refresh" label="刷新" severity="secondary" outlined size="small" @click="emit('refresh')" />
      </div>
    </template>
    <template #content>
      <div class="log-view">
        <div v-if="!logs.length" class="log-empty">暂无日志</div>
        <template v-else>
          <div
            v-for="(entry, index) in highlightedLogs"
            :key="index"
            :class="['log-line', entry.level ? `log-line-${entry.level}` : '']"
            :title="entry.raw"
          >
            <span
              v-for="(token, tokenIndex) in entry.tokens"
              :key="tokenIndex"
              :class="['log-token', `log-${token.kind}`]"
            >{{ token.value }}</span>
          </div>
        </template>
      </div>
    </template>
  </Card>
</template>
