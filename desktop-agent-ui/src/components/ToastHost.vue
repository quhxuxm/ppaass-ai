<script setup lang="ts">
import type { ToastKind } from "../types";

defineProps<{
  toast: null | { kind: ToastKind; message: string };
}>();
</script>

<template>
  <Transition name="toast">
    <div v-if="toast" :class="['toast', toast.kind]">{{ toast.message }}</div>
  </Transition>
</template>
