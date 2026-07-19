<script setup lang="ts">
import { ref, watch } from "vue";
import InputNumber from "primevue/inputnumber";

defineOptions({
  inheritAttrs: false
});

const props = withDefaults(
  defineProps<{
    modelValue: number;
    min?: number;
    max?: number;
    suffix?: string;
    disabled?: boolean;
    useGrouping?: boolean;
    allowEmpty?: boolean;
  }>(),
  {
    min: undefined,
    max: undefined,
    suffix: undefined,
    disabled: false,
    useGrouping: false,
    allowEmpty: true
  }
);

const emit = defineEmits<{
  "update:modelValue": [value: number];
}>();

const focused = ref(false);
const draftValue = ref<number | null>(props.modelValue);

watch(
  () => props.modelValue,
  (value) => {
    if (!focused.value || draftValue.value !== null) {
      draftValue.value = value;
    }
  }
);

function updateDraft(value: number | null) {
  draftValue.value = value;
  if (value !== null) {
    emit("update:modelValue", value);
  }
}

function restoreEmptyDraft() {
  focused.value = false;
  if (draftValue.value === null) {
    draftValue.value = props.modelValue;
  }
}
</script>

<template>
  <InputNumber
    v-bind="$attrs"
    :model-value="draftValue"
    :min="min"
    :max="max"
    :suffix="suffix"
    :disabled="disabled"
    :use-grouping="useGrouping"
    :allow-empty="allowEmpty"
    @focus="focused = true"
    @blur="restoreEmptyDraft"
    @update:model-value="updateDraft"
  />
</template>
