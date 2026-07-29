<script setup lang="ts">
import { computed, ref, watch } from "vue";
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import Message from "primevue/message";
import Password from "primevue/password";

const props = defineProps<{
  busy: boolean;
  error: string;
  initialPassword: string;
  visible: boolean;
}>();

const emit = defineEmits<{
  close: [];
  confirm: [password: string];
}>();

const password = ref("");
const canConfirm = computed(() => !props.busy && password.value.length >= 8);

watch(
  () => props.visible,
  (visible) => {
    if (visible) {
      password.value = props.initialPassword;
    } else {
      password.value = "";
    }
  }
);

function confirm() {
  if (canConfirm.value) {
    emit("confirm", password.value);
  }
}
</script>

<template>
  <Dialog
    :visible="visible"
    modal
    header="生成新密钥"
    :closable="!busy"
    :close-on-escape="!busy"
    class="rotate-key-dialog"
    @update:visible="$event || emit('close')"
  >
    <form class="rotate-key-form" @submit.prevent="confirm">
      <p>
        新密钥会直接下载并应用到 Agent，私钥不会显示。若 Agent 正在运行，应用后会自动重启。
      </p>
      <Message v-if="error" severity="error" :closable="false">
        {{ error }}
      </Message>
      <label for="rotate-key-password">当前密码</label>
      <Password
        v-model="password"
        input-id="rotate-key-password"
        autocomplete="current-password"
        placeholder="输入当前密码"
        :feedback="false"
        :disabled="busy"
        toggle-mask
        fluid
      />
    </form>

    <template #footer>
      <Button
        label="取消"
        severity="secondary"
        text
        :disabled="busy"
        @click="emit('close')"
      />
      <Button
        label="确认生成并应用"
        :loading="busy"
        :disabled="!canConfirm"
        @click="confirm"
      />
    </template>
  </Dialog>
</template>
