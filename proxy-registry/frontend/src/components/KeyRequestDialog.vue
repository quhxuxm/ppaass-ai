<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Textarea from 'primevue/textarea'
import { KEY_REQUEST_MESSAGE_MAX_LENGTH } from '../api/types'

const props = defineProps<{
  visible: boolean
  loading: boolean
  renewal: boolean
}>()

const emit = defineEmits<{
  'update:visible': [visible: boolean]
  submit: [message: string | null]
}>()

const message = ref('')
const messageLength = computed(() => Array.from(message.value).length)
const messageTooLong = computed(
  () => messageLength.value > KEY_REQUEST_MESSAGE_MAX_LENGTH,
)

watch(
  () => props.visible,
  (visible) => {
    if (visible) {
      message.value = ''
    }
  },
)

function updateVisible(visible: boolean): void {
  if (!props.loading) {
    emit('update:visible', visible)
  }
}

function updateMessage(value: string | undefined): void {
  message.value = Array.from(value ?? '')
    .slice(0, KEY_REQUEST_MESSAGE_MAX_LENGTH)
    .join('')
}

function submit(): void {
  if (props.loading || messageTooLong.value) {
    return
  }
  emit('submit', message.value.trim() || null)
}
</script>

<template>
  <Dialog
    :visible="visible"
    modal
    :header="renewal ? '申请续期并生成新密钥' : '申请生成密钥'"
    class="key-request-dialog"
    :style="{ width: 'min(92vw, 560px)' }"
    :closable="!loading"
    :close-on-escape="!loading"
    @update:visible="updateVisible"
  >
    <p class="key-request-dialog-intro">
      管理员会在审批时设置密钥有效期。你可以附上一段留言，说明用途或期望的有效期。
    </p>
    <form id="key-request-form" @submit.prevent="submit">
      <label class="key-request-message-field" for="key-request-message">
        <span>给管理员的留言 <small>可选</small></span>
        <Textarea
          id="key-request-message"
          :model-value="message"
          rows="7"
          placeholder="例如：用于出差期间连接，期望有效至本月底"
          aria-describedby="key-request-message-help"
          fluid
          @update:model-value="updateMessage"
        />
      </label>
      <div
        id="key-request-message-help"
        class="key-request-message-help"
        :class="{ invalid: messageTooLong }"
      >
        <small>留言仅用于本次审批，不会写入代理配置。</small>
        <span>{{ messageLength }} / {{ KEY_REQUEST_MESSAGE_MAX_LENGTH }}</span>
      </div>
    </form>
    <template #footer>
      <Button
        label="取消"
        severity="secondary"
        text
        :disabled="loading"
        @click="updateVisible(false)"
      />
      <Button
        type="submit"
        form="key-request-form"
        label="确认提交申请"
        icon="pi pi-send"
        :loading="loading"
        :disabled="messageTooLong"
      />
    </template>
  </Dialog>
</template>

<style scoped>
.key-request-dialog-intro {
  margin: 0 0 18px;
  color: #667085;
  font-size: 0.8rem;
  line-height: 1.6;
}

.key-request-message-field {
  display: grid;
  gap: 8px;
}

.key-request-message-field > span {
  color: #344054;
  font-size: 0.78rem;
  font-weight: 650;
}

.key-request-message-field small {
  color: #98a2b3;
  font-weight: 500;
}

.key-request-message-field :deep(textarea) {
  min-height: 132px;
  max-height: 230px;
  line-height: 1.55;
  resize: vertical;
}

.key-request-message-help {
  display: flex;
  justify-content: space-between;
  gap: 14px;
  margin-top: 7px;
  color: #98a2b3;
  font-size: 0.68rem;
}

.key-request-message-help.invalid {
  color: #d92d20;
}

@media (max-width: 560px) {
  .key-request-message-help {
    align-items: flex-end;
    flex-direction: column;
    gap: 3px;
  }
}
</style>
