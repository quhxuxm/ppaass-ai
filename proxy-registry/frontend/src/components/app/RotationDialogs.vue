<script setup lang="ts">
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Textarea from 'primevue/textarea'
import { useAppControllerContext } from '../../appController'

const {
  keyRotationLoading,
  managedUsername,
  ownRotationReason,
  ownRotationVisible,
  rotateAdminKey,
  rotateOwnKey,
  rotatingUsername,
  rotationReason,
  rotationUser,
  rotationVisible,
} = useAppControllerContext()
</script>

<template>
<Dialog
  v-model:visible="ownRotationVisible"
  modal
  header="重新生成自己的密钥"
  class="form-dialog"
  :style="{ width: 'min(92vw, 520px)' }"
  :closable="!keyRotationLoading"
>
  <div class="dialog-form">
    <p class="dialog-lead">
      旧连接凭据会立即失效。管理员操作将写入审计记录，请填写原因。
    </p>
    <div class="form-field">
      <label for="own-rotation-reason">重生成原因</label>
      <Textarea
        id="own-rotation-reason"
        v-model="ownRotationReason"
        rows="4"
        maxlength="500"
        placeholder="说明为什么需要重新生成自己的密钥"
        :disabled="keyRotationLoading"
        fluid
      />
      <small>{{ Array.from(ownRotationReason).length }} / 500，必填。</small>
    </div>
  </div>
  <template #footer>
    <Button
      label="取消"
      severity="secondary"
      text
      :disabled="keyRotationLoading"
      @click="ownRotationVisible = false"
    />
    <Button
      label="生成新密钥"
      icon="pi pi-refresh"
      severity="danger"
      :loading="keyRotationLoading"
      :disabled="!ownRotationReason.trim()"
      @click="rotateOwnKey(ownRotationReason)"
    />
  </template>
</Dialog>

<Dialog
  v-model:visible="rotationVisible"
  modal
  header="重新生成用户密钥"
  class="form-dialog"
  :style="{ width: 'min(92vw, 520px)' }"
  :closable="!rotatingUsername"
>
  <div v-if="rotationUser" class="dialog-form">
    <p class="dialog-lead">
      将为“{{ managedUsername(rotationUser) }}”生成新密钥，旧私钥会立即失效。
    </p>
    <div class="form-field">
      <label for="rotation-reason">重生成原因</label>
      <Textarea
        id="rotation-reason"
        v-model="rotationReason"
        rows="4"
        maxlength="500"
        placeholder="说明为什么需要重新生成该用户的密钥"
        :disabled="Boolean(rotatingUsername)"
        fluid
      />
      <small>{{ Array.from(rotationReason).length }} / 500，必填。</small>
    </div>
  </div>
  <template #footer>
    <Button
      label="取消"
      severity="secondary"
      text
      :disabled="Boolean(rotatingUsername)"
      @click="rotationVisible = false"
    />
    <Button
      label="生成新密钥"
      icon="pi pi-refresh"
      severity="danger"
      :loading="Boolean(rotatingUsername)"
      @click="rotationUser && rotateAdminKey(rotationUser)"
    />
  </template>
</Dialog>
</template>
