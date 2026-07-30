<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Avatar from 'primevue/avatar'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import type { AccountSummary, UpdateMyProfilePayload } from '../api'

const props = defineProps<{
  account: AccountSummary
  saving: boolean
}>()

const emit = defineEmits<{
  save: [payload: UpdateMyProfilePayload]
}>()

const MAX_NICKNAME_CHARACTERS = 6
const MAX_AVATAR_BYTES = 1024 * 1024
const AVATAR_SIZE = 64
const nickname = ref('')
const avatarPreview = ref<string | null>(null)
const avatarChanged = ref(false)
const error = ref('')
const fileInput = ref<HTMLInputElement | null>(null)

watch(
  () => props.account,
  (account) => {
    nickname.value = account.displayName ?? ''
    avatarPreview.value = account.avatarUrl ?? null
    avatarChanged.value = false
    error.value = ''
  },
  { immediate: true },
)

const nicknameLength = computed(() => Array.from(nickname.value.trim()).length)
const avatarLabel = computed(() =>
  (nickname.value.trim() || props.account.username || 'U')
    .slice(0, 1)
    .toUpperCase(),
)

function chooseAvatar(): void {
  fileInput.value?.click()
}

async function onAvatarSelected(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
    error.value = '头像只支持 PNG、JPEG 或 WebP 格式'
    return
  }
  if (file.size > MAX_AVATAR_BYTES) {
    error.value = '头像文件不能超过 1 MiB'
    return
  }
  try {
    avatarPreview.value = await resizeAvatar(file)
    avatarChanged.value = true
    error.value = ''
  } catch {
    error.value = '无法处理头像图片'
  }
}

function removeAvatar(): void {
  avatarPreview.value = null
  avatarChanged.value = true
  error.value = ''
}

function submit(): void {
  const normalizedNickname = nickname.value.trim()
  if (Array.from(normalizedNickname).length > MAX_NICKNAME_CHARACTERS) {
    error.value = '昵称不能超过 6 个字符'
    return
  }
  emit('save', {
    display_name: normalizedNickname || null,
    ...(avatarChanged.value ? { avatar_data_url: avatarPreview.value } : {}),
  })
}

function readAsDataUrl(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () =>
      typeof reader.result === 'string' ? resolve(reader.result) : reject()
    reader.onerror = () => reject(reader.error)
    reader.readAsDataURL(file)
  })
}

async function resizeAvatar(file: File): Promise<string> {
  const url = URL.createObjectURL(file)
  try {
    const image = await loadImage(url)
    const canvas = document.createElement('canvas')
    canvas.width = AVATAR_SIZE
    canvas.height = AVATAR_SIZE
    const context = canvas.getContext('2d')
    if (!context) throw new Error('Canvas is unavailable')
    context.drawImage(image, 0, 0, AVATAR_SIZE, AVATAR_SIZE)
    const avatar = await canvasToPng(canvas)
    if (avatar.size > MAX_AVATAR_BYTES) {
      throw new Error('Resized avatar is too large')
    }
    return readAsDataUrl(avatar)
  } finally {
    URL.revokeObjectURL(url)
  }
}

function loadImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image()
    image.onload = () => {
      image.naturalWidth > 0 && image.naturalHeight > 0
        ? resolve(image)
        : reject(new Error('Image dimensions are invalid'))
    }
    image.onerror = () => reject(new Error('Image decoding failed'))
    image.src = url
  })
}

function canvasToPng(canvas: HTMLCanvasElement): Promise<Blob> {
  return new Promise((resolve, reject) => {
    canvas.toBlob(
      (blob) => (blob ? resolve(blob) : reject(new Error('PNG encoding failed'))),
      'image/png',
    )
  })
}
</script>

<template>
  <section class="content-card profile-editor-card">
    <div class="card-heading">
      <div>
        <h2>个人资料</h2>
        <p>昵称和头像会显示在 Proxy Web 与已登录的 Agent 中。</p>
      </div>
    </div>

    <form class="profile-editor-form" @submit.prevent="submit">
      <div class="avatar-editor">
        <Avatar
          :image="avatarPreview || undefined"
          :label="avatarPreview ? undefined : avatarLabel"
          shape="circle"
          size="xlarge"
        />
        <div class="avatar-editor-actions">
          <input
            ref="fileInput"
            class="avatar-file-input"
            type="file"
            accept="image/png,image/jpeg,image/webp"
            @change="onAvatarSelected"
          />
          <Button
            type="button"
            label="选择头像"
            icon="pi pi-upload"
            severity="secondary"
            outlined
            @click="chooseAvatar"
          />
          <Button
            v-if="avatarPreview"
            type="button"
            label="移除"
            icon="pi pi-trash"
            severity="secondary"
            text
            @click="removeAvatar"
          />
          <small>PNG、JPEG 或 WebP；原文件不超过 1 MiB，上传时统一缩放为 64 × 64 像素。</small>
        </div>
      </div>

      <div class="profile-editor-nickname">
        <label for="profile-nickname">昵称</label>
        <InputText
          id="profile-nickname"
          v-model="nickname"
          :maxlength="MAX_NICKNAME_CHARACTERS"
          placeholder="最多 6 个字符"
          fluid
        />
        <small>{{ nicknameLength }} / {{ MAX_NICKNAME_CHARACTERS }}</small>
      </div>

      <div class="profile-editor-footer">
        <small v-if="error" class="profile-editor-error" role="alert">{{ error }}</small>
        <span v-else />
        <Button
          type="submit"
          label="保存个人资料"
          icon="pi pi-check"
          :loading="saving"
        />
      </div>
    </form>
  </section>
</template>

<style scoped>
.profile-editor-card {
  margin-top: 20px;
  padding: 24px;
}

.profile-editor-form {
  display: grid;
  grid-template-columns: minmax(260px, 1fr) minmax(220px, 1fr);
  gap: 22px;
  margin-top: 20px;
}

.avatar-editor {
  display: flex;
  align-items: center;
  gap: 16px;
}

.avatar-editor :deep(.p-avatar) {
  width: 64px;
  height: 64px;
  flex: 0 0 64px;
  overflow: hidden;
  color: #155eef;
  font-weight: 700;
  background: #eaf1ff;
}

.avatar-editor :deep(.p-avatar img) {
  width: 64px;
  height: 64px;
  object-fit: cover;
}

.avatar-editor-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.avatar-editor-actions small {
  width: 100%;
  color: #667085;
  line-height: 1.45;
}

.avatar-file-input {
  display: none;
}

.profile-editor-nickname {
  display: grid;
  align-content: start;
  gap: 8px;
}

.profile-editor-nickname label {
  color: #344054;
  font-weight: 650;
}

.profile-editor-nickname small {
  justify-self: end;
  color: #98a2b3;
}

.profile-editor-footer {
  display: flex;
  grid-column: 1 / -1;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.profile-editor-error {
  color: #d92d20;
}

@media (max-width: 720px) {
  .profile-editor-form {
    grid-template-columns: 1fr;
  }

  .profile-editor-footer {
    grid-column: 1;
    align-items: stretch;
    flex-direction: column;
  }
}
</style>
