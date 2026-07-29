<script setup lang="ts">
import { reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Tag from 'primevue/tag'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import {
  ApiError,
  createProxyAddress,
  deleteProxyAddress,
  updateProxyAddress,
  type ProxyAddress,
} from '../api'

defineProps<{
  addresses: ProxyAddress[]
  loading: boolean
}>()

const emit = defineEmits<{ changed: [] }>()
const toast = useToast()
const confirm = useConfirm()
const visible = ref(false)
const saving = ref(false)
const editingId = ref<string | null>(null)
const form = reactive({ label: '', address: '' })

function openCreate(): void {
  editingId.value = null
  form.label = ''
  form.address = ''
  visible.value = true
}

function openEdit(address: ProxyAddress): void {
  editingId.value = address.id
  form.label = address.label === address.address ? '' : address.label
  form.address = address.address
  visible.value = true
}

function showError(summary: string, error: unknown): void {
  toast.add({
    severity: 'error',
    summary,
    detail: error instanceof Error ? error.message : '请求失败',
    life: 5200,
  })
}

async function submit(): Promise<void> {
  const address = form.address.trim()
  if (!address) {
    toast.add({ severity: 'warn', summary: '请输入 Proxy 地址', life: 2600 })
    return
  }
  saving.value = true
  try {
    if (editingId.value) {
      await updateProxyAddress(editingId.value, {
        label: form.label.trim(),
        address,
      })
    } else {
      await createProxyAddress({
        label: form.label.trim() || undefined,
        address,
      })
    }
    visible.value = false
    emit('changed')
    toast.add({
      severity: 'success',
      summary: editingId.value ? 'Proxy 地址已更新' : 'Proxy 地址已创建',
      life: 2600,
    })
  } catch (error) {
    showError('保存 Proxy 地址失败', error)
  } finally {
    saving.value = false
  }
}

async function setEnabled(address: ProxyAddress, enabled: boolean): Promise<void> {
  try {
    await updateProxyAddress(address.id, { enabled })
    emit('changed')
    toast.add({
      severity: 'success',
      summary: enabled ? 'Proxy 地址已启用' : 'Proxy 地址已停用',
      life: 2400,
    })
  } catch (error) {
    showError(
      error instanceof ApiError && error.code === 'proxy_address_in_use'
        ? '请先为相关账号重新分配地址'
        : '更新 Proxy 地址状态失败',
      error,
    )
  }
}

function confirmDelete(address: ProxyAddress): void {
  confirm.require({
    header: '删除 Proxy 地址',
    message: `确定删除“${address.label}”吗？`,
    icon: 'pi pi-trash',
    acceptLabel: '删除',
    rejectLabel: '取消',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await deleteProxyAddress(address.id)
        emit('changed')
        toast.add({ severity: 'success', summary: 'Proxy 地址已删除', life: 2400 })
      } catch (error) {
        showError('删除 Proxy 地址失败', error)
      }
    },
  })
}
</script>

<template>
  <section class="content-card proxy-catalog-card">
    <div class="catalog-heading">
      <div>
        <h2>Proxy 地址目录</h2>
        <p>预定义可分配给账号的远端 Proxy 地址；地址不会显示在 Agent 界面。</p>
      </div>
      <Button label="新增地址" icon="pi pi-plus" @click="openCreate" />
    </div>
    <div v-if="loading" class="catalog-empty">正在读取地址目录…</div>
    <div v-else-if="addresses.length" class="catalog-list">
      <article v-for="item in addresses" :key="item.id" class="catalog-item">
        <div>
          <strong>{{ item.label }}</strong>
          <code>{{ item.address }}</code>
        </div>
        <Tag
          :value="item.enabled ? '已启用' : '已停用'"
          :severity="item.enabled ? 'success' : 'secondary'"
          rounded
        />
        <div class="catalog-actions">
          <Button
            v-if="item.enabled"
            label="停用"
            severity="secondary"
            text
            size="small"
            @click="setEnabled(item, false)"
          />
          <Button
            v-else
            label="启用"
            severity="success"
            text
            size="small"
            @click="setEnabled(item, true)"
          />
          <Button
            icon="pi pi-pencil"
            severity="secondary"
            text
            rounded
            aria-label="编辑 Proxy 地址"
            @click="openEdit(item)"
          />
          <Button
            icon="pi pi-trash"
            severity="danger"
            text
            rounded
            aria-label="删除 Proxy 地址"
            :disabled="item.enabled"
            @click="confirmDelete(item)"
          />
        </div>
      </article>
    </div>
    <div v-else class="catalog-empty">
      <i class="pi pi-server" />
      <span>尚未配置地址。创建用户或批准密钥申请前，至少先新增一个地址。</span>
    </div>
  </section>

  <Dialog
    v-model:visible="visible"
    modal
    :header="editingId ? '编辑 Proxy 地址' : '新增 Proxy 地址'"
    :style="{ width: 'min(92vw, 520px)' }"
  >
    <form id="proxy-address-form" class="catalog-form" @submit.prevent="submit">
      <label for="proxy-address-label">名称（可选）</label>
      <InputText
        id="proxy-address-label"
        v-model="form.label"
        placeholder="留空则使用地址"
        fluid
      />
      <label for="proxy-address-value">地址</label>
      <InputText
        id="proxy-address-value"
        v-model="form.address"
        placeholder="proxy.example.com:443"
        fluid
      />
      <small>支持 hostname:port、IPv4:port 和 [IPv6]:port。</small>
    </form>
    <template #footer>
      <Button label="取消" severity="secondary" text @click="visible = false" />
      <Button
        form="proxy-address-form"
        type="submit"
        label="保存"
        icon="pi pi-check"
        :loading="saving"
      />
    </template>
  </Dialog>
</template>

<style scoped>
.catalog-heading,
.catalog-item,
.catalog-actions {
  display: flex;
  align-items: center;
}

.catalog-heading {
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1rem;
}

.catalog-heading h2,
.catalog-heading p {
  margin: 0;
}

.catalog-heading p,
.catalog-item code,
.catalog-empty,
.catalog-form small {
  color: var(--text-muted);
}

.catalog-list {
  display: grid;
  gap: 0.75rem;
}

.catalog-item {
  gap: 1rem;
  padding: 0.9rem 1rem;
  border: 1px solid var(--border);
  border-radius: 14px;
}

.catalog-item > div:first-child {
  display: grid;
  gap: 0.3rem;
  min-width: 0;
  flex: 1;
}

.catalog-item code {
  overflow-wrap: anywhere;
}

.catalog-actions {
  gap: 0.25rem;
}

.catalog-empty {
  display: flex;
  gap: 0.65rem;
  justify-content: center;
  padding: 1.4rem;
}

.catalog-form {
  display: grid;
  gap: 0.65rem;
}

.catalog-form label:not(:first-child) {
  margin-top: 0.4rem;
}

@media (max-width: 720px) {
  .catalog-item {
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .catalog-actions {
    width: 100%;
    justify-content: flex-end;
  }
}
</style>
