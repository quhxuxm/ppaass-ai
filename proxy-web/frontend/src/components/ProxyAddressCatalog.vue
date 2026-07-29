<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import ProgressSpinner from 'primevue/progressspinner'
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

const props = defineProps<{
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
const enabledCount = computed(
  () => props.addresses.filter((address) => address.enabled).length,
)
const disabledCount = computed(() => props.addresses.length - enabledCount.value)

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
  <section class="content-card proxy-catalog-card" aria-labelledby="proxy-catalog-title">
    <header class="catalog-header">
      <div class="catalog-title">
        <span class="catalog-title-icon"><i class="pi pi-server" /></span>
        <div>
          <div class="catalog-title-line">
            <h2 id="proxy-catalog-title">Proxy 地址目录</h2>
            <Tag
              v-if="!loading"
              :value="`${addresses.length} 个节点`"
              severity="info"
              rounded
            />
          </div>
          <p>集中维护可分配给账号的远端 Proxy 节点，具体地址不会暴露在 Agent 界面。</p>
        </div>
      </div>
      <Button
        class="catalog-add-button"
        label="新增节点"
        icon="pi pi-plus"
        @click="openCreate"
      />
    </header>

    <div class="catalog-body">
      <div v-if="loading" class="catalog-loading" aria-live="polite">
        <ProgressSpinner stroke-width="4" />
        <div>
          <strong>正在读取 Proxy 节点</strong>
          <span>同步节点状态和分配信息…</span>
        </div>
      </div>

      <div v-else-if="addresses.length" class="catalog-list">
        <div class="catalog-columns" aria-hidden="true">
          <span />
          <span>节点名称</span>
          <span>连接地址</span>
          <span>状态</span>
          <span>操作</span>
        </div>
        <article
          v-for="item in addresses"
          :key="item.id"
          class="catalog-row"
          :class="{ disabled: !item.enabled }"
        >
          <span class="catalog-node-icon">
            <i :class="item.enabled ? 'pi pi-globe' : 'pi pi-ban'" />
          </span>
          <div class="catalog-identity">
            <strong :title="item.label">{{ item.label }}</strong>
            <small>
              {{ item.enabled ? '可分配给用户并由 Agent 连接' : '保留配置，不再下发给 Agent' }}
            </small>
          </div>
          <span class="catalog-address" :title="item.address">
            <i class="pi pi-link" />
            <code>{{ item.address }}</code>
          </span>
          <Tag
            class="catalog-status"
            :value="item.enabled ? '运行中' : '已停用'"
            :severity="item.enabled ? 'success' : 'secondary'"
            rounded
          />
          <div class="catalog-actions">
            <Button
              v-if="item.enabled"
              label="停用"
              icon="pi pi-pause"
              severity="secondary"
              outlined
              size="small"
              @click="setEnabled(item, false)"
            />
            <Button
              v-else
              label="启用"
              icon="pi pi-play"
              severity="success"
              outlined
              size="small"
              @click="setEnabled(item, true)"
            />
            <Button
              label="编辑"
              icon="pi pi-pencil"
              severity="secondary"
              text
              size="small"
              @click="openEdit(item)"
            />
            <Button
              v-tooltip.top="item.enabled ? '请先停用节点' : '删除节点'"
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
        <span class="catalog-empty-icon"><i class="pi pi-server" /></span>
        <div>
          <strong>还没有 Proxy 节点</strong>
          <p>先新增至少一个节点，之后才能在创建用户或批准密钥时进行分配。</p>
          <Button
            label="新增第一个节点"
            icon="pi pi-plus"
            size="small"
            @click="openCreate"
          />
        </div>
      </div>
    </div>

    <footer v-if="!loading && addresses.length" class="catalog-footer">
      <div>
        <span class="catalog-count active">
          <i class="pi pi-check-circle" /> {{ enabledCount }} 个启用
        </span>
        <span class="catalog-count">
          <i class="pi pi-ban" /> {{ disabledCount }} 个停用
        </span>
      </div>
      <small><i class="pi pi-info-circle" /> 节点停用后，已分配账号将无法再领取该地址。</small>
    </footer>
  </section>

  <Dialog
    v-model:visible="visible"
    modal
    :header="editingId ? '编辑 Proxy 地址' : '新增 Proxy 地址'"
    :style="{ width: 'min(92vw, 520px)' }"
    class="proxy-address-dialog"
  >
    <div class="catalog-dialog-intro">
      <span><i class="pi pi-server" /></span>
      <div>
        <strong>{{ editingId ? '更新节点连接信息' : '添加一个远端节点' }}</strong>
        <small>保存后可在用户编辑和密钥审批中勾选分配。</small>
      </div>
    </div>
    <form id="proxy-address-form" class="catalog-form" @submit.prevent="submit">
      <div class="catalog-form-field">
        <label for="proxy-address-label">
          显示名称 <span>可选</span>
        </label>
        <InputText
          id="proxy-address-label"
          v-model="form.label"
          placeholder="例如：新加坡主节点"
          fluid
        />
        <small>留空时自动使用连接地址作为名称。</small>
      </div>
      <div class="catalog-form-field">
        <label for="proxy-address-value">连接地址</label>
        <InputText
          id="proxy-address-value"
          v-model="form.address"
          placeholder="proxy.example.com:443"
          fluid
        />
        <small>支持 hostname:port、IPv4:port 和 [IPv6]:port。</small>
      </div>
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

<style scoped src="./ProxyAddressCatalog.css"></style>
