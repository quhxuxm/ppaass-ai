<script setup lang="ts">
import { computed } from 'vue'
import Checkbox from 'primevue/checkbox'
import Tag from 'primevue/tag'
import type { ProxyAddress } from '../api'

interface Props {
  addresses: ProxyAddress[]
  inputPrefix: string
  title?: string
  description?: string
  emptyMessage?: string
  required?: boolean
  compact?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  title: '可用 Proxy 地址',
  description: '',
  emptyMessage: '暂无可分配的 Proxy 地址。',
  required: true,
  compact: false,
})

const selectedIds = defineModel<string[]>({ default: () => [] })

const selectedCount = computed(
  () => props.addresses.filter((address) => selectedIds.value.includes(address.id)).length,
)

function inputId(addressId: string): string {
  return `${props.inputPrefix}-${addressId}`
}
</script>

<template>
  <section
    class="proxy-checklist"
    :class="{ 'proxy-checklist--compact': compact }"
    :aria-labelledby="`${inputPrefix}-title`"
    :aria-describedby="description ? `${inputPrefix}-description` : undefined"
  >
    <header class="proxy-checklist__heading">
      <div class="proxy-checklist__heading-copy">
        <strong :id="`${inputPrefix}-title`">{{ title }}</strong>
        <small v-if="description" :id="`${inputPrefix}-description`">
          {{ description }}
        </small>
      </div>
      <Tag
        :value="`${selectedCount} / ${addresses.length} 已选`"
        :severity="selectedCount ? 'info' : required ? 'danger' : 'secondary'"
        rounded
      />
    </header>

    <div
      v-if="addresses.length"
      class="proxy-checklist__table"
      role="group"
      :aria-label="title"
    >
      <div class="proxy-checklist__columns" aria-hidden="true">
        <span />
        <span>节点名称</span>
        <span>连接地址</span>
      </div>

      <label
        v-for="address in addresses"
        :key="address.id"
        class="proxy-checklist__row"
        :class="{
          'proxy-checklist__row--selected': selectedIds.includes(address.id),
          'proxy-checklist__row--disabled': !address.enabled,
        }"
        :for="inputId(address.id)"
      >
        <span class="proxy-checklist__check">
          <Checkbox
            v-model="selectedIds"
            :input-id="inputId(address.id)"
            :value="address.id"
            :disabled="!address.enabled"
          />
        </span>
        <span class="proxy-checklist__name">
          <strong>{{ address.label }}</strong>
          <Tag
            v-if="!address.enabled"
            value="已停用"
            severity="secondary"
            rounded
          />
        </span>
        <code class="proxy-checklist__address">{{ address.address }}</code>
      </label>
    </div>

    <div v-else class="proxy-checklist__empty" role="status">
      <span class="proxy-checklist__empty-icon" aria-hidden="true">
        <i class="pi pi-server" />
      </span>
      <span>
        <strong>暂无可选节点</strong>
        <small>{{ emptyMessage }}</small>
      </span>
    </div>
  </section>
</template>

<style scoped src="./ProxyAddressChecklist.css"></style>
