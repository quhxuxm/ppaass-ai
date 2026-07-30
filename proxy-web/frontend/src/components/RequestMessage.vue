<script setup lang="ts">
withDefaults(
  defineProps<{
    message: string | null
    label?: string
    compact?: boolean
    emptyText?: string
  }>(),
  {
    label: '申请留言',
    compact: false,
    emptyText: '',
  },
)
</script>

<template>
  <section
    v-if="message || emptyText"
    :class="['request-message', { compact }]"
  >
    <span class="request-message-label">
      <i class="pi pi-comment" aria-hidden="true" />
      {{ label }}
    </span>
    <p :class="{ empty: !message }">{{ message || emptyText }}</p>
  </section>
</template>

<style scoped>
.request-message {
  min-width: 0;
  display: grid;
  gap: 7px;
  margin-top: 12px;
  padding: 11px 12px;
  color: #475467;
  border: 1px solid #dbe7ff;
  border-radius: 10px;
  background: #f7faff;
}

.request-message-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: #155eef;
  font-size: 0.7rem;
  font-weight: 700;
}

.request-message p {
  max-height: 180px;
  margin: 0;
  overflow-x: hidden;
  overflow-y: auto;
  color: #475467;
  font-size: 0.76rem;
  line-height: 1.6;
  overflow-wrap: anywhere;
  scrollbar-gutter: stable;
  white-space: pre-wrap;
}

.request-message p.empty {
  color: #667085;
  font-style: italic;
}

.request-message.compact {
  gap: 5px;
  margin-top: 6px;
  padding: 8px 9px;
}

.request-message.compact p {
  max-height: 96px;
  font-size: 0.7rem;
  line-height: 1.5;
}

@media (max-width: 560px) {
  .request-message {
    padding: 10px;
  }
}
</style>
