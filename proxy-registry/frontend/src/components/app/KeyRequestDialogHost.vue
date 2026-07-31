<script setup lang="ts">
import { useAppControllerContext } from '../../appController'
import KeyRequestDialog from '../KeyRequestDialog.vue'

const {
  keyRequestDialogVisible,
  keyRequestLoading,
  keyState,
  submitKeyRequest,
} = useAppControllerContext()
</script>

<template>
  <KeyRequestDialog
    v-model:visible="keyRequestDialogVisible"
    :loading="keyRequestLoading"
    :renewal="keyState === 'expired'"
    @submit="submitKeyRequest"
  />
</template>
