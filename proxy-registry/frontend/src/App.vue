<script setup lang="ts">
import { provide } from 'vue'
import ConfirmDialog from 'primevue/confirmdialog'
import ProgressSpinner from 'primevue/progressspinner'
import Toast from 'primevue/toast'
import {
  appControllerKey,
  useAppController,
} from './appController'
import AccountPage from './components/app/AccountPage.vue'
import AdminPage from './components/app/AdminPage.vue'
import AgentAuthorizationPage from './components/app/AgentAuthorizationPage.vue'
import AppTopbar from './components/app/AppTopbar.vue'
import AuthPage from './components/app/AuthPage.vue'
import CreateUserDialog from './components/app/CreateUserDialog.vue'
import EditUserDialog from './components/app/EditUserDialog.vue'
import KeyApprovalDialogs from './components/app/KeyApprovalDialogs.vue'
import KeyRequestDialogHost from './components/app/KeyRequestDialogHost.vue'
import RotationDialogs from './components/app/RotationDialogs.vue'

const controller = useAppController()
provide(appControllerKey, controller)

const {
  activePage,
  agentAuthorizationActive,
  booting,
  isAdmin,
  isAuthenticated,
} = controller
</script>

<template>
  <Toast />
  <ConfirmDialog />

  <div v-if="booting" class="boot-screen" aria-live="polite">
    <div class="brand-mark"><i class="pi pi-shield" /></div>
    <ProgressSpinner stroke-width="4" />
    <p>正在安全连接账户服务…</p>
  </div>

  <AuthPage v-else-if="!isAuthenticated" />
  <AgentAuthorizationPage v-else-if="agentAuthorizationActive" />
  <div v-else class="app-shell">
    <AppTopbar />
    <main class="workspace">
      <AccountPage v-if="activePage === 'account'" />
      <AdminPage v-else-if="activePage === 'admin' && isAdmin" />
    </main>
  </div>

  <CreateUserDialog />
  <EditUserDialog />
  <KeyRequestDialogHost />
  <KeyApprovalDialogs />
  <RotationDialogs />
</template>
