import {
  inject,
  onMounted,
  onUnmounted,
  watch,
  type InjectionKey,
} from 'vue'
import { getProviders, getSession } from './api'
import { createAccountActions } from './controller/actions/account'
import { createAdminApprovalActions } from './controller/actions/adminApprovals'
import { createAdminDataActions } from './controller/actions/adminData'
import { createAdminUserActions } from './controller/actions/adminUsers'
import { createAuthAgentActions } from './controller/actions/authAgent'
import { createCommonActions } from './controller/actions/common'
import {
  PASSWORD_MIN_CHARACTERS,
  accountStatusLabel,
  agentPermissionOptions,
  basePermissionOptions,
  canAdminRotateDirectly,
  deleteBlockedReason,
  formatExpiry,
  isRootAdmin,
  keyRequestKindLabel,
  managedAgentPermissions,
  managedCustomPermissions,
  managedHiddenPermissionCount,
  managedPermissionsTitle,
  managedProxyAddressesTitle,
  managedUsername,
  roleOptions,
  statusOptions,
} from './controller/model'
import type { ControllerServices } from './controller/services'
import { createControllerState } from './controller/state'

export function useAppController() {
  const state = createControllerState()
  const services = {} as ControllerServices
  const common = createCommonActions(state)
  Object.assign(services, common)
  const accountActions = createAccountActions(state, services)
  Object.assign(services, accountActions)
  const adminDataActions = createAdminDataActions(state, services)
  Object.assign(services, adminDataActions)
  const authAgentActions = createAuthAgentActions(state, services)
  Object.assign(services, authAgentActions)
  const adminUserActions = createAdminUserActions(state, services)
  const adminApprovalActions =
    createAdminApprovalActions(state, services)

  let clockTimer: ReturnType<typeof setInterval> | undefined
  onMounted(async () => {
    clockTimer = setInterval(() => {
      state.currentTime.value = Date.now()
    }, 5000)
    try {
      const [providerResult, sessionResult] = await Promise.allSettled([
        getProviders(),
        getSession(),
      ])
      if (providerResult.status === 'fulfilled') {
        state.providers.value = providerResult.value
        if (
          !state.providers.value.localRegistration &&
          state.authMode.value === 'register'
        ) {
          state.authMode.value = 'login'
        }
      }
      if (sessionResult.status === 'fulfilled') {
        state.session.value = sessionResult.value
      }
      if (state.session.value?.authenticated) {
        await accountActions.refreshSelf()
        if (
          state.agentAuthorizationActive.value &&
          state.agentAuthorizationCode.value
        ) {
          await authAgentActions.refreshAgentAuthorization()
        }
      }
    } finally {
      state.booting.value = false
    }
  })

  onUnmounted(() => {
    if (clockTimer) clearInterval(clockTimer)
  })

  watch(state.activePage, async (page) => {
    if (page !== 'account') common.resetPasswordForm()
    if (page === 'admin' && state.isAdmin.value) {
      await adminDataActions.refreshAdminUsers()
      if (state.activeAdminSection.value === 'audit') {
        await adminDataActions.refreshAuditEvents()
      }
    }
  })
  watch(state.createVisible, (visible) => {
    if (!visible) state.createForm.password = ''
  })

  return {
    ...state,
    ...common,
    ...accountActions,
    ...adminDataActions,
    ...authAgentActions,
    ...adminUserActions,
    ...adminApprovalActions,
    PASSWORD_MIN_CHARACTERS,
    basePermissionOptions,
    agentPermissionOptions,
    roleOptions,
    statusOptions,
    managedUsername,
    deleteBlockedReason,
    isRootAdmin,
    accountStatusLabel,
    canAdminRotateDirectly,
    keyRequestKindLabel,
    managedAgentPermissions,
    managedCustomPermissions,
    managedPermissionsTitle,
    managedHiddenPermissionCount,
    managedProxyAddressesTitle,
    formatExpiry,
  }
}

export type AppController = ReturnType<typeof useAppController>

export const appControllerKey: InjectionKey<AppController> =
  Symbol('appController')

export function useAppControllerContext(): AppController {
  const controller = inject(appControllerKey)
  if (!controller) throw new Error('App controller is unavailable')
  return controller
}
