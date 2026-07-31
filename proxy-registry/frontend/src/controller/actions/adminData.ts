import {
  getAccessLogSettings,
  listAuditEvents,
  listManagedUsers,
  listPendingKeyRequests,
  listProxyAddresses,
  updateAccessLogSettings,
  type AuditAction,
} from '../../api'
import type { AdminSection } from '../model'
import type { ControllerServices } from '../services'
import type { ControllerState } from '../state'

export function createAdminDataActions(
  state: ControllerState,
  services: ControllerServices,
) {
  const {
    toast, isAdmin, adminLoading, keyRequestsLoading, adminUsers,
    adminKeyRequests, retentionDays, proxyAddresses, auditEventsLoaded,
    auditEventsLoading, auditSearch, auditAction, adminAuditEvents,
    auditEventsHasMore, activeAdminSection, auditEventsLoadingMore,
    retentionSaving,
  } = state

  async function refreshAdminUsers(): Promise<void> {
    if (!isAdmin.value) return
    adminLoading.value = true
    keyRequestsLoading.value = true
    try {
      const [usersResult, requestsResult, settingsResult, addressesResult] =
        await Promise.allSettled([
          listManagedUsers(),
          listPendingKeyRequests(),
          getAccessLogSettings(),
          listProxyAddresses(),
        ])
      if (usersResult.status === 'fulfilled') {
        adminUsers.value = usersResult.value
      } else {
        services.showError('无法读取用户列表', usersResult.reason)
      }
      if (requestsResult.status === 'fulfilled') {
        adminKeyRequests.value = requestsResult.value.filter(
          (request) => request.status === 'pending',
        )
      } else {
        services.showError('无法读取密钥申请', requestsResult.reason)
      }
      if (settingsResult.status === 'fulfilled') {
        retentionDays.value = settingsResult.value.retentionDays
      }
      if (addressesResult.status === 'fulfilled') {
        proxyAddresses.value = addressesResult.value
      } else {
        services.showError(
          '无法读取 Proxy 地址目录',
          addressesResult.reason,
        )
      }
      auditEventsLoaded.value = false
    } finally {
      adminLoading.value = false
      keyRequestsLoading.value = false
    }
  }

  async function refreshAuditEvents(): Promise<void> {
    auditEventsLoading.value = true
    try {
      const page = await listAuditEvents({
        limit: 50,
        search: auditSearch.value,
        action: auditAction.value,
      })
      adminAuditEvents.value = page.events
      auditEventsHasMore.value = page.hasMore
      auditEventsLoaded.value = true
    } catch (error) {
      services.showError('无法读取操作审计', error)
    } finally {
      auditEventsLoading.value = false
    }
  }

  async function selectAdminSection(
    section: AdminSection,
  ): Promise<void> {
    activeAdminSection.value = section
    if (section === 'audit' && !auditEventsLoaded.value) {
      await refreshAuditEvents()
    }
  }

  async function filterAuditEvents(
    search: string,
    action: AuditAction | null,
  ): Promise<void> {
    auditSearch.value = search
    auditAction.value = action
    await refreshAuditEvents()
  }

  async function loadMoreAuditEvents(): Promise<void> {
    if (
      auditEventsLoading.value ||
      auditEventsLoadingMore.value ||
      !auditEventsHasMore.value
    ) {
      return
    }
    const beforeId =
      adminAuditEvents.value[adminAuditEvents.value.length - 1]?.id
    if (!beforeId) return
    auditEventsLoadingMore.value = true
    try {
      const page = await listAuditEvents({
        beforeId,
        limit: 50,
        search: auditSearch.value,
        action: auditAction.value,
      })
      const knownIds = new Set(
        adminAuditEvents.value.map((event) => event.id),
      )
      adminAuditEvents.value.push(
        ...page.events.filter((event) => !knownIds.has(event.id)),
      )
      auditEventsHasMore.value = page.hasMore
    } catch (error) {
      services.showError('无法加载更早的操作审计', error)
    } finally {
      auditEventsLoadingMore.value = false
    }
  }

  async function saveRetentionDays(): Promise<void> {
    const days = retentionDays.value
    if (
      !Number.isInteger(days) ||
      days === null ||
      days < 1 ||
      days > 365
    ) {
      toast.add({
        severity: 'warn',
        summary: '保留天数无效',
        detail: '请输入 1 到 365 之间的整数',
        life: 3200,
      })
      return
    }
    retentionSaving.value = true
    try {
      const settings = await updateAccessLogSettings(days)
      retentionDays.value = settings.retentionDays
      toast.add({
        severity: 'success',
        summary: '访问记录保留策略已更新',
        detail:
          `普通用户现在可以查看最近 ${settings.retentionDays} 天的本人访问记录`,
        life: 4200,
      })
    } catch (error) {
      services.showError('更新访问记录保留策略失败', error)
    } finally {
      retentionSaving.value = false
    }
  }

  return {
    refreshAdminUsers, refreshAuditEvents, selectAdminSection,
    filterAuditEvents, loadMoreAuditEvents, saveRetentionDays,
  }
}
