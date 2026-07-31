import { ApiError } from '../../api'
import type { ControllerState } from '../state'

export function createCommonActions(state: ControllerState) {
  function errorMessage(error: unknown): string {
    if (error instanceof ApiError || error instanceof Error) {
      return error.message
    }
    return '发生未知错误，请稍后重试'
  }

  function showError(summary: string, error: unknown): void {
    state.toast.add({
      severity: 'error',
      summary,
      detail: errorMessage(error),
      life: 5000,
    })
  }

  function resetPasswordForm(): void {
    state.passwordForm.currentPassword = ''
    state.passwordForm.newPassword = ''
    state.passwordForm.confirmPassword = ''
  }

  return { errorMessage, showError, resetPasswordForm }
}
