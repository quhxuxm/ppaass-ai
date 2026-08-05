export interface ControllerServices {
  errorMessage(error: unknown): string
  showError(summary: string, error: unknown): void
  resetPasswordForm(): void
  refreshSelf(): Promise<void>
  refreshAccessRecords(showFailure?: boolean): Promise<void>
  refreshAdminUsers(): Promise<void>
  refreshAuditEvents(): Promise<void>
  refreshAgentAuthorization(): Promise<void>
}
