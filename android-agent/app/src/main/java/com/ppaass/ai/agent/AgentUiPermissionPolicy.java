package com.ppaass.ai.agent;

final class AgentUiPermissionPolicy {
    private AgentUiPermissionPolicy() {
    }

    static boolean captureOperationAllowed(
            boolean hasPermission,
            boolean destroyed,
            boolean operationInFlight,
            boolean uiReady) {
        return hasPermission && !destroyed && !operationInFlight && uiReady;
    }

    static String guardedConfigValue(
            boolean canEdit,
            String storedValue,
            String requestedValue) {
        return canEdit ? requestedValue : storedValue;
    }
}
