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

    static String permissionFingerprint(
            boolean administrator,
            boolean proxyEntrySelect,
            boolean packetCapture,
            boolean egressEdit,
            boolean runtimeThreadsEdit) {
        return (administrator ? "A" : "U")
                + (proxyEntrySelect ? "1" : "0")
                + (packetCapture ? "1" : "0")
                + (egressEdit ? "1" : "0")
                + (runtimeThreadsEdit ? "1" : "0");
    }
}
