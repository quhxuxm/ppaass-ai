package com.ppaass.ai.agent;

final class AgentSyncFailurePolicy {
    private AgentSyncFailurePolicy() {
    }

    static AgentAuthClient.SyncFailure forResponse(int status, String code) {
        if (status == 409 && "proxy_address_not_assigned".equals(code)) {
            return AgentAuthClient.SyncFailure.PROXY_ADDRESS_REQUIRED;
        }
        return status >= 500
                ? AgentAuthClient.SyncFailure.TRANSIENT
                : AgentAuthClient.SyncFailure.SERVICE_REJECTED;
    }

    static boolean requiresManagedProxyShutdown(
            AgentAuthClient.SyncFailure failure) {
        return failure == AgentAuthClient.SyncFailure.INVALID_RESPONSE
                || failure == AgentAuthClient.SyncFailure.PROXY_ADDRESS_REQUIRED;
    }
}
