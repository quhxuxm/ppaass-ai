package com.ppaass.ai.agent;

import android.content.Context;

final class AgentProxyEntryClient {
    private static final int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
    private final AgentAuthHttpTransport transport;

    AgentProxyEntryClient(Context context, String baseUrl) {
        transport = new AgentAuthHttpTransport(
                context,
                AgentAuthConfig.normalizeProxyRegistryUrl(baseUrl));
    }

    AgentAuthClient.ProfileSyncResult select(
            String accessToken,
            String expectedUsername,
            String proxyEntryId) throws AgentAuthClient.AuthException {
        AgentAuthDtos.ProfileSyncResponse response = transport.requestObject(
                "PUT",
                "/api/v1/agent/proxy-entry",
                new AgentAuthDtos.SelectProxyEntryRequest(proxyEntryId),
                accessToken,
                MAX_RESPONSE_BYTES,
                AgentAuthDtos.ProfileSyncResponse.class);
        return AgentAuthResponseParser.parseProfileSync(response, expectedUsername);
    }
}
