package com.ppaass.ai.agent;

import android.content.Context;

import java.util.List;

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
            List<String> proxyEntryIds) throws AgentAuthClient.AuthException {
        AgentAuthDtos.ProfileSyncResponse response = transport.requestObject(
                "PUT",
                "/api/v1/agent/proxy-entry",
                new AgentAuthDtos.SelectProxyEntryRequest(proxyEntryIds),
                accessToken,
                MAX_RESPONSE_BYTES,
                AgentAuthDtos.ProfileSyncResponse.class);
        return AgentAuthResponseParser.parseProfileSync(response, expectedUsername);
    }
}
