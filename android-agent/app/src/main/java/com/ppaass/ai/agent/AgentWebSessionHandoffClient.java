package com.ppaass.ai.agent;

import android.content.Context;

import java.net.URI;
import java.net.URISyntaxException;

final class AgentWebSessionHandoffClient {
    static final String CREATE_PATH = "/api/v1/agent/web-session-handoffs";
    static final String CONSUME_PATH = "/api/v1/auth/agent-handoff";
    static final int MAX_RESPONSE_BYTES = 16 * 1024;
    private static final int MAX_HANDOFF_SECONDS = 5 * 60;
    private static final int MAX_HANDOFF_PATH_LENGTH = 2 * 1024;
    private static final int MAX_ACCESS_TOKEN_LENGTH = 4 * 1024;

    private final String baseUrl;
    private final Transport transport;

    AgentWebSessionHandoffClient(Context context, String baseUrl) {
        this.baseUrl = AgentAuthConfig.normalizeProxyWebUrl(baseUrl);
        this.transport = new HttpTransport(
                new AgentAuthHttpTransport(context, this.baseUrl));
    }

    AgentWebSessionHandoffClient(String baseUrl, Transport transport) {
        this.baseUrl = AgentAuthConfig.normalizeProxyWebUrl(baseUrl);
        this.transport = transport;
    }

    Handoff create(String accessToken) throws AgentAuthClient.AuthException {
        if (accessToken == null
                || accessToken.isEmpty()
                || accessToken.length() > MAX_ACCESS_TOKEN_LENGTH
                || containsWhitespace(accessToken)) {
            throw new AgentAuthClient.AuthException(
                    "账户管理登录凭据已失效，请重新登录 Agent");
        }
        AgentAuthDtos.WebSessionHandoffResponse response = transport.request(
                "POST",
                CREATE_PATH,
                null,
                accessToken,
                MAX_RESPONSE_BYTES);
        return parseResponse(baseUrl, response);
    }

    void cancel() {
        transport.cancel();
    }

    static Handoff parseResponse(
            String baseUrl,
            AgentAuthDtos.WebSessionHandoffResponse response)
            throws AgentAuthClient.AuthException {
        if (response == null
                || response.handoff_path == null
                || response.handoff_path.isEmpty()
                || response.handoff_path.length() > MAX_HANDOFF_PATH_LENGTH
                || response.expires_in == null
                || response.expires_in < 1
                || response.expires_in > MAX_HANDOFF_SECONDS) {
            throw invalidResponse(null);
        }
        try {
            String resolved = AgentAuthConfig.resolveServiceRelativeUrl(
                    baseUrl,
                    response.handoff_path);
            URI configured = new URI(AgentAuthConfig.normalizeProxyWebUrl(baseUrl));
            URI handoff = new URI(resolved);
            if (!sameOrigin(configured, handoff)
                    || !CONSUME_PATH.equals(handoff.getRawPath())
                    || handoff.getRawQuery() == null
                    || handoff.getRawQuery().isEmpty()
                    || handoff.getRawFragment() != null) {
                throw invalidResponse(null);
            }
            return new Handoff(resolved, response.expires_in.intValue());
        } catch (IllegalArgumentException | URISyntaxException error) {
            throw invalidResponse(error);
        }
    }

    private static boolean sameOrigin(URI expected, URI actual) {
        return expected.getScheme().equalsIgnoreCase(actual.getScheme())
                && expected.getHost().equalsIgnoreCase(actual.getHost())
                && effectivePort(expected) == effectivePort(actual)
                && actual.getRawUserInfo() == null;
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static boolean containsWhitespace(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (Character.isWhitespace(value.charAt(index))) {
                return true;
            }
        }
        return false;
    }

    private static AgentAuthClient.AuthException invalidResponse(Throwable cause) {
        return cause == null
                ? new AgentAuthClient.AuthException(
                "Proxy Web 返回的账户管理登录地址无效")
                : new AgentAuthClient.AuthException(
                "Proxy Web 返回的账户管理登录地址无效",
                cause);
    }

    interface Transport {
        AgentAuthDtos.WebSessionHandoffResponse request(
                String method,
                String path,
                Object body,
                String bearerToken,
                int maximumBytes) throws AgentAuthClient.AuthException;

        void cancel();
    }

    static final class Handoff {
        final String url;
        final int expiresInSeconds;

        Handoff(String url, int expiresInSeconds) {
            this.url = url;
            this.expiresInSeconds = expiresInSeconds;
        }
    }

    private static final class HttpTransport implements Transport {
        private final AgentAuthHttpTransport delegate;

        HttpTransport(AgentAuthHttpTransport delegate) {
            this.delegate = delegate;
        }

        @Override
        public AgentAuthDtos.WebSessionHandoffResponse request(
                String method,
                String path,
                Object body,
                String bearerToken,
                int maximumBytes) throws AgentAuthClient.AuthException {
            return delegate.requestObject(
                    method,
                    path,
                    body,
                    bearerToken,
                    maximumBytes,
                    AgentAuthDtos.WebSessionHandoffResponse.class);
        }

        @Override
        public void cancel() {
            delegate.cancel();
        }
    }
}
