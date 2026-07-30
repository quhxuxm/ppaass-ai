package com.ppaass.ai.agent;

import android.content.Context;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class AgentAdminClient {
    static final String KEY_REQUESTS_PATH = "/api/v1/admin/key-requests";
    static final String PROXY_ADDRESSES_PATH = "/api/v1/admin/proxy-addresses";
    static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
    private static final int MAX_REQUESTS = 4096;
    private static final int MAX_PROXY_ADDRESSES = 4096;
    private static final int MAX_TOKEN_BYTES = 4 * 1024;
    private static final int MAX_ID_BYTES = 128;
    private static final int MAX_USERNAME_BYTES = 128;
    private static final int MAX_AVATAR_URL_BYTES = 1_500_000;
    private static final int MAX_MESSAGE_CHARACTERS = 500;
    private static final int MAX_PROXY_IDS_PER_REQUEST = 32;

    private final Transport transport;

    AgentAdminClient(Context context, String baseUrl) {
        this(new HttpTransport(new AgentAuthHttpTransport(
                context,
                AgentAuthConfig.normalizeProxyWebUrl(baseUrl))));
    }

    AgentAdminClient(Transport transport) {
        this.transport = transport;
    }

    List<AgentAdminModels.KeyRequest> listKeyRequests(String accessToken)
            throws AdminException {
        AgentAdminDtos.KeyRequestsResponse response = request(
                "GET",
                KEY_REQUESTS_PATH,
                null,
                accessToken,
                AgentAdminDtos.KeyRequestsResponse.class);
        if (response.requests == null || response.requests.size() > MAX_REQUESTS) {
            throw invalidResponse();
        }
        List<AgentAdminModels.KeyRequest> requests =
                new ArrayList<>(response.requests.size());
        Set<String> seen = new HashSet<>();
        for (AgentAdminDtos.KeyRequest request : response.requests) {
            AgentAdminModels.KeyRequest parsed = parseRequest(request, "pending");
            if (!seen.add(parsed.id)) {
                throw invalidResponse();
            }
            requests.add(parsed);
        }
        return immutableCopy(requests);
    }

    List<AgentAdminModels.ProxyAddress> listProxyAddresses(String accessToken)
            throws AdminException {
        AgentAdminDtos.ProxyAddressesResponse response = request(
                "GET",
                PROXY_ADDRESSES_PATH,
                null,
                accessToken,
                AgentAdminDtos.ProxyAddressesResponse.class);
        if (response.proxy_addresses == null
                || response.proxy_addresses.size() > MAX_PROXY_ADDRESSES) {
            throw invalidResponse();
        }
        List<AgentAdminModels.ProxyAddress> addresses =
                new ArrayList<>(response.proxy_addresses.size());
        Set<String> seen = new HashSet<>();
        for (AgentAdminDtos.ProxyAddress value : response.proxy_addresses) {
            AgentAdminModels.ProxyAddress address = parseProxyAddress(value);
            if (!seen.add(address.id)) {
                throw invalidResponse();
            }
            addresses.add(address);
        }
        return immutableCopy(addresses);
    }

    AgentAdminModels.Dashboard loadDashboard(String accessToken)
            throws AdminException {
        return new AgentAdminModels.Dashboard(
                listKeyRequests(accessToken),
                listProxyAddresses(accessToken));
    }

    void approve(
            String accessToken,
            String requestId,
            long expiresAt,
            List<String> proxyAddressIds) throws AdminException {
        if (expiresAt <= 0) {
            throw new AdminException(0, "invalid_request", "密钥有效期无效");
        }
        List<String> ids = requireProxyIds(proxyAddressIds, true);
        AgentAdminDtos.DecisionResponse response = request(
                "POST",
                decisionPath(requestId, "approve"),
                new AgentAdminDtos.ApproveKeyRequest(expiresAt, ids),
                accessToken,
                AgentAdminDtos.DecisionResponse.class);
        parseRequest(response.request, "approved");
    }

    void reject(String accessToken, String requestId, String reason) throws AdminException {
        reason = optionalMessage(reason);
        AgentAdminDtos.DecisionResponse response = request(
                "POST",
                decisionPath(requestId, "reject"),
                new AgentAdminDtos.RejectKeyRequest(
                        reason.isEmpty() ? null : reason),
                accessToken,
                AgentAdminDtos.DecisionResponse.class);
        parseRequest(response.request, "rejected");
    }

    void cancel() {
        transport.cancel();
    }

    private <T> T request(
            String method,
            String path,
            Object body,
            String accessToken,
            Class<T> responseType) throws AdminException {
        requireAccessToken(accessToken);
        final AgentAuthHttpTransport.Response response;
        try {
            response = transport.execute(
                    method,
                    path,
                    body,
                    accessToken,
                    MAX_RESPONSE_BYTES);
        } catch (AgentAuthClient.AuthException error) {
            throw new AdminException(0, "transport_error", error.getMessage(), error);
        }
        if (!response.isSuccessful()) {
            throw apiError(response.status, response.body);
        }
        try {
            return AgentAuthJsonCodec.decode(response.body, responseType);
        } catch (AgentAuthClient.AuthException error) {
            throw invalidResponse(error);
        }
    }

    private static AgentAdminModels.KeyRequest parseRequest(
            AgentAdminDtos.KeyRequest value,
            String expectedStatus) throws AdminException {
        if (value == null
                || value.account == null
                || !expectedStatus.equals(value.status)
                || !("initial".equals(value.kind) || "rotate".equals(value.kind))
                || value.requested_at == null
                || value.requested_at <= 0) {
            throw invalidResponse();
        }
        String id = requireIdentifier(value.request_id);
        String username = requireText(value.account.login_name, MAX_USERNAME_BYTES);
        String displayName = optionalText(value.account.display_name, 256);
        String avatarUrl = optionalText(
                value.account.avatar_url,
                MAX_AVATAR_URL_BYTES);
        String email = optionalText(value.account.email, 320);
        String message = optionalMessage(value.request_message);
        List<String> proxyIds = requireProxyIds(value.proxy_address_ids, false);
        return new AgentAdminModels.KeyRequest(
                id,
                username,
                displayName,
                avatarUrl,
                email,
                proxyIds,
                message,
                value.kind,
                value.requested_at);
    }

    private static AgentAdminModels.ProxyAddress parseProxyAddress(
            AgentAdminDtos.ProxyAddress value) throws AdminException {
        if (value == null || value.enabled == null) {
            throw invalidResponse();
        }
        return new AgentAdminModels.ProxyAddress(
                requireIdentifier(value.proxy_address_id),
                optionalText(value.label, 256),
                requireText(value.address, 1024),
                value.enabled);
    }

    private static List<String> requireProxyIds(List<String> values, boolean required)
            throws AdminException {
        if (values == null
                || values.size() > MAX_PROXY_IDS_PER_REQUEST
                || required && values.isEmpty()) {
            throw new AdminException(
                    0,
                    "invalid_request",
                    required ? "请至少选择一个可用 Proxy 地址" : "Proxy 地址列表无效");
        }
        List<String> result = new ArrayList<>(values.size());
        Set<String> seen = new HashSet<>();
        for (String value : values) {
            String id = requireIdentifier(value);
            if (!seen.add(id)) {
                throw invalidResponse();
            }
            result.add(id);
        }
        return immutableCopy(result);
    }

    private static <T> List<T> immutableCopy(List<T> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

    private static String decisionPath(String requestId, String action)
            throws AdminException {
        return KEY_REQUESTS_PATH + "/" + requireIdentifier(requestId) + "/" + action;
    }

    private static String requireIdentifier(String value) throws AdminException {
        value = requireText(value, MAX_ID_BYTES);
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!(Character.isLetterOrDigit(character)
                    || character == '-'
                    || character == '_')) {
                throw invalidResponse();
            }
        }
        return value;
    }

    private static String requireText(String value, int maximumBytes)
            throws AdminException {
        if (value == null || value.isEmpty() || value.length() > maximumBytes) {
            throw invalidResponse();
        }
        return value;
    }

    private static String optionalText(String value, int maximumCharacters)
            throws AdminException {
        if (value == null) {
            return "";
        }
        value = value.trim();
        if (value.length() > maximumCharacters) {
            throw invalidResponse();
        }
        return value;
    }

    private static String optionalMessage(String value) throws AdminException {
        String message = optionalText(value, MAX_MESSAGE_CHARACTERS);
        if (message.codePointCount(0, message.length()) > MAX_MESSAGE_CHARACTERS) {
            throw invalidResponse();
        }
        return message;
    }

    private static void requireAccessToken(String value) throws AdminException {
        if (value == null || value.isEmpty() || value.length() > MAX_TOKEN_BYTES) {
            throw new AdminException(401, "unauthorized", "管理员登录凭据已失效");
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.isWhitespace(value.charAt(index))) {
                throw new AdminException(401, "unauthorized", "管理员登录凭据已失效");
            }
        }
    }

    private static AdminException apiError(int status, byte[] body) {
        AgentAuthDtos.ApiErrorEnvelope envelope = AgentAuthJsonCodec.decodeError(
                body,
                AgentAuthDtos.ApiErrorEnvelope.class);
        String code = envelope == null || envelope.error == null
                || envelope.error.code == null ? "" : envelope.error.code;
        String message = envelope == null || envelope.error == null
                || envelope.error.message == null || envelope.error.message.isEmpty()
                ? "管理员服务返回 HTTP " + status
                : envelope.error.message;
        return new AdminException(status, code, message);
    }

    private static AdminException invalidResponse() {
        return invalidResponse(null);
    }

    private static AdminException invalidResponse(Throwable cause) {
        return new AdminException(
                502,
                "invalid_response",
                "Proxy Web 返回的管理员数据无效",
                cause);
    }

    interface Transport {
        AgentAuthHttpTransport.Response execute(
                String method,
                String path,
                Object body,
                String bearerToken,
                int maximumBytes) throws AgentAuthClient.AuthException;

        void cancel();
    }

    static final class AdminException extends Exception {
        final int status;
        final String code;

        AdminException(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }

        AdminException(int status, String code, String message, Throwable cause) {
            super(message, cause);
            this.status = status;
            this.code = code;
        }

        boolean isConflict() {
            return status == 409;
        }
    }

    private static final class HttpTransport implements Transport {
        private final AgentAuthHttpTransport delegate;

        HttpTransport(AgentAuthHttpTransport delegate) {
            this.delegate = delegate;
        }

        @Override
        public AgentAuthHttpTransport.Response execute(
                String method,
                String path,
                Object body,
                String bearerToken,
                int maximumBytes) throws AgentAuthClient.AuthException {
            return delegate.execute(
                    method,
                    path,
                    body,
                    null,
                    bearerToken,
                    maximumBytes);
        }

        @Override
        public void cancel() {
            delegate.cancel();
        }
    }
}
