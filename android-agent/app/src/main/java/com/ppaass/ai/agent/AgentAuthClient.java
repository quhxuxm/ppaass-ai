package com.ppaass.ai.agent;

import android.content.Context;
import android.util.Log;

import java.util.List;
import java.util.Set;

final class AgentAuthClient {
    private static final String TAG = "PpaassAgentAuth";
    private static final int MAX_NORMAL_RESPONSE_BYTES = 8 * 1024 * 1024;
    private static final int MAX_CREDENTIAL_RESPONSE_BYTES = 8 * 1024 * 1024;
    private static final int MAX_DEVICE_AUTHORIZATION_SECONDS = 60 * 60;
    private static final int MAX_DEVICE_POLL_DELAY_SECONDS = 5 * 60;

    private final String baseUrl;
    private final AgentAuthHttpTransport transport;

    AgentAuthClient(Context context, String baseUrl) {
        this.baseUrl = AgentAuthConfig.normalizeProxyRegistryUrl(baseUrl);
        this.transport = new AgentAuthHttpTransport(
                context,
                this.baseUrl);
    }

    LoginResult authenticate(String username, String password) throws AuthException {
        String normalizedUsername = username == null ? "" : username.trim();
        if (normalizedUsername.isEmpty()) {
            throw new AuthException("请输入用户名");
        }
        if (password == null || password.length() < 8) {
            throw new AuthException("密码至少需要 8 位");
        }
        AgentAuthDtos.CredentialResponse response = transport.requestObject(
                "POST",
                "/api/v1/agent/login",
                new AgentAuthDtos.PasswordLoginRequest(normalizedUsername, password),
                null,
                MAX_CREDENTIAL_RESPONSE_BYTES,
                AgentAuthDtos.CredentialResponse.class);
        LoginResult result = AgentAuthResponseParser.parseLogin(response);
        Log.i(TAG, "Native Agent login and managed key validation succeeded");
        return result;
    }

    ProfileSyncResult syncProfile(String accessToken, String expectedUsername)
            throws SyncException {
        final AgentAuthHttpTransport.Response response;
        try {
            response = transport.execute(
                    "GET",
                    "/api/v1/agent/me",
                    null,
                    null,
                    accessToken,
                    MAX_NORMAL_RESPONSE_BYTES);
        } catch (AuthException error) {
            throw new SyncException(SyncFailure.TRANSIENT, error.getMessage(), error);
        }
        if (response.status == 401) {
            throw new SyncException(
                    SyncFailure.UNAUTHORIZED,
                    "Agent 权限同步凭据已失效");
        }
        if (!response.isSuccessful()) {
            String code = errorCode(response.body);
            SyncFailure failure =
                    AgentSyncFailurePolicy.forResponse(response.status, code);
            if (failure == SyncFailure.PROXY_ADDRESS_REQUIRED) {
                throw new SyncException(
                        failure,
                        "管理员尚未为当前账户分配 Proxy 地址");
            }
            throw new SyncException(
                    failure,
                    "权限同步服务返回 HTTP " + response.status);
        }
        try {
            AgentAuthDtos.ProfileSyncResponse body = AgentAuthJsonCodec.decode(
                    response.body,
                    AgentAuthDtos.ProfileSyncResponse.class);
            return AgentAuthResponseParser.parseProfileSync(body, expectedUsername);
        } catch (AuthException error) {
            throw new SyncException(
                    SyncFailure.INVALID_RESPONSE,
                    error.getMessage(),
                    error);
        }
    }

    AgentDeviceAuthModels.Authorization startDeviceAuthorization() throws AuthException {
        AgentAuthDtos.DeviceStartResponse response = transport.requestObject(
                "POST",
                "/api/v1/agent/device-authorizations",
                new AgentAuthDtos.DeviceStartRequest(
                        "android",
                        "PPAASS Android Agent"),
                null,
                MAX_NORMAL_RESPONSE_BYTES,
                AgentAuthDtos.DeviceStartResponse.class);
        String deviceCode = requireText(response.device_code);
        String userCode = requireText(response.user_code);
        String verificationUri = requireText(response.verification_uri);
        String verificationUriComplete = requireText(response.verification_uri_complete);
        long expiresIn = requireLong(response.expires_in);
        long interval = requireLong(response.interval);
        if (deviceCode.length() != 43
                || !isUrlSafeToken(deviceCode)
                || userCode.length() > 64
                || expiresIn < 1
                || expiresIn > MAX_DEVICE_AUTHORIZATION_SECONDS
                || interval < 1
                || interval > MAX_DEVICE_POLL_DELAY_SECONDS) {
            throw new AuthException("Proxy Registry 返回的设备登录参数无效");
        }
        try {
            AgentAuthConfig.resolveServiceRelativeUrl(baseUrl, verificationUri);
            String verificationUrl = AgentAuthConfig.resolveServiceRelativeUrl(
                    baseUrl,
                    verificationUriComplete);
            return new AgentDeviceAuthModels.Authorization(
                    deviceCode,
                    verificationUrl,
                    (int) expiresIn,
                    (int) interval);
        } catch (IllegalArgumentException error) {
            throw new AuthException("Proxy Registry 返回的设备登录地址无效", error);
        }
    }

    AgentDeviceAuthModels.PollResult pollDeviceAuthorization(
            String deviceCode,
            int currentIntervalSeconds) throws AuthException {
        AgentAuthHttpTransport.Response response = transport.execute(
                "POST",
                "/api/v1/agent/device-authorizations/token",
                new AgentAuthDtos.DeviceTokenRequest(deviceCode),
                null,
                null,
                MAX_CREDENTIAL_RESPONSE_BYTES);
        if (response.isSuccessful()) {
            AgentAuthDtos.CredentialResponse body = AgentAuthJsonCodec.decode(
                    response.body,
                    AgentAuthDtos.CredentialResponse.class);
            try {
                LoginResult result = AgentAuthResponseParser.parseLogin(body);
                if (transport.isCancelled()) {
                    throw new CancelledException();
                }
                return AgentDeviceAuthModels.PollResult.authorized(result);
            } finally {
                if (body.csrf_token != null && !body.csrf_token.isEmpty()) {
                    transport.bestEffortLogout(
                            body.csrf_token,
                            MAX_NORMAL_RESPONSE_BYTES);
                }
            }
        }

        String code = errorCode(response.body);
        if (response.status == 428 && "authorization_pending".equals(code)) {
            return AgentDeviceAuthModels.PollResult.pending(devicePollDelaySeconds(
                    currentIntervalSeconds,
                    response.retryAfterSeconds,
                    false));
        }
        int rateLimitDelay = devicePollRateLimitDelaySeconds(
                response.status,
                code,
                currentIntervalSeconds,
                response.retryAfterSeconds);
        if (rateLimitDelay > 0) {
            return "slow_down".equals(code)
                    ? AgentDeviceAuthModels.PollResult.slowDown(rateLimitDelay)
                    : AgentDeviceAuthModels.PollResult.pending(rateLimitDelay);
        }
        if (response.status == 403 && "access_denied".equals(code)) {
            throw new AuthException("你已拒绝这次 Agent 登录");
        }
        if (response.status == 403 && "authorization_invalidated".equals(code)) {
            throw new AuthException("账号状态已变化，请重新开始登录");
        }
        if (response.status == 400 && "expired_token".equals(code)) {
            throw new AuthException("设备登录请求已过期，请重新开始");
        }
        if (response.status == 400 && "invalid_device_code".equals(code)) {
            throw new AuthException("设备登录请求无效或已被使用，请重新开始");
        }
        throw AgentAuthErrors.apiError(response.status, response.body);
    }

    void cancel() {
        transport.cancel();
    }

    static int devicePollDelaySeconds(
            int currentIntervalSeconds,
            int retryAfterSeconds,
            boolean slowDown) {
        return AgentDevicePollPolicy.delaySeconds(
                currentIntervalSeconds, retryAfterSeconds, slowDown);
    }

    static int devicePollRateLimitDelaySeconds(
            int status,
            String code,
            int currentIntervalSeconds,
            int retryAfterSeconds) {
        return AgentDevicePollPolicy.rateLimitDelaySeconds(
                status, code, currentIntervalSeconds, retryAfterSeconds);
    }

    private static String errorCode(byte[] body) {
        AgentAuthDtos.ApiErrorEnvelope envelope = AgentAuthJsonCodec.decodeError(
                body,
                AgentAuthDtos.ApiErrorEnvelope.class);
        return envelope == null || envelope.error == null || envelope.error.code == null
                ? ""
                : envelope.error.code;
    }

    private static String requireText(String value) throws AuthException {
        if (value == null || value.isEmpty()) {
            throw new AuthException("Proxy Registry 响应格式无效");
        }
        return value;
    }

    private static long requireLong(Long value) throws AuthException {
        if (value == null) {
            throw new AuthException("Proxy Registry 响应格式无效");
        }
        return value;
    }

    private static boolean isUrlSafeToken(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!(Character.isLetterOrDigit(character)
                    || character == '-'
                    || character == '_')) {
                return false;
            }
        }
        return true;
    }

    static final class LoginResult {
        final String username;
        final String displayName;
        final String avatarUrl;
        final String role;
        final Set<String> permissions;
        final List<String> proxyAddresses;
        final List<ManagedProxyEntries.Entry> proxyEntries;
        final List<String> selectedProxyEntryIds;
        final long keyVersion;
        final long expiresAt;
        final String privateKeyPem;
        final String accessToken;
        final long accessTokenExpiresAt;
        final int refreshAfterSeconds;

        LoginResult(
                String username,
                String displayName,
                String avatarUrl,
                String role,
                Set<String> permissions,
                List<String> proxyAddresses,
                List<ManagedProxyEntries.Entry> proxyEntries,
                List<String> selectedProxyEntryIds,
                long keyVersion,
                long expiresAt,
                String privateKeyPem,
                String accessToken,
                long accessTokenExpiresAt,
                int refreshAfterSeconds) {
            this.username = username;
            this.displayName = displayName;
            this.avatarUrl = avatarUrl;
            this.role = role;
            this.permissions = permissions;
            this.proxyAddresses = proxyAddresses;
            this.proxyEntries = proxyEntries;
            this.selectedProxyEntryIds = selectedProxyEntryIds;
            this.keyVersion = keyVersion;
            this.expiresAt = expiresAt;
            this.privateKeyPem = privateKeyPem;
            this.accessToken = accessToken;
            this.accessTokenExpiresAt = accessTokenExpiresAt;
            this.refreshAfterSeconds = refreshAfterSeconds;
        }
    }

    static final class ProfileSyncResult {
        final String username;
        final String displayName;
        final String avatarUrl;
        final String role;
        final String accountStatus;
        final Set<String> permissions;
        final List<String> proxyAddresses;
        final List<ManagedProxyEntries.Entry> proxyEntries;
        final List<String> selectedProxyEntryIds;
        final boolean profileEnabled;
        final long keyVersion;
        final long expiresAt;
        final String keyState;
        final String accessToken;
        final long accessTokenExpiresAt;
        final int refreshAfterSeconds;

        ProfileSyncResult(
                String username,
                String displayName,
                String avatarUrl,
                String role,
                String accountStatus,
                Set<String> permissions,
                List<String> proxyAddresses,
                List<ManagedProxyEntries.Entry> proxyEntries,
                List<String> selectedProxyEntryIds,
                boolean profileEnabled,
                long keyVersion,
                long expiresAt,
                String keyState,
                String accessToken,
                long accessTokenExpiresAt,
                int refreshAfterSeconds) {
            this.username = username;
            this.displayName = displayName;
            this.avatarUrl = avatarUrl;
            this.role = role;
            this.accountStatus = accountStatus;
            this.permissions = permissions;
            this.proxyAddresses = proxyAddresses;
            this.proxyEntries = proxyEntries;
            this.selectedProxyEntryIds = selectedProxyEntryIds;
            this.profileEnabled = profileEnabled;
            this.keyVersion = keyVersion;
            this.expiresAt = expiresAt;
            this.keyState = keyState;
            this.accessToken = accessToken;
            this.accessTokenExpiresAt = accessTokenExpiresAt;
            this.refreshAfterSeconds = refreshAfterSeconds;
        }
    }

    enum SyncFailure {
        UNAUTHORIZED,
        TRANSIENT,
        PROXY_ADDRESS_REQUIRED,
        SERVICE_REJECTED,
        INVALID_RESPONSE
    }

    static final class SyncException extends Exception {
        final SyncFailure failure;

        SyncException(SyncFailure failure, String message) {
            super(message);
            this.failure = failure;
        }

        SyncException(SyncFailure failure, String message, Throwable cause) {
            super(message, cause);
            this.failure = failure;
        }
    }

    static final class CancelledException extends AuthException {
        CancelledException() {
            super("设备登录已取消");
        }
    }

    static class AuthException extends Exception {
        AuthException(String message) {
            super(message);
        }

        AuthException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
