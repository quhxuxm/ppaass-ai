package com.ppaass.ai.agent;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class AgentAuthResponseParser {
    static final int MIN_REFRESH_SECONDS = 60;
    static final int MAX_REFRESH_SECONDS = 60 * 60;
    private static final int MAX_ACCESS_TOKEN_BYTES = 4 * 1024;

    private AgentAuthResponseParser() {
    }

    static AgentAuthClient.LoginResult parseLogin(
            AgentAuthDtos.CredentialResponse response)
            throws AgentAuthClient.AuthException {
        AgentAuthDtos.Account account = requireAccount(response.account);
        String role = requireRole(account.role);
        if (!"active".equals(account.status)) {
            throw new AgentAuthClient.AuthException("账号已停用");
        }

        AgentAuthDtos.Profile profile = requireProfile(response.profile);
        String username = requireText(profile.username);
        requireLinkedUsername(account.linked_username, username);
        if (!Boolean.TRUE.equals(profile.enabled)) {
            throw new AgentAuthClient.AuthException("Proxy 用户已停用");
        }
        Set<String> permissions = permissions(profile.permissions);
        List<String> proxyAddresses =
                ManagedProxyAddresses.require(profile.proxy_addresses);
        ManagedProxyEntries.Selection proxyEntries = ManagedProxyEntries.require(
                profile.proxy_entries,
                profile.selected_proxy_entry_id,
                AgentPermissions.allows(
                        role,
                        permissions,
                        AgentPermissions.PROXY_ENTRY_SELECT));
        long keyVersion = requireLong(profile.key_version);
        long expiresAt = optionalEpoch(profile.expires_at);
        if (keyVersion < 1 || expiresAt == 0 || expiresAt < -1) {
            throw invalidResponse();
        }

        String privateKeyPem = requireText(response.private_key_pem);
        String publicKeyPem = requireText(response.public_key_pem);
        AgentKeyValidator.validateMatchingKeyPair(privateKeyPem, publicKeyPem);

        return new AgentAuthClient.LoginResult(
                username,
                optionalDisplayName(account.display_name),
                optionalAvatarUrl(account.avatar_url),
                role,
                permissions,
                proxyAddresses,
                proxyEntries.entries,
                proxyEntries.selectedId,
                keyVersion,
                expiresAt,
                privateKeyPem,
                accessToken(response.agent_access_token),
                accessTokenExpiresAt(response.agent_access_token_expires_at),
                refreshSeconds(response.refresh_after_seconds));
    }

    static AgentAuthClient.ProfileSyncResult parseProfileSync(
            AgentAuthDtos.ProfileSyncResponse response,
            String expectedUsername) throws AgentAuthClient.AuthException {
        AgentAuthDtos.Account account = requireAccount(response.account);
        String role = requireRole(account.role);
        if (!"active".equals(account.status) && !"disabled".equals(account.status)) {
            throw invalidResponse();
        }
        String keyState = requireText(response.key_state);
        if (!isKeyState(keyState)) {
            throw invalidResponse();
        }

        String username = expectedUsername;
        Set<String> permissions = Collections.emptySet();
        List<String> proxyAddresses = Collections.emptyList();
        ManagedProxyEntries.Selection proxyEntries = ManagedProxyEntries.Selection.empty();
        boolean profileEnabled = false;
        long keyVersion = -1;
        long expiresAt = -1;
        if (response.profile != null) {
            AgentAuthDtos.Profile profile = requireProfile(response.profile);
            username = requireText(profile.username);
            if (!username.equals(expectedUsername)) {
                throw new AgentAuthClient.AuthException(
                        "Proxy Registry 返回了其他用户的权限配置");
            }
            requireLinkedUsername(account.linked_username, username);
            permissions = permissions(profile.permissions);
            proxyAddresses =
                    ManagedProxyAddresses.require(profile.proxy_addresses);
            proxyEntries = ManagedProxyEntries.require(
                    profile.proxy_entries,
                    profile.selected_proxy_entry_id,
                    AgentPermissions.allows(
                            role,
                            permissions,
                            AgentPermissions.PROXY_ENTRY_SELECT));
            profileEnabled = requireBoolean(profile.enabled);
            keyVersion = requireLong(profile.key_version);
            expiresAt = optionalEpoch(profile.expires_at);
            if (keyVersion < 0 || expiresAt == 0 || expiresAt < -1) {
                throw invalidResponse();
            }
        }

        return new AgentAuthClient.ProfileSyncResult(
                username,
                optionalDisplayName(account.display_name),
                optionalAvatarUrl(account.avatar_url),
                role,
                account.status,
                permissions,
                proxyAddresses,
                proxyEntries.entries,
                proxyEntries.selectedId,
                profileEnabled,
                keyVersion,
                expiresAt,
                keyState,
                accessToken(response.agent_access_token),
                accessTokenExpiresAt(response.agent_access_token_expires_at),
                refreshSeconds(response.refresh_after_seconds));
    }

    static int clampRefreshSeconds(long seconds) {
        return (int) Math.max(
                MIN_REFRESH_SECONDS,
                Math.min(seconds, MAX_REFRESH_SECONDS));
    }

    private static AgentAuthDtos.Account requireAccount(AgentAuthDtos.Account account)
            throws AgentAuthClient.AuthException {
        if (account == null
                || requireText(account.status).isEmpty()
                || requireText(account.role).isEmpty()) {
            throw invalidResponse();
        }
        return account;
    }

    private static AgentAuthDtos.Profile requireProfile(AgentAuthDtos.Profile profile)
            throws AgentAuthClient.AuthException {
        if (profile == null) {
            throw invalidResponse();
        }
        return profile;
    }

    private static String requireRole(String role)
            throws AgentAuthClient.AuthException {
        if (!AgentPermissions.isSupportedRole(role)) {
            throw invalidResponse();
        }
        return role;
    }

    private static String optionalDisplayName(String value)
            throws AgentAuthClient.AuthException {
        if (value == null) {
            return "";
        }
        value = value.trim();
        if (value.codePointCount(0, value.length()) > 6
                || value.chars().anyMatch(Character::isISOControl)) {
            throw invalidResponse();
        }
        return value;
    }

    private static String optionalAvatarUrl(String value) {
        if (value == null) {
            return "";
        }
        if (value.length() > 1_500_000
                || !(value.startsWith("data:image/png;base64,")
                || value.startsWith("data:image/jpeg;base64,")
                || value.startsWith("data:image/webp;base64,"))) {
            // Avatar data is presentational and must never invalidate otherwise
            // valid Agent credentials or stop an SSE profile refresh.
            return "";
        }
        return value;
    }

    private static void requireLinkedUsername(String linkedUsername, String username)
            throws AgentAuthClient.AuthException {
        if (linkedUsername != null && !linkedUsername.equals(username)) {
            throw new AgentAuthClient.AuthException(
                    "账号与 Proxy 用户绑定关系不一致，请联系管理员");
        }
    }

    private static Set<String> permissions(List<String> values)
            throws AgentAuthClient.AuthException {
        if (values == null || values.size() > 256) {
            throw invalidResponse();
        }
        LinkedHashSet<String> permissions = new LinkedHashSet<>();
        for (String value : values) {
            if (!AgentPermissions.isValidPermission(value)) {
                throw invalidResponse();
            }
            permissions.add(value);
        }
        return AgentPermissions.immutableCopy(permissions);
    }

    private static String accessToken(String token)
            throws AgentAuthClient.AuthException {
        token = requireText(token);
        if (token.length() > MAX_ACCESS_TOKEN_BYTES || !isUrlSafeToken(token)) {
            throw invalidResponse();
        }
        return token;
    }

    private static long accessTokenExpiresAt(Long expiresAt)
            throws AgentAuthClient.AuthException {
        long value = requireLong(expiresAt);
        if (value <= 0) {
            throw invalidResponse();
        }
        return value;
    }

    private static int refreshSeconds(Long seconds)
            throws AgentAuthClient.AuthException {
        return clampRefreshSeconds(requireLong(seconds));
    }

    private static long optionalEpoch(Long value) {
        return value == null ? -1 : value;
    }

    private static long requireLong(Long value)
            throws AgentAuthClient.AuthException {
        if (value == null) {
            throw invalidResponse();
        }
        return value;
    }

    private static boolean requireBoolean(Boolean value)
            throws AgentAuthClient.AuthException {
        if (value == null) {
            throw invalidResponse();
        }
        return value;
    }

    private static String requireText(String value)
            throws AgentAuthClient.AuthException {
        if (value == null || value.isEmpty()) {
            throw invalidResponse();
        }
        return value;
    }

    private static boolean isKeyState(String value) {
        return "active".equals(value)
                || "missing".equals(value)
                || "expired".equals(value)
                || "disabled".equals(value);
    }

    private static boolean isUrlSafeToken(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            boolean allowed = character >= 'a' && character <= 'z'
                    || character >= 'A' && character <= 'Z'
                    || character >= '0' && character <= '9'
                    || character == '-'
                    || character == '_';
            if (!allowed) {
                return false;
            }
        }
        return true;
    }

    private static AgentAuthClient.AuthException invalidResponse() {
        return new AgentAuthClient.AuthException("Proxy Registry 响应格式无效");
    }
}
