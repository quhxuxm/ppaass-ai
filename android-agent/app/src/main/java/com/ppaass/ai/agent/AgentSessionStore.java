package com.ppaass.ai.agent;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

final class AgentSessionStore {
    static final String PREF_ROLE = "managed_account_role";
    static final String PREF_DISPLAY_NAME = "managed_account_display_name";
    static final String PREF_AVATAR_URL = "managed_account_avatar_url";
    static final String PREF_PERMISSIONS = "managed_agent_permissions";
    static final String PREF_ACCESS_TOKEN = "managed_agent_access_token";
    static final String PREF_ACCESS_TOKEN_EXPIRES_AT =
            "managed_agent_access_token_expires_at";
    static final String PREF_REFRESH_SECONDS = "managed_agent_refresh_seconds";
    static final String PREF_SYNC_STATE = "managed_agent_sync_state";
    static final String PREF_SYNC_MESSAGE = "managed_agent_sync_message";
    static final String PREF_ACCOUNT_STATUS = "managed_account_status";
    static final String PREF_KEY_STATE = "managed_key_state";
    static final String PREF_PERMISSION_REVISION = "managed_permission_revision";
    static final String PREF_PROXY_ASSIGNMENT_STATE =
            "managed_proxy_assignment_state";
    static final String PROXY_ASSIGNMENT_ASSIGNED = "assigned";
    static final String PROXY_ASSIGNMENT_MISSING = "missing";

    private static final String STATE_CURRENT = "current";
    private static final String STATE_LEGACY = "legacy";
    private static final String STATE_UNAUTHORIZED = "unauthorized";
    private static final String STATE_UNAVAILABLE = "unavailable";
    private static final int DEFAULT_REFRESH_SECONDS = 5 * 60;

    private AgentSessionStore() {
    }

    static void installInto(
            SharedPreferences.Editor editor,
            AgentAuthClient.LoginResult result) {
        editor.putString(PREF_ROLE, result.role)
                .putString(PREF_DISPLAY_NAME, result.displayName)
                .putString(PREF_AVATAR_URL, result.avatarUrl)
                .putStringSet(PREF_PERMISSIONS, new HashSet<>(result.permissions))
                .putString(
                        ManagedProxyAddresses.PREF_PROXY_ADDRESSES,
                        ManagedProxyAddresses.serialize(result.proxyAddresses))
                .putString(
                        ManagedProxyEntries.PREF_ENTRIES,
                        ManagedProxyEntries.serialize(result.proxyEntries))
                .putString(
                        ManagedProxyEntries.PREF_SELECTED_IDS,
                        ManagedProxyEntries.serializeSelectedIds(
                                result.selectedProxyEntryIds))
                .putString(
                        PREF_PROXY_ASSIGNMENT_STATE,
                        PROXY_ASSIGNMENT_ASSIGNED)
                .putString(PREF_ACCESS_TOKEN, result.accessToken)
                .putLong(PREF_ACCESS_TOKEN_EXPIRES_AT, result.accessTokenExpiresAt)
                .putInt(PREF_REFRESH_SECONDS, result.refreshAfterSeconds)
                .putString(PREF_SYNC_STATE, STATE_CURRENT)
                .putString(PREF_SYNC_MESSAGE, "")
                .putString(PREF_ACCOUNT_STATUS, "active")
                .putString(PREF_KEY_STATE, "active")
                .putInt(PREF_PERMISSION_REVISION, 1);
    }

    static StoredSession load(Context context) {
        SharedPreferences preferences = preferences(context);
        boolean current = preferences.contains(PREF_ROLE)
                && preferences.contains(PREF_ACCESS_TOKEN);
        String role = preferences.getString(PREF_ROLE, AgentPermissions.ROLE_USER);
        if (!AgentPermissions.isSupportedRole(role)) {
            role = AgentPermissions.ROLE_USER;
            current = false;
        }
        Set<String> stored = preferences.getStringSet(
                PREF_PERMISSIONS,
                Collections.emptySet());
        Set<String> permissions = AgentPermissions.immutableCopy(
                stored == null ? Collections.emptySet() : new HashSet<>(stored));
        String token = preferences.getString(PREF_ACCESS_TOKEN, "");
        if (token == null) {
            token = "";
        }
        return new StoredSession(
                role,
                preferences.getString(PREF_DISPLAY_NAME, ""),
                preferences.getString(PREF_AVATAR_URL, ""),
                permissions,
                token,
                preferences.getLong(PREF_ACCESS_TOKEN_EXPIRES_AT, -1),
                clampedRefresh(preferences.getInt(
                        PREF_REFRESH_SECONDS,
                        DEFAULT_REFRESH_SECONDS)),
                !current || token.isEmpty());
    }

    static boolean persistSync(
            Context context,
            AgentAuthClient.ProfileSyncResult result,
            long localKeyVersion) {
        SharedPreferences preferences = preferences(context);
        SharedPreferences.Editor editor = preferences.edit()
                .putString(PREF_ROLE, result.role)
                .putString(PREF_DISPLAY_NAME, result.displayName)
                .putString(PREF_AVATAR_URL, result.avatarUrl)
                .putStringSet(PREF_PERMISSIONS, new HashSet<>(result.permissions))
                .putString(
                        ManagedProxyAddresses.PREF_PROXY_ADDRESSES,
                        ManagedProxyAddresses.serialize(result.proxyAddresses))
                .putString(
                        ManagedProxyEntries.PREF_ENTRIES,
                        ManagedProxyEntries.serialize(result.proxyEntries))
                .putString(
                        ManagedProxyEntries.PREF_SELECTED_IDS,
                        ManagedProxyEntries.serializeSelectedIds(
                                result.selectedProxyEntryIds))
                .putString(
                        PREF_PROXY_ASSIGNMENT_STATE,
                        PROXY_ASSIGNMENT_ASSIGNED)
                .putString(PREF_ACCESS_TOKEN, result.accessToken)
                .putLong(PREF_ACCESS_TOKEN_EXPIRES_AT, result.accessTokenExpiresAt)
                .putInt(PREF_REFRESH_SECONDS, result.refreshAfterSeconds)
                .putString(PREF_SYNC_STATE, STATE_CURRENT)
                .putString(PREF_ACCOUNT_STATUS, result.accountStatus)
                .putString(PREF_KEY_STATE, result.keyState)
                .putString(
                        PREF_SYNC_MESSAGE,
                        successMessage(result, localKeyVersion))
                .putInt(
                        PREF_PERMISSION_REVISION,
                        nextRevision(preferences));
        if (result.keyVersion == localKeyVersion) {
            editor.putLong(ManagedCredentials.PREF_EXPIRES_AT, result.expiresAt);
        }
        return editor.commit();
    }

    static boolean recordLegacySession(Context context) {
        SharedPreferences preferences = preferences(context);
        if (STATE_LEGACY.equals(preferences.getString(PREF_SYNC_STATE, ""))) {
            return true;
        }
        return preferences.edit()
                .putString(PREF_SYNC_STATE, STATE_LEGACY)
                .putString(
                        PREF_SYNC_MESSAGE,
                        "当前登录来自旧版本，请重新登录以启用权限同步；代理连接保持不变")
                .putInt(PREF_PERMISSION_REVISION, nextRevision(preferences))
                .commit();
    }

    static boolean recordSyncFailure(
            Context context,
            AgentAuthClient.SyncFailure failure) {
        SharedPreferences preferences = preferences(context);
        boolean unauthorized = failure == AgentAuthClient.SyncFailure.UNAUTHORIZED;
        String message = unauthorized
                ? "权限同步凭据已失效，请重新登录以恢复权限同步；当前代理和密钥保持不变"
                : "暂时无法同步账号权限，继续使用上次成功同步的权限";
        return preferences.edit()
                .putString(
                        PREF_SYNC_STATE,
                        unauthorized ? STATE_UNAUTHORIZED : STATE_UNAVAILABLE)
                .putString(PREF_SYNC_MESSAGE, message)
                .putInt(PREF_PERMISSION_REVISION, nextRevision(preferences))
                .commit();
    }

    static boolean recordManagedProxyAddressFailure(Context context) {
        SharedPreferences preferences = preferences(context);
        return preferences.edit()
                .remove(ManagedProxyAddresses.PREF_PROXY_ADDRESSES)
                .remove(ManagedProxyEntries.PREF_ENTRIES)
                .remove(ManagedProxyEntries.PREF_SELECTED_IDS)
                .remove(ManagedProxyEntries.LEGACY_PREF_SELECTED_ID)
                .putString(
                        PREF_PROXY_ASSIGNMENT_STATE,
                        PROXY_ASSIGNMENT_MISSING)
                .putString(PREF_SYNC_STATE, STATE_UNAVAILABLE)
                .putString(
                        PREF_SYNC_MESSAGE,
                        "管理员尚未分配有效 Proxy 地址；Agent 保持登录，网络服务已停止")
                .putInt(PREF_PERMISSION_REVISION, nextRevision(preferences))
                .commit();
    }

    static boolean recordLegacyManagedProxyAddressFailure(Context context) {
        SharedPreferences preferences = preferences(context);
        return preferences.edit()
                .remove(ManagedProxyAddresses.PREF_PROXY_ADDRESSES)
                .putString(PREF_SYNC_STATE, STATE_UNAVAILABLE)
                .putString(
                        PREF_SYNC_MESSAGE,
                        "旧版登录没有受管 Proxy 地址，网络服务已停止；请重新登录")
                .putInt(PREF_PERMISSION_REVISION, nextRevision(preferences))
                .commit();
    }

    static String proxyAssignmentState(Context context) {
        String state;
        try {
            state = preferences(context).getString(
                    PREF_PROXY_ASSIGNMENT_STATE,
                    "");
        } catch (ClassCastException error) {
            return "";
        }
        return state == null ? "" : state;
    }

    static String syncMessage(Context context) {
        String message = preferences(context).getString(PREF_SYNC_MESSAGE, "");
        return message == null ? "" : message;
    }

    static boolean serverDisabled(Context context) {
        return "disabled".equals(
                preferences(context).getString(PREF_ACCOUNT_STATUS, "active"))
                || "disabled".equals(
                preferences(context).getString(PREF_KEY_STATE, "active"));
    }

    static void clearFrom(SharedPreferences.Editor editor) {
        editor.remove(PREF_ROLE)
                .remove(PREF_DISPLAY_NAME)
                .remove(PREF_AVATAR_URL)
                .remove(PREF_PERMISSIONS)
                .remove(ManagedProxyAddresses.PREF_PROXY_ADDRESSES)
                .remove(ManagedProxyEntries.PREF_ENTRIES)
                .remove(ManagedProxyEntries.PREF_SELECTED_IDS)
                .remove(ManagedProxyEntries.LEGACY_PREF_SELECTED_ID)
                .remove(PREF_PROXY_ASSIGNMENT_STATE)
                .remove(PREF_ACCESS_TOKEN)
                .remove(PREF_ACCESS_TOKEN_EXPIRES_AT)
                .remove(PREF_REFRESH_SECONDS)
                .remove(PREF_SYNC_STATE)
                .remove(PREF_SYNC_MESSAGE)
                .remove(PREF_ACCOUNT_STATUS)
                .remove(PREF_KEY_STATE)
                .remove(PREF_PERMISSION_REVISION);
    }

    static int clampedRefresh(int seconds) {
        return AgentAuthResponseParser.clampRefreshSeconds(seconds);
    }

    private static String successMessage(
            AgentAuthClient.ProfileSyncResult result,
            long localKeyVersion) {
        if ("disabled".equals(result.accountStatus)
                || "disabled".equals(result.keyState)) {
            return "账号已停用；Agent 保持登录，代理连接会在服务端认证时被拒绝";
        }
        if ("expired".equals(result.keyState) || "missing".equals(result.keyState)) {
            return "账号密钥不可用或已过期；Agent 保持登录，请联系管理员";
        }
        if (!result.profileEnabled) {
            return "账号已停用；Agent 保持登录，代理连接会在服务端认证时被拒绝";
        }
        if (result.keyVersion != localKeyVersion) {
            return "服务端密钥已变更，请重新登录下载新密钥；当前 Agent 不会自动退出";
        }
        return "";
    }

    private static int nextRevision(SharedPreferences preferences) {
        int current = preferences.getInt(PREF_PERMISSION_REVISION, 0);
        return current == Integer.MAX_VALUE ? 1 : current + 1;
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(
                ManagedCredentials.PREFERENCES_NAME,
                Context.MODE_PRIVATE);
    }

    static final class StoredSession {
        final String role;
        final String displayName;
        final String avatarUrl;
        final Set<String> permissions;
        final String accessToken;
        final long accessTokenExpiresAt;
        final int refreshSeconds;
        final boolean needsRelogin;

        StoredSession(
                String role,
                String displayName,
                String avatarUrl,
                Set<String> permissions,
                String accessToken,
                long accessTokenExpiresAt,
                int refreshSeconds,
                boolean needsRelogin) {
            this.role = role;
            this.displayName = displayName == null ? "" : displayName;
            this.avatarUrl = avatarUrl == null ? "" : avatarUrl;
            this.permissions = permissions;
            this.accessToken = accessToken;
            this.accessTokenExpiresAt = accessTokenExpiresAt;
            this.refreshSeconds = refreshSeconds;
            this.needsRelogin = needsRelogin;
        }
    }
}
