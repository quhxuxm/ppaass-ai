package com.ppaass.ai.agent;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

final class AgentAuthSession {
    static final String PREF_SERVER_AUTHENTICATION_STATUS =
            "server_authentication_status";
    private static final int SERVER_STATUS_ACTIVE = 0;
    private static final int SERVER_STATUS_USER_EXPIRED = 1;
    private static final int SERVER_STATUS_USER_DISABLED = 2;

    private static String username;
    private static String role = AgentPermissions.ROLE_USER;
    private static Set<String> permissions = Collections.emptySet();
    private static long keyVersion = -1;
    private static long expiresAt = -1;
    private static boolean initialized;

    private AgentAuthSession() {
    }

    static synchronized void authenticate(AgentAuthClient.LoginResult result) {
        authenticate(
                result.username,
                result.role,
                result.permissions,
                result.keyVersion,
                result.expiresAt);
    }

    static synchronized void authenticate(
            String authenticatedUsername,
            long authenticatedKeyVersion,
            long authenticatedExpiresAt) {
        authenticate(
                authenticatedUsername,
                AgentPermissions.ROLE_USER,
                Collections.emptySet(),
                authenticatedKeyVersion,
                authenticatedExpiresAt);
    }

    private static void authenticate(
            String authenticatedUsername,
            String authenticatedRole,
            Set<String> authenticatedPermissions,
            long authenticatedKeyVersion,
            long authenticatedExpiresAt) {
        username = authenticatedUsername;
        role = authenticatedRole;
        permissions = AgentPermissions.immutableCopy(authenticatedPermissions);
        keyVersion = authenticatedKeyVersion;
        expiresAt = authenticatedExpiresAt;
        initialized = true;
    }

    static synchronized void clear() {
        username = null;
        role = AgentPermissions.ROLE_USER;
        permissions = Collections.emptySet();
        keyVersion = -1;
        expiresAt = -1;
        initialized = true;
    }

    static synchronized boolean isActive(Context context) {
        if (!initialized) {
            restore(context);
        }
        return hasAuthenticatedIdentity(username, keyVersion);
    }

    static synchronized boolean restore(Context context) {
        ManagedCredentials.Metadata metadata = ManagedCredentials.loadMetadata(context);
        if (metadata == null) {
            clear();
            return false;
        }
        AgentSessionStore.StoredSession stored = AgentSessionStore.load(context);
        authenticate(
                metadata.username,
                stored.role,
                stored.permissions,
                metadata.keyVersion,
                metadata.expiresAt);
        if (stored.needsRelogin) {
            AgentSessionStore.recordLegacySession(context);
        }
        return true;
    }

    static boolean hasAuthenticatedIdentity(String candidateUsername, long candidateKeyVersion) {
        return candidateUsername != null
                && !candidateUsername.isEmpty()
                && candidateKeyVersion >= 0;
    }

    static synchronized boolean hasPermission(Context context, String permission) {
        if (!isActive(context) || AgentSessionStore.serverDisabled(context)) {
            return false;
        }
        return AgentPermissions.allows(role, permissions, permission);
    }

    static synchronized boolean isAdmin(Context context) {
        return isActive(context)
                && !AgentSessionStore.serverDisabled(context)
                && AgentPermissions.ROLE_ADMIN.equals(role);
    }

    static synchronized boolean applySynchronizedProfile(
            Context context,
            AgentAuthClient.ProfileSyncResult result) throws IOException {
        if (!isActive(context) || !username.equals(result.username)) {
            throw new IOException("权限同步返回的账号与当前登录不一致");
        }
        List<String> previousProxyAddresses = ManagedProxyAddresses.load(context);
        long localKeyVersion = keyVersion;
        if (!AgentSessionStore.persistSync(context, result, localKeyVersion)) {
            throw new IOException("无法安全保存同步后的 Agent 权限");
        }
        role = result.role;
        permissions = AgentPermissions.immutableCopy(result.permissions);
        if (result.keyVersion == localKeyVersion) {
            expiresAt = result.expiresAt;
        }
        applyProfileServerStatus(context, result);
        boolean configDefaultsChanged =
                AgentPermissionConfigEnforcer.enforce(context, false);
        if (AgentPermissionConfigPolicy.runningAgentsRequireReload(
                previousProxyAddresses,
                result.proxyAddresses,
                configDefaultsChanged)) {
            AgentPermissionConfigEnforcer.reloadRunningAgents(context);
        }
        return true;
    }

    static boolean applyVerifiedServerStatus(Context context, int authenticationStatus) {
        int serverStatus = serverStatusForNativeStatus(authenticationStatus);
        return serverStatus >= 0 && writeServerStatus(context, serverStatus);
    }

    static int serverStatusForNativeStatus(int authenticationStatus) {
        if (authenticationStatus == NativeAgent.AUTHENTICATION_VERIFIED_ACTIVE) {
            return SERVER_STATUS_ACTIVE;
        }
        if (authenticationStatus == NativeAgent.AUTHENTICATION_USER_EXPIRED) {
            return SERVER_STATUS_USER_EXPIRED;
        }
        if (authenticationStatus == NativeAgent.AUTHENTICATION_USER_DISABLED) {
            return SERVER_STATUS_USER_DISABLED;
        }
        return -1;
    }

    static int serverStatus(Context context) {
        return preferences(context).getInt(
                PREF_SERVER_AUTHENTICATION_STATUS,
                SERVER_STATUS_ACTIVE);
    }

    static boolean isServerExpired(Context context) {
        return serverStatus(context) == SERVER_STATUS_USER_EXPIRED;
    }

    static boolean isServerDisabled(Context context) {
        return serverStatus(context) == SERVER_STATUS_USER_DISABLED
                || AgentSessionStore.serverDisabled(context);
    }

    static synchronized String username() {
        return username == null ? "" : username;
    }

    static synchronized String role() {
        return role;
    }

    static synchronized long keyVersion() {
        return keyVersion;
    }

    static synchronized long expiresAt() {
        return expiresAt;
    }

    static String syncMessage(Context context) {
        return AgentSessionStore.syncMessage(context);
    }

    private static void applyProfileServerStatus(
            Context context,
            AgentAuthClient.ProfileSyncResult result) {
        int status;
        if ("disabled".equals(result.accountStatus)
                || "disabled".equals(result.keyState)) {
            status = SERVER_STATUS_USER_DISABLED;
        } else if ("expired".equals(result.keyState)
                || "missing".equals(result.keyState)) {
            status = SERVER_STATUS_USER_EXPIRED;
        } else if (!result.profileEnabled) {
            status = SERVER_STATUS_USER_DISABLED;
        } else {
            status = SERVER_STATUS_ACTIVE;
        }
        writeServerStatus(context, status);
    }

    private static boolean writeServerStatus(Context context, int serverStatus) {
        SharedPreferences preferences = preferences(context);
        if (preferences.getInt(
                PREF_SERVER_AUTHENTICATION_STATUS,
                SERVER_STATUS_ACTIVE) == serverStatus) {
            return false;
        }
        preferences.edit()
                .putInt(PREF_SERVER_AUTHENTICATION_STATUS, serverStatus)
                .apply();
        return true;
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(
                ManagedCredentials.PREFERENCES_NAME,
                Context.MODE_PRIVATE);
    }
}
