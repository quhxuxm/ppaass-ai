package com.ppaass.ai.agent;

import android.content.Context;

final class AgentAuthSession {
    static final String PREF_SERVER_AUTHENTICATION_STATUS =
            "server_authentication_status";
    private static final int SERVER_STATUS_ACTIVE = 0;
    private static final int SERVER_STATUS_USER_EXPIRED = 1;
    private static final int SERVER_STATUS_USER_DISABLED = 2;

    private static String username;
    private static long keyVersion = -1;
    private static long expiresAt = -1;
    private static boolean initialized;

    private AgentAuthSession() {
    }

    static synchronized void authenticate(
            String authenticatedUsername,
            long authenticatedKeyVersion,
            long authenticatedExpiresAt) {
        username = authenticatedUsername;
        keyVersion = authenticatedKeyVersion;
        expiresAt = authenticatedExpiresAt;
        initialized = true;
    }

    static synchronized void clear() {
        username = null;
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
            username = null;
            keyVersion = -1;
            expiresAt = -1;
            initialized = true;
            return false;
        }
        username = metadata.username;
        keyVersion = metadata.keyVersion;
        expiresAt = metadata.expiresAt;
        initialized = true;
        return true;
    }

    static boolean hasAuthenticatedIdentity(String candidateUsername, long candidateKeyVersion) {
        return candidateUsername != null
                && !candidateUsername.isEmpty()
                && candidateKeyVersion >= 0;
    }

    static boolean applyVerifiedServerStatus(Context context, int authenticationStatus) {
        int serverStatus = serverStatusForNativeStatus(authenticationStatus);
        if (serverStatus < 0) {
            return false;
        }
        android.content.SharedPreferences preferences = context.getSharedPreferences(
                ManagedCredentials.PREFERENCES_NAME,
                Context.MODE_PRIVATE);
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
        return context.getSharedPreferences(
                        ManagedCredentials.PREFERENCES_NAME,
                        Context.MODE_PRIVATE)
                .getInt(PREF_SERVER_AUTHENTICATION_STATUS, SERVER_STATUS_ACTIVE);
    }

    static boolean isServerExpired(Context context) {
        return serverStatus(context) == SERVER_STATUS_USER_EXPIRED;
    }

    static boolean isServerDisabled(Context context) {
        return serverStatus(context) == SERVER_STATUS_USER_DISABLED;
    }

    static synchronized String username() {
        return username == null ? "" : username;
    }

    static synchronized long keyVersion() {
        return keyVersion;
    }

    static synchronized long expiresAt() {
        return expiresAt;
    }
}
