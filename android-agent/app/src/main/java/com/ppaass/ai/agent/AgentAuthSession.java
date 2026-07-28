package com.ppaass.ai.agent;

import android.content.Context;

final class AgentAuthSession {
    private static String username;
    private static long keyVersion = -1;
    private static long expiresAt = -1;

    private AgentAuthSession() {
    }

    static synchronized void authenticate(
            String authenticatedUsername,
            long authenticatedKeyVersion,
            long authenticatedExpiresAt) {
        username = authenticatedUsername;
        keyVersion = authenticatedKeyVersion;
        expiresAt = authenticatedExpiresAt;
    }

    static synchronized void clear() {
        username = null;
        keyVersion = -1;
        expiresAt = -1;
    }

    static synchronized boolean isActive(Context context) {
        if (username == null || username.isEmpty() || keyVersion < 0) {
            return false;
        }
        if (expiresAt <= System.currentTimeMillis() / 1000L) {
            return false;
        }
        return ManagedCredentials.matches(context, username, keyVersion, expiresAt);
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
