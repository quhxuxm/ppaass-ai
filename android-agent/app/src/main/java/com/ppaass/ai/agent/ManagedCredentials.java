package com.ppaass.ai.agent;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

final class ManagedCredentials {
    static final String PREFERENCES_NAME = "ppaass_agent";
    static final String PREF_USERNAME = "managed_username";
    static final String PREF_KEY_VERSION = "managed_key_version";
    static final String PREF_EXPIRES_AT = "managed_expires_at";
    static final String PREF_PRIVATE_KEY_FILE = "managed_private_key_file";
    static final String PREF_PRIVATE_KEY_LENGTH = "managed_private_key_length";
    static final String PREF_PRIVATE_KEY_SHA256 = "managed_private_key_sha256";
    private ManagedCredentials() {
    }

    @SuppressLint("ApplySharedPref")
    static void install(
            Context context,
            AgentAuthClient.LoginResult result) throws IOException {
        String username = result.username;
        long keyVersion = result.keyVersion;
        long expiresAt = result.expiresAt;
        String privateKeyPem = result.privateKeyPem;
        String normalizedUsername = username == null ? "" : username.trim();
        if (normalizedUsername.isEmpty() || keyVersion < 0) {
            throw new IOException("Proxy Registry 返回的用户凭据无效");
        }
        byte[] privateKeyBytes = privateKeyPem == null
                ? new byte[0]
                : privateKeyPem.getBytes(StandardCharsets.UTF_8);
        if (privateKeyBytes.length == 0
                || privateKeyBytes.length > ManagedCredentialFiles.MAX_PRIVATE_KEY_BYTES) {
            throw new IOException("Proxy Registry 返回的私钥大小无效");
        }
        String privateKeySha256 = ManagedCredentialFiles.sha256Hex(privateKeyBytes);

        File directory = ManagedCredentialFiles.credentialsDirectory(context);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("无法创建 Agent 私钥目录");
        }
        ManagedCredentialFiles.restrictToOwner(directory);
        ManagedCredentialFiles.deleteManagedKeyFiles(directory, null);

        File destination = ManagedCredentialFiles.newManagedCredentialFile(
                directory,
                normalizedUsername,
                keyVersion);
        String fileName = destination.getName();
        File temporary = File.createTempFile(".managed-private-key-", ".tmp", directory);
        ManagedCredentialFiles.restrictToOwner(temporary);
        boolean installed = false;
        IOException failure = null;
        try {
            try (FileOutputStream output = new FileOutputStream(temporary, false)) {
                output.write(privateKeyBytes);
                output.flush();
                output.getFD().sync();
            }
            try {
                Files.move(
                        temporary.toPath(),
                        destination.toPath(),
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException error) {
                Files.move(
                        temporary.toPath(),
                        destination.toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
            }
            ManagedCredentialFiles.restrictToOwner(destination);
            if (!ManagedCredentialFiles.credentialFileMatches(
                    destination,
                    privateKeyBytes.length,
                    privateKeySha256)) {
                throw new IOException("Agent 托管私钥写入校验失败");
            }

            SharedPreferences preferences = preferences(context);
            SharedPreferences.Editor editor = preferences.edit()
                    .putString(PREF_USERNAME, normalizedUsername)
                    .putLong(PREF_KEY_VERSION, keyVersion)
                    .putLong(PREF_EXPIRES_AT, expiresAt)
                    .putString(PREF_PRIVATE_KEY_FILE, fileName)
                    .putLong(PREF_PRIVATE_KEY_LENGTH, privateKeyBytes.length)
                    .putString(PREF_PRIVATE_KEY_SHA256, privateKeySha256)
                    .remove("username")
                    .remove("private_key_pem");
            AgentSessionStore.installInto(editor, result);
            installed = editor.commit();
            if (!installed) {
                throw new IOException("无法保存 Agent 托管凭据");
            }
        } catch (IOException error) {
            failure = error;
            throw error;
        } catch (RuntimeException error) {
            failure = new IOException("无法安全写入 Agent 托管私钥", error);
            throw failure;
        } finally {
            IOException cleanupFailure = null;
            try {
                ManagedCredentialFiles.deleteIfExists(temporary);
                if (!installed) {
                    ManagedCredentialFiles.deleteIfExists(destination);
                }
            } catch (IOException error) {
                cleanupFailure = error;
            }
            if (cleanupFailure != null) {
                if (failure != null) {
                    failure.addSuppressed(cleanupFailure);
                } else {
                    if (installed) {
                        SharedPreferences.Editor editor = preferences(context).edit()
                                .remove(PREF_USERNAME)
                                .remove(PREF_KEY_VERSION)
                                .remove(PREF_EXPIRES_AT)
                                .remove(PREF_PRIVATE_KEY_FILE)
                                .remove(PREF_PRIVATE_KEY_LENGTH)
                                .remove(PREF_PRIVATE_KEY_SHA256)
                                .remove("username")
                                .remove("private_key_pem");
                        AgentSessionStore.clearFrom(editor);
                        editor.commit();
                    }
                    throw cleanupFailure;
                }
            }
        }
    }

    static String username(Context context) throws IOException {
        String value = preferences(context).getString(PREF_USERNAME, "");
        if (value == null || value.trim().isEmpty()) {
            throw new IOException("请先登录 Agent");
        }
        return value.trim();
    }

    static String readPrivateKey(Context context) throws IOException {
        SharedPreferences preferences = preferences(context);
        String fileName = preferences.getString(PREF_PRIVATE_KEY_FILE, "");
        if (fileName == null || fileName.isEmpty()) {
            throw new IOException("请先登录 Agent");
        }
        long expectedLength = preferences.getLong(PREF_PRIVATE_KEY_LENGTH, -1);
        String expectedSha256 = preferences.getString(PREF_PRIVATE_KEY_SHA256, "");
        File directory = ManagedCredentialFiles.credentialsDirectory(context);
        ManagedCredentialFiles.requireOwnerOnlyPermissions(directory, true);
        File credential = ManagedCredentialFiles.checkedCredentialFile(directory, fileName);
        if (!ManagedCredentialFiles.credentialFileMatches(
                credential,
                expectedLength,
                expectedSha256)) {
            throw new IOException("Agent 托管私钥不存在或已损坏，请重新登录");
        }

        return new String(
                ManagedCredentialFiles.readBounded(credential),
                StandardCharsets.UTF_8);
    }

    static boolean matches(
            Context context,
            String username,
            long keyVersion,
            long expiresAt) {
        SharedPreferences preferences = preferences(context);
        String storedUsername = preferences.getString(PREF_USERNAME, "");
        String fileName = preferences.getString(PREF_PRIVATE_KEY_FILE, "");
        long expectedLength = preferences.getLong(PREF_PRIVATE_KEY_LENGTH, -1);
        String expectedSha256 = preferences.getString(PREF_PRIVATE_KEY_SHA256, "");
        if (!username.equals(storedUsername)
                || keyVersion != preferences.getLong(PREF_KEY_VERSION, -1)
                || expiresAt != preferences.getLong(PREF_EXPIRES_AT, -1)
                || fileName == null
                || fileName.isEmpty()) {
            return false;
        }
        try {
            File directory = ManagedCredentialFiles.credentialsDirectory(context);
            ManagedCredentialFiles.requireOwnerOnlyPermissions(directory, true);
            return ManagedCredentialFiles.credentialFileMatches(
                    ManagedCredentialFiles.checkedCredentialFile(directory, fileName),
                    expectedLength,
                    expectedSha256);
        } catch (IOException error) {
            return false;
        }
    }

    static Metadata loadMetadata(Context context) {
        SharedPreferences preferences = preferences(context);
        String username = preferences.getString(PREF_USERNAME, "");
        long keyVersion = preferences.getLong(PREF_KEY_VERSION, -1);
        long expiresAt = preferences.getLong(PREF_EXPIRES_AT, -1);
        if (!isRestorableMetadata(username, keyVersion, expiresAt)
                || !matches(context, username.trim(), keyVersion, expiresAt)) {
            return null;
        }
        return new Metadata(username.trim(), keyVersion, expiresAt);
    }

    static boolean isRestorableMetadata(String username, long keyVersion, long expiresAt) {
        // expiresAt is server-owned metadata. The pinned Proxy, rather than the
        // Android wall clock, decides when it becomes a terminal account state.
        return username != null && !username.trim().isEmpty() && keyVersion >= 0;
    }

    static boolean clear(Context context) {
        boolean cleared = true;
        File directory = ManagedCredentialFiles.credentialsDirectory(context);
        try {
            ManagedCredentialFiles.deleteManagedKeyFiles(directory, null);
        } catch (IOException | RuntimeException error) {
            cleared = false;
        }
        SharedPreferences.Editor editor = preferences(context).edit()
                .remove(PREF_USERNAME)
                .remove(PREF_KEY_VERSION)
                .remove(PREF_EXPIRES_AT)
                .remove(PREF_PRIVATE_KEY_FILE)
                .remove(PREF_PRIVATE_KEY_LENGTH)
                .remove(PREF_PRIVATE_KEY_SHA256)
                .remove(AgentAuthSession.PREF_SERVER_AUTHENTICATION_STATUS)
                .remove("username")
                .remove("private_key_pem");
        AgentSessionStore.clearFrom(editor);
        boolean metadataCleared = editor.commit();
        return cleared && metadataCleared;
    }

    static boolean clearLegacyInlineCredentials(Context context) {
        return preferences(context).edit()
                .remove("username")
                .remove("private_key_pem")
                .commit();
    }

    static String managedPrivateKeyFileName(String username, long keyVersion) {
        return ManagedCredentialFiles.managedPrivateKeyFileName(username, keyVersion);
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
    }

    static String sha256Hex(byte[] value) {
        return ManagedCredentialFiles.sha256Hex(value);
    }

    static final class Metadata {
        final String username;
        final long keyVersion;
        final long expiresAt;

        Metadata(String username, long keyVersion, long expiresAt) {
            this.username = username;
            this.keyVersion = keyVersion;
            this.expiresAt = expiresAt;
        }
    }

    static boolean credentialFileMatches(
            File credential,
            long expectedLength,
            String expectedSha256) throws IOException {
        return ManagedCredentialFiles.credentialFileMatches(
                credential,
                expectedLength,
                expectedSha256);
    }
}
