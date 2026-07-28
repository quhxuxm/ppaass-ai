package com.ppaass.ai.agent;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.Set;
import java.security.SecureRandom;

final class ManagedCredentials {
    static final String PREFERENCES_NAME = "ppaass_agent";
    static final String PREF_USERNAME = "managed_username";
    static final String PREF_KEY_VERSION = "managed_key_version";
    static final String PREF_EXPIRES_AT = "managed_expires_at";
    static final String PREF_PRIVATE_KEY_FILE = "managed_private_key_file";
    static final String PREF_PRIVATE_KEY_LENGTH = "managed_private_key_length";
    static final String PREF_PRIVATE_KEY_SHA256 = "managed_private_key_sha256";
    static final String PREF_PROXY_IDENTITY_PUBLIC_KEY_PEM =
            "managed_proxy_identity_public_key_pem";

    private static final String CREDENTIALS_DIR = "credentials";
    private static final int MAX_PRIVATE_KEY_BYTES = 256 * 1024;
    private static final SecureRandom FILE_NAME_RANDOM = new SecureRandom();
    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS =
            EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> FILE_PERMISSIONS =
            EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);

    private ManagedCredentials() {
    }

    @SuppressLint("ApplySharedPref")
    static void install(
            Context context,
            String username,
            long keyVersion,
            long expiresAt,
            String privateKeyPem,
            String proxyIdentityPublicKeyPem) throws IOException {
        String normalizedUsername = username == null ? "" : username.trim();
        if (normalizedUsername.isEmpty() || keyVersion < 0) {
            throw new IOException("Proxy Web 返回的用户凭据无效");
        }
        if (expiresAt <= System.currentTimeMillis() / 1000L) {
            throw new IOException("Proxy Web 返回的用户凭据已经过期");
        }
        byte[] privateKeyBytes = privateKeyPem == null
                ? new byte[0]
                : privateKeyPem.getBytes(StandardCharsets.UTF_8);
        if (privateKeyBytes.length == 0 || privateKeyBytes.length > MAX_PRIVATE_KEY_BYTES) {
            throw new IOException("Proxy Web 返回的私钥大小无效");
        }
        try {
            AgentAuthClient.validateProxyIdentityPublicKey(proxyIdentityPublicKeyPem);
        } catch (AgentAuthClient.AuthException error) {
            throw new IOException(error.getMessage(), error);
        }
        String privateKeySha256 = sha256Hex(privateKeyBytes);

        File directory = credentialsDirectory(context);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("无法创建 Agent 私钥目录");
        }
        restrictToOwner(directory);
        deleteManagedKeyFiles(directory, null);

        File destination = newManagedCredentialFile(
                directory,
                normalizedUsername,
                keyVersion);
        String fileName = destination.getName();
        File temporary = File.createTempFile(".managed-private-key-", ".tmp", directory);
        restrictToOwner(temporary);
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
            restrictToOwner(destination);
            if (!credentialFileMatches(
                    destination,
                    privateKeyBytes.length,
                    privateKeySha256)) {
                throw new IOException("Agent 托管私钥写入校验失败");
            }

            SharedPreferences preferences = preferences(context);
            installed = preferences.edit()
                    .putString(PREF_USERNAME, normalizedUsername)
                    .putLong(PREF_KEY_VERSION, keyVersion)
                    .putLong(PREF_EXPIRES_AT, expiresAt)
                    .putString(PREF_PRIVATE_KEY_FILE, fileName)
                    .putLong(PREF_PRIVATE_KEY_LENGTH, privateKeyBytes.length)
                    .putString(PREF_PRIVATE_KEY_SHA256, privateKeySha256)
                    .putString(
                            PREF_PROXY_IDENTITY_PUBLIC_KEY_PEM,
                            proxyIdentityPublicKeyPem)
                    .remove("username")
                    .remove("private_key_pem")
                    .commit();
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
                deleteIfExists(temporary);
                if (!installed) {
                    deleteIfExists(destination);
                }
            } catch (IOException error) {
                cleanupFailure = error;
            }
            if (cleanupFailure != null) {
                if (failure != null) {
                    failure.addSuppressed(cleanupFailure);
                } else {
                    if (installed) {
                        preferences(context).edit()
                                .remove(PREF_USERNAME)
                                .remove(PREF_KEY_VERSION)
                                .remove(PREF_EXPIRES_AT)
                                .remove(PREF_PRIVATE_KEY_FILE)
                                .remove(PREF_PRIVATE_KEY_LENGTH)
                                .remove(PREF_PRIVATE_KEY_SHA256)
                                .remove(PREF_PROXY_IDENTITY_PUBLIC_KEY_PEM)
                                .commit();
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
        long expiresAt = preferences.getLong(PREF_EXPIRES_AT, -1);
        if (expiresAt <= System.currentTimeMillis() / 1000L) {
            throw new IOException("Agent 托管私钥已经过期，请重新登录");
        }
        long expectedLength = preferences.getLong(PREF_PRIVATE_KEY_LENGTH, -1);
        String expectedSha256 = preferences.getString(PREF_PRIVATE_KEY_SHA256, "");
        File directory = credentialsDirectory(context);
        requireOwnerOnlyPermissions(directory, true);
        File credential = checkedCredentialFile(directory, fileName);
        if (!credentialFileMatches(credential, expectedLength, expectedSha256)) {
            throw new IOException("Agent 托管私钥不存在或已损坏，请重新登录");
        }

        return new String(readBounded(credential), StandardCharsets.UTF_8);
    }

    static String readProxyIdentityPublicKey(Context context) throws IOException {
        String publicKeyPem = preferences(context)
                .getString(PREF_PROXY_IDENTITY_PUBLIC_KEY_PEM, "");
        try {
            AgentAuthClient.validateProxyIdentityPublicKey(publicKeyPem);
        } catch (AgentAuthClient.AuthException error) {
            throw new IOException("Agent 托管的 Proxy 身份公钥不存在或已损坏，请重新登录", error);
        }
        return publicKeyPem;
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
        String proxyIdentityPublicKeyPem =
                preferences.getString(PREF_PROXY_IDENTITY_PUBLIC_KEY_PEM, "");
        if (!username.equals(storedUsername)
                || keyVersion != preferences.getLong(PREF_KEY_VERSION, -1)
                || expiresAt != preferences.getLong(PREF_EXPIRES_AT, -1)
                || fileName == null
                || fileName.isEmpty()
                || proxyIdentityPublicKeyPem == null
                || proxyIdentityPublicKeyPem.isEmpty()) {
            return false;
        }
        try {
            AgentAuthClient.validateProxyIdentityPublicKey(proxyIdentityPublicKeyPem);
            File directory = credentialsDirectory(context);
            requireOwnerOnlyPermissions(directory, true);
            return credentialFileMatches(
                    checkedCredentialFile(directory, fileName),
                    expectedLength,
                    expectedSha256);
        } catch (IOException | AgentAuthClient.AuthException error) {
            return false;
        }
    }

    static boolean clear(Context context) {
        boolean cleared = true;
        File directory = credentialsDirectory(context);
        try {
            deleteManagedKeyFiles(directory, null);
        } catch (IOException | RuntimeException error) {
            cleared = false;
        }
        boolean metadataCleared = preferences(context).edit()
                .remove(PREF_USERNAME)
                .remove(PREF_KEY_VERSION)
                .remove(PREF_EXPIRES_AT)
                .remove(PREF_PRIVATE_KEY_FILE)
                .remove(PREF_PRIVATE_KEY_LENGTH)
                .remove(PREF_PRIVATE_KEY_SHA256)
                .remove(PREF_PROXY_IDENTITY_PUBLIC_KEY_PEM)
                .remove("username")
                .remove("private_key_pem")
                .commit();
        return cleared && metadataCleared;
    }

    static boolean clearLegacyInlineCredentials(Context context) {
        return preferences(context).edit()
                .remove("username")
                .remove("private_key_pem")
                .commit();
    }

    static String managedPrivateKeyFileName(String username, long keyVersion) {
        byte[] usernameHash = sha256(username.getBytes(StandardCharsets.UTF_8));
        byte[] nonce = new byte[8];
        FILE_NAME_RANDOM.nextBytes(nonce);
        return "managed-"
                + toHex(usernameHash, 16)
                + "-v"
                + keyVersion
                + "-"
                + toHex(nonce, nonce.length)
                + ".pem";
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
    }

    private static File credentialsDirectory(Context context) {
        return new File(context.getNoBackupFilesDir(), CREDENTIALS_DIR);
    }

    private static File checkedCredentialFile(File directory, String fileName) throws IOException {
        if (fileName.contains("/") || fileName.contains("\\") || fileName.contains("..")) {
            throw new IOException("Agent 托管私钥路径无效");
        }
        File canonicalDirectory = directory.getCanonicalFile();
        File candidate = new File(canonicalDirectory, fileName).getCanonicalFile();
        if (!canonicalDirectory.equals(candidate.getParentFile())) {
            throw new IOException("Agent 托管私钥路径越界");
        }
        return candidate;
    }

    private static File newManagedCredentialFile(
            File directory,
            String username,
            long keyVersion) throws IOException {
        for (int attempt = 0; attempt < 8; attempt++) {
            File candidate = checkedCredentialFile(
                    directory,
                    managedPrivateKeyFileName(username, keyVersion));
            if (!candidate.exists()) {
                return candidate;
            }
        }
        throw new IOException("无法分配新的 Agent 私钥文件");
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("Android runtime does not provide SHA-256", error);
        }
    }

    static String sha256Hex(byte[] value) {
        byte[] digest = sha256(value);
        return toHex(digest, digest.length);
    }

    private static String toHex(byte[] value, int length) {
        char[] alphabet = "0123456789abcdef".toCharArray();
        StringBuilder encoded = new StringBuilder(length * 2);
        for (int index = 0; index < length; index++) {
            int octet = value[index] & 0xff;
            encoded.append(alphabet[octet >>> 4]);
            encoded.append(alphabet[octet & 0x0f]);
        }
        return encoded.toString();
    }

    private static void restrictToOwner(File file) throws IOException {
        Set<PosixFilePermission> expected =
                file.isDirectory() ? DIRECTORY_PERMISSIONS : FILE_PERMISSIONS;
        try {
            Files.setPosixFilePermissions(file.toPath(), expected);
        } catch (RuntimeException error) {
            throw new IOException("无法限制 Agent 私钥文件权限", error);
        }
        requireOwnerOnlyPermissions(file, file.isDirectory());
    }

    private static void requireOwnerOnlyPermissions(File file, boolean directory)
            throws IOException {
        if (!file.exists()) {
            throw new IOException("Agent 私钥路径不存在");
        }
        Set<PosixFilePermission> expected =
                directory ? DIRECTORY_PERMISSIONS : FILE_PERMISSIONS;
        final Set<PosixFilePermission> actual;
        try {
            actual = Files.getPosixFilePermissions(file.toPath());
        } catch (RuntimeException error) {
            throw new IOException("无法校验 Agent 私钥文件权限", error);
        }
        if (!actual.equals(expected)) {
            throw new IOException("Agent 私钥文件权限不安全");
        }
    }

    static boolean credentialFileMatches(
            File credential,
            long expectedLength,
            String expectedSha256) throws IOException {
        if (!credential.isFile()
                || expectedLength <= 0
                || expectedLength > MAX_PRIVATE_KEY_BYTES
                || credential.length() != expectedLength
                || expectedSha256 == null
                || !expectedSha256.matches("[0-9a-f]{64}")) {
            return false;
        }
        requireOwnerOnlyPermissions(credential, false);
        byte[] actualDigest = sha256(readBounded(credential));
        byte[] expectedDigest = decodeHex(expectedSha256);
        return MessageDigest.isEqual(expectedDigest, actualDigest);
    }

    private static byte[] readBounded(File credential) throws IOException {
        try (FileInputStream input = new FileInputStream(credential);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > MAX_PRIVATE_KEY_BYTES) {
                    throw new IOException("Agent 托管私钥过大");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static byte[] decodeHex(String value) throws IOException {
        if (value == null || value.length() != 64) {
            throw new IOException("Agent 私钥摘要无效");
        }
        byte[] decoded = new byte[value.length() / 2];
        for (int index = 0; index < decoded.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IOException("Agent 私钥摘要无效");
            }
            decoded[index] = (byte) ((high << 4) | low);
        }
        return decoded;
    }

    private static void deleteManagedKeyFiles(File directory, String preservedFileName)
            throws IOException {
        if (!directory.exists()) {
            return;
        }
        if (!directory.isDirectory()) {
            throw new IOException("Agent 私钥目录无效");
        }
        File[] files = directory.listFiles();
        if (files == null) {
            throw new IOException("无法读取 Agent 私钥目录");
        }
        for (File file : files) {
            boolean managed = file.getName().startsWith("managed-")
                    || file.getName().startsWith(".managed-private-key-");
            if (managed && !file.getName().equals(preservedFileName)) {
                deleteIfExists(file);
            }
        }
    }

    private static void deleteIfExists(File file) throws IOException {
        try {
            Files.deleteIfExists(file.toPath());
            if (file.exists()) {
                throw new IOException("无法删除 Agent 托管私钥");
            }
        } catch (RuntimeException error) {
            throw new IOException("无法删除 Agent 托管私钥", error);
        }
    }
}
