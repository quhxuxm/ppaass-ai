package com.ppaass.ai.agent;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Set;

final class ManagedCredentialFiles {
    static final int MAX_PRIVATE_KEY_BYTES = 256 * 1024;
    private static final String CREDENTIALS_DIR = "credentials";
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

    private ManagedCredentialFiles() {
    }

    static File credentialsDirectory(Context context) {
        return new File(context.getNoBackupFilesDir(), CREDENTIALS_DIR);
    }

    static File checkedCredentialFile(File directory, String fileName) throws IOException {
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

    static File newManagedCredentialFile(
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

    static String sha256Hex(byte[] value) {
        byte[] digest = sha256(value);
        return toHex(digest, digest.length);
    }

    static void restrictToOwner(File file) throws IOException {
        Set<PosixFilePermission> expected =
                file.isDirectory() ? DIRECTORY_PERMISSIONS : FILE_PERMISSIONS;
        try {
            Files.setPosixFilePermissions(file.toPath(), expected);
        } catch (RuntimeException error) {
            throw new IOException("无法限制 Agent 私钥文件权限", error);
        }
        requireOwnerOnlyPermissions(file, file.isDirectory());
    }

    static void requireOwnerOnlyPermissions(File file, boolean directory)
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

    static byte[] readBounded(File credential) throws IOException {
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

    static void deleteManagedKeyFiles(File directory, String preservedFileName)
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

    static void deleteIfExists(File file) throws IOException {
        try {
            Files.deleteIfExists(file.toPath());
            if (file.exists()) {
                throw new IOException("无法删除 Agent 托管私钥");
            }
        } catch (RuntimeException error) {
            throw new IOException("无法删除 Agent 托管私钥", error);
        }
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(
                    "Android runtime does not provide SHA-256",
                    error);
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
}
