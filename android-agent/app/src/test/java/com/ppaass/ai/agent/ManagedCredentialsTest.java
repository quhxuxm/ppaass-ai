package com.ppaass.ai.agent;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;

public class ManagedCredentialsTest {
    @Rule
    public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void managedKeyFileNameEncodesUsernameWithoutPathCharacters() {
        String first = ManagedCredentials.managedPrivateKeyFileName("alice/测试", 42);
        String second = ManagedCredentials.managedPrivateKeyFileName("alice/测试", 42);

        assertTrue(first.matches("managed-[0-9a-f]{32}-v42-[0-9a-f]{16}\\.pem"));
        assertTrue(first.length() < 128);
        assertNotEquals(first, second);
        assertFalse(first.contains("/"));
        assertFalse(first.contains("\\"));
        assertFalse(first.contains(".."));
    }

    @Test
    public void managedKeyIntegrityRejectsContentChanges() throws Exception {
        byte[] original = "private-key-material".getBytes(StandardCharsets.UTF_8);
        File credential = temporaryFolder.newFile("managed-test.pem");
        Files.write(credential.toPath(), original);
        Files.setPosixFilePermissions(
                credential.toPath(),
                EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE));
        String digest = ManagedCredentials.sha256Hex(original);

        assertTrue(ManagedCredentials.credentialFileMatches(
                credential,
                original.length,
                digest));

        Files.write(
                credential.toPath(),
                "private-key-materiaL".getBytes(StandardCharsets.UTF_8));
        assertFalse(ManagedCredentials.credentialFileMatches(
                credential,
                original.length,
                digest));
    }

    @Test
    public void managedKeyIntegrityRejectsUnsafePermissions() throws Exception {
        byte[] content = "private-key-material".getBytes(StandardCharsets.UTF_8);
        File credential = temporaryFolder.newFile("managed-permissions.pem");
        Files.write(credential.toPath(), content);
        Files.setPosixFilePermissions(
                credential.toPath(),
                EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.GROUP_READ));

        assertThrows(
                IOException.class,
                () -> ManagedCredentials.credentialFileMatches(
                        credential,
                        content.length,
                        ManagedCredentials.sha256Hex(content)));
    }
}
