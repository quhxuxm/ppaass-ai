package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class AgentAuthDeviceFlowTest {
    @Test
    public void pendingPollNeverRunsFasterThanConfiguredInterval() {
        assertEquals(5, AgentAuthClient.devicePollDelaySeconds(5, 2, false));
        assertEquals(9, AgentAuthClient.devicePollDelaySeconds(5, 9, false));
    }

    @Test
    public void slowDownAddsFiveSecondsAndHonorsRetryAfter() {
        assertEquals(10, AgentAuthClient.devicePollDelaySeconds(5, 0, true));
        assertEquals(17, AgentAuthClient.devicePollDelaySeconds(10, 17, true));
    }

    @Test
    public void pollDelayIsBounded() {
        assertEquals(1, AgentAuthClient.devicePollDelaySeconds(0, 0, false));
        assertEquals(300, AgentAuthClient.devicePollDelaySeconds(299, 999, true));
    }

    @Test
    public void proxyWebRateLimitRetriesUsingRetryAfterOrCurrentInterval() {
        assertEquals(
                5,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        429,
                        "rate_limited",
                        5,
                        0));
        assertEquals(
                17,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        429,
                        "rate_limited",
                        5,
                        17));
    }

    @Test
    public void devicePollOnlyRetriesRecognizedRateLimitResponses() {
        assertEquals(
                10,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        429,
                        "slow_down",
                        5,
                        0));
        assertEquals(
                0,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        429,
                        "unexpected",
                        5,
                        17));
        assertEquals(
                0,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        500,
                        "rate_limited",
                        5,
                        17));
    }

    @Test
    public void proxyIdentityPinRequiresStrongRsaSubjectPublicKeyInfo() throws Exception {
        AgentAuthClient.validateProxyIdentityPublicKey(publicKeyPem(2048));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> AgentAuthClient.validateProxyIdentityPublicKey(publicKeyPem(1024)));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> AgentAuthClient.validateProxyIdentityPublicKey("not a public key"));
    }

    private static String publicKeyPem(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        String body = Base64.getMimeEncoder(
                        64,
                        "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(generator.generateKeyPair().getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n"
                + body
                + "\n-----END PUBLIC KEY-----\n";
    }
}
