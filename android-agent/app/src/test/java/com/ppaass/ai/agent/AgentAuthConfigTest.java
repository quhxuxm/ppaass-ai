package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AgentAuthConfigTest {
    @Test
    public void remoteAuthenticationAllowsHttpOrHttpsAtRootUrl() {
        assertEquals(
                "https://140.82.30.214",
                AgentAuthConfig.normalizeProxyRegistryUrl("https://140.82.30.214/"));
        assertEquals(
                "http://proxy.example.com",
                AgentAuthConfig.normalizeProxyRegistryUrl("HTTP://Proxy.Example.Com/"));
        assertEquals(
                "http://140.82.30.214:8787",
                AgentAuthConfig.normalizeProxyRegistryUrl("http://140.82.30.214:8787"));
        assertEquals(
                "http://127.0.0.1:8787",
                AgentAuthConfig.normalizeProxyRegistryUrl("http://127.0.0.1:8787"));
        assertEquals(
                "http://127.0.0.2:8787",
                AgentAuthConfig.normalizeProxyRegistryUrl("http://127.0.0.2:8787"));

        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyRegistryUrl("ftp://proxy.example.com"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyRegistryUrl("https://proxy.example.com/login"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyRegistryUrl(
                        "https://user:password@proxy.example.com"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyRegistryUrl(
                        "https://proxy.example.com/?mode=register"));
    }

    @Test
    public void loopbackDetectionDoesNotTrustDnsSuffixes() {
        assertTrue(AgentAuthConfig.isLoopbackHost("localhost"));
        assertTrue(AgentAuthConfig.isLoopbackHost("127.0.0.2"));
        assertTrue(AgentAuthConfig.isLoopbackHost("::1"));
        assertFalse(AgentAuthConfig.isLoopbackHost("127.attacker.example"));
        assertFalse(AgentAuthConfig.isLoopbackHost("127.0.0.1.example"));
        assertFalse(AgentAuthConfig.isLoopbackHost("127.0.0.999"));
    }

    @Test
    public void serviceRelativeUrlsCannotEscapeConfiguredService() {
        assertEquals(
                "https://proxy.example.com/api/agent/auth/device/authorize?code=ABCD-EFGH-JKLM",
                AgentAuthConfig.resolveServiceRelativeUrl(
                        "https://proxy.example.com/",
                        "/api/agent/auth/device/authorize?code=ABCD-EFGH-JKLM"));
        assertEquals(
                "http://127.0.0.1:8787/?mode=register",
                AgentAuthConfig.resolveServiceRelativeUrl(
                        "http://127.0.0.1:8787",
                        "/?mode=register"));

        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.resolveServiceRelativeUrl(
                        "https://proxy.example.com",
                        "https://attacker.example/api/agent/auth/device/authorize"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.resolveServiceRelativeUrl(
                        "https://proxy.example.com",
                        "//attacker.example/api/agent/auth/device/authorize"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.resolveServiceRelativeUrl(
                        "https://proxy.example.com",
                        "relative/api/agent/auth/device/authorize"));
    }
}
