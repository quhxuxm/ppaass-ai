package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

public class AgentAuthConfigTest {
    @Test
    public void remoteAuthenticationRequiresHttpsAndRootUrl() {
        assertEquals(
                "https://140.82.30.214",
                AgentAuthConfig.normalizeProxyWebUrl("https://140.82.30.214/"));
        assertEquals(
                "http://127.0.0.1:8787",
                AgentAuthConfig.normalizeProxyWebUrl("http://127.0.0.1:8787"));
        assertEquals(
                "http://127.0.0.2:8787",
                AgentAuthConfig.normalizeProxyWebUrl("http://127.0.0.2:8787"));

        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyWebUrl("http://proxy.example.com"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyWebUrl(
                        "http://127.attacker.example"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyWebUrl(
                        "http://127.0.0.1.example"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyWebUrl("https://proxy.example.com/login"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyWebUrl(
                        "https://user:password@proxy.example.com"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentAuthConfig.normalizeProxyWebUrl(
                        "https://proxy.example.com/?mode=register"));
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
