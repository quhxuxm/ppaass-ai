package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AgentWebSessionHandoffClientTest {
    @Test
    public void postsBearerAndReturnsStrictSameOriginHandoffUrl() throws Exception {
        FakeTransport transport = new FakeTransport(response(
                "/api/v1/auth/agent-handoff?code=one-time-code",
                90));
        AgentWebSessionHandoffClient client = new AgentWebSessionHandoffClient(
                "https://proxy.example.com",
                transport);

        AgentWebSessionHandoffClient.Handoff handoff =
                client.create("agent_access_token");

        assertEquals("POST", transport.method);
        assertEquals(AgentWebSessionHandoffClient.CREATE_PATH, transport.path);
        assertNull(transport.body);
        assertEquals("agent_access_token", transport.bearerToken);
        assertEquals(
                AgentWebSessionHandoffClient.MAX_RESPONSE_BYTES,
                transport.maximumBytes);
        assertEquals(
                "https://proxy.example.com/api/v1/auth/agent-handoff?code=one-time-code",
                handoff.url);
        assertFalse(handoff.url.contains("agent_access_token"));
        assertEquals(90, handoff.expiresInSeconds);
    }

    @Test
    public void rejectsCrossOriginArbitraryAndFragmentHandoffUrls() {
        assertInvalid("https://attacker.example/account", 90);
        assertInvalid("//attacker.example/account", 90);
        assertInvalid("/account?code=one-time-code", 90);
        assertInvalid("/api/v1/auth/agent-handoff", 90);
        assertInvalid(
                "/api/v1/auth/agent-handoff?code=one-time-code#fragment",
                90);
    }

    @Test
    public void rejectsMissingOrLongLivedHandoffsAndInvalidBearer() {
        assertInvalid("/api/v1/auth/agent-handoff?code=one-time-code", 0);
        assertInvalid("/api/v1/auth/agent-handoff?code=one-time-code", 301);

        FakeTransport transport = new FakeTransport(response(
                "/api/v1/auth/agent-handoff?code=one-time-code",
                90));
        AgentWebSessionHandoffClient client = new AgentWebSessionHandoffClient(
                "https://proxy.example.com",
                transport);
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> client.create("invalid token"));
        assertNull(transport.method);
    }

    @Test
    public void cancellationReachesHttpTransportBoundary() {
        FakeTransport transport = new FakeTransport(response(
                "/api/v1/auth/agent-handoff?code=one-time-code",
                90));
        AgentWebSessionHandoffClient client = new AgentWebSessionHandoffClient(
                "https://proxy.example.com",
                transport);

        client.cancel();

        assertTrue(transport.cancelled);
    }

    private static void assertInvalid(String handoffPath, long expiresIn) {
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> AgentWebSessionHandoffClient.parseResponse(
                        "https://proxy.example.com",
                        response(handoffPath, expiresIn)));
    }

    private static AgentAuthDtos.WebSessionHandoffResponse response(
            String handoffPath,
            long expiresIn) {
        AgentAuthDtos.WebSessionHandoffResponse response =
                new AgentAuthDtos.WebSessionHandoffResponse();
        response.handoff_path = handoffPath;
        response.expires_in = expiresIn;
        return response;
    }

    private static final class FakeTransport
            implements AgentWebSessionHandoffClient.Transport {
        private final AgentAuthDtos.WebSessionHandoffResponse response;
        private String method;
        private String path;
        private Object body;
        private String bearerToken;
        private int maximumBytes;
        private boolean cancelled;

        FakeTransport(AgentAuthDtos.WebSessionHandoffResponse response) {
            this.response = response;
        }

        @Override
        public AgentAuthDtos.WebSessionHandoffResponse request(
                String method,
                String path,
                Object body,
                String bearerToken,
                int maximumBytes) {
            this.method = method;
            this.path = path;
            this.body = body;
            this.bearerToken = bearerToken;
            this.maximumBytes = maximumBytes;
            return response;
        }

        @Override
        public void cancel() {
            cancelled = true;
        }
    }
}
