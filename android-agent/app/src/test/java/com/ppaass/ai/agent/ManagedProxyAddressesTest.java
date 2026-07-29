package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

public final class ManagedProxyAddressesTest {
    @Test
    public void validManagedAddressesPreserveServerOrder() throws Exception {
        List<String> addresses = ManagedProxyAddresses.require(List.of(
                "proxy-a.example:80",
                "[2001:db8::1]:443"));

        assertEquals(
                List.of("proxy-a.example:80", "[2001:db8::1]:443"),
                addresses);
        assertEquals(
                "proxy-a.example:80\n[2001:db8::1]:443",
                ManagedProxyAddresses.serialize(addresses));
    }

    @Test
    public void missingDuplicateOrMalformedAddressesFailClosed() {
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(null));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of()));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of(
                        "proxy.example:80",
                        "PROXY.EXAMPLE:80")));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of(
                        "proxy.example:80\ninjected.example:443")));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of(
                        "https://proxy.example:443")));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of(
                        "invalid_host.example:443")));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of(
                        "-invalid.example:443")));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of(
                        "invalid-.example:443")));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of(
                        "invalid..example:443")));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> ManagedProxyAddresses.require(List.of(
                        "a".repeat(64) + ".example:443")));
    }

    @Test
    public void proxyAssignmentApiErrorHasSpecificMessage() {
        byte[] response = ("{\"error\":{"
                + "\"code\":\"proxy_address_not_assigned\","
                + "\"message\":\"ignored\"}}")
                .getBytes(StandardCharsets.UTF_8);

        assertEquals(
                "管理员尚未为当前账户分配 Proxy 地址",
                AgentAuthErrors.apiError(409, response).getMessage());
    }

    @Test
    public void onlyAddressContractFailuresRequireNetworkShutdown() {
        assertEquals(
                AgentAuthClient.SyncFailure.PROXY_ADDRESS_REQUIRED,
                AgentSyncFailurePolicy.forResponse(
                        409,
                        "proxy_address_not_assigned"));
        assertEquals(
                AgentAuthClient.SyncFailure.SERVICE_REJECTED,
                AgentSyncFailurePolicy.forResponse(409, "other_conflict"));
        assertEquals(
                AgentAuthClient.SyncFailure.SERVICE_REJECTED,
                AgentSyncFailurePolicy.forResponse(429, "rate_limited"));
        assertEquals(
                AgentAuthClient.SyncFailure.TRANSIENT,
                AgentSyncFailurePolicy.forResponse(503, ""));
        assertTrue(AgentSyncFailurePolicy.requiresManagedProxyShutdown(
                AgentAuthClient.SyncFailure.INVALID_RESPONSE));
        assertTrue(AgentSyncFailurePolicy.requiresManagedProxyShutdown(
                AgentAuthClient.SyncFailure.PROXY_ADDRESS_REQUIRED));
        assertFalse(AgentSyncFailurePolicy.requiresManagedProxyShutdown(
                AgentAuthClient.SyncFailure.TRANSIENT));
        assertFalse(AgentSyncFailurePolicy.requiresManagedProxyShutdown(
                AgentAuthClient.SyncFailure.SERVICE_REJECTED));
    }
}
