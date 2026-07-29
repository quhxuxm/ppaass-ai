package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AgentPermissionConfigPolicyTest {
    private static final Map<String, String> EGRESS_DEFAULTS = Map.ofEntries(
            Map.entry("transport_mode", DefaultConfig.TRANSPORT_MODE),
            Map.entry(
                    "udp_session_pool_size",
                    String.valueOf(DefaultConfig.UDP_SESSION_POOL_SIZE)),
            Map.entry(
                    "connect_timeout_secs",
                    String.valueOf(DefaultConfig.CONNECT_TIMEOUT_SECS)),
            Map.entry("quic_policy", DefaultConfig.QUIC_POLICY),
            Map.entry("compression_mode", DefaultConfig.COMPRESSION_MODE),
            Map.entry(
                    "yamux_udp_sessions",
                    String.valueOf(DefaultConfig.UDP_YAMUX_SESSIONS)),
            Map.entry(
                    "yamux_udp_max_streams_per_session",
                    String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION)),
            Map.entry(
                    "yamux_udp_open_stream_timeout_secs",
                    String.valueOf(DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
            Map.entry(
                    "yamux_udp_keepalive_interval_secs",
                    String.valueOf(DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
            Map.entry(
                    "yamux_udp_connection_write_timeout_secs",
                    String.valueOf(DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
            Map.entry(
                    "yamux_udp_stream_window_size_kb",
                    String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB)));

    @Test
    public void deniedEgressForcesEveryEgressFieldToBuiltInDefault() {
        Map<String, String> defaults =
                AgentPermissionConfigPolicy.requiredDefaults(false, true);

        assertEquals(EGRESS_DEFAULTS, defaults);
    }

    @Test
    public void deniedRuntimeForcesOnlyRuntimePanelFieldToDefault() {
        Map<String, String> defaults =
                AgentPermissionConfigPolicy.requiredDefaults(true, false);

        assertEquals(Set.of("runtime_threads"), defaults.keySet());
        assertEquals(
                String.valueOf(DefaultConfig.RUNTIME_THREADS),
                defaults.get("runtime_threads"));
    }

    @Test
    public void grantedPermissionsDoNotOverwriteStoredConfiguration() {
        assertTrue(AgentPermissionConfigPolicy.requiredDefaults(true, true).isEmpty());
        assertEquals(
                "proxy_addrs",
                AgentPermissionConfigPolicy.LEGACY_PROXY_ADDRESS_KEY);
    }

    @Test
    public void egressAndRuntimeDefaultsStayIndependent() {
        Map<String, String> egressOnly =
                AgentPermissionConfigPolicy.requiredDefaults(false, true);
        Map<String, String> runtimeOnly =
                AgentPermissionConfigPolicy.requiredDefaults(true, false);

        assertFalse(egressOnly.containsKey("runtime_threads"));
        assertFalse(runtimeOnly.keySet().stream().anyMatch(EGRESS_DEFAULTS::containsKey));
    }

    @Test
    public void managedProxyAddressChangeReloadsEvenWithoutDefaultChanges() {
        assertTrue(AgentPermissionConfigPolicy.runningAgentsRequireReload(
                List.of("old.example:80"),
                List.of("new.example:80"),
                false));
        assertFalse(AgentPermissionConfigPolicy.runningAgentsRequireReload(
                List.of("same.example:80"),
                List.of("same.example:80"),
                false));
        assertTrue(AgentPermissionConfigPolicy.runningAgentsRequireReload(
                List.of("same.example:80"),
                List.of("same.example:80"),
                true));
    }

    @Test
    public void restoredAssignmentStateSeparatesLegacyMissingAndAssigned() {
        assertEquals(
                AgentPermissionConfigPolicy.RestoredProxyAction.STOP_LEGACY,
                AgentPermissionConfigPolicy.restoredProxyAction(
                        "",
                        List.of()));
        assertEquals(
                AgentPermissionConfigPolicy.RestoredProxyAction.STOP_MISSING,
                AgentPermissionConfigPolicy.restoredProxyAction(
                        AgentSessionStore.PROXY_ASSIGNMENT_MISSING,
                        List.of()));
        assertEquals(
                AgentPermissionConfigPolicy.RestoredProxyAction.STOP_MISSING,
                AgentPermissionConfigPolicy.restoredProxyAction(
                        AgentSessionStore.PROXY_ASSIGNMENT_ASSIGNED,
                        List.of()));
        assertEquals(
                AgentPermissionConfigPolicy.RestoredProxyAction.KEEP_RUNNING,
                AgentPermissionConfigPolicy.restoredProxyAction(
                        AgentSessionStore.PROXY_ASSIGNMENT_ASSIGNED,
                        List.of("managed.example:80")));
    }
}
