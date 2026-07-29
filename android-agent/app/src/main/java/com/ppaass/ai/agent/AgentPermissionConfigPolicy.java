package com.ppaass.ai.agent;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class AgentPermissionConfigPolicy {
    static final String PREFS_NAME = "ppaass_agent";
    static final String LEGACY_PROXY_ADDRESS_KEY = "proxy_addrs";

    enum RestoredProxyAction {
        KEEP_RUNNING,
        STOP_MISSING,
        STOP_LEGACY
    }

    private AgentPermissionConfigPolicy() {
    }

    static Map<String, String> requiredDefaults(
            boolean canEditEgress,
            boolean canEditRuntime) {
        LinkedHashMap<String, String> defaults = new LinkedHashMap<>();
        if (!canEditEgress) {
            defaults.put("transport_mode", DefaultConfig.TRANSPORT_MODE);
            defaults.put(
                    "udp_session_pool_size",
                    String.valueOf(DefaultConfig.UDP_SESSION_POOL_SIZE));
            defaults.put(
                    "connect_timeout_secs",
                    String.valueOf(DefaultConfig.CONNECT_TIMEOUT_SECS));
            defaults.put("quic_policy", DefaultConfig.QUIC_POLICY);
            defaults.put("compression_mode", DefaultConfig.COMPRESSION_MODE);
            defaults.put(
                    "yamux_udp_sessions",
                    String.valueOf(DefaultConfig.UDP_YAMUX_SESSIONS));
            defaults.put(
                    "yamux_udp_max_streams_per_session",
                    String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION));
            defaults.put(
                    "yamux_udp_open_stream_timeout_secs",
                    String.valueOf(DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS));
            defaults.put(
                    "yamux_udp_keepalive_interval_secs",
                    String.valueOf(DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS));
            defaults.put(
                    "yamux_udp_connection_write_timeout_secs",
                    String.valueOf(DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS));
            defaults.put(
                    "yamux_udp_stream_window_size_kb",
                    String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB));
        }
        if (!canEditRuntime) {
            defaults.put(
                    "runtime_threads",
                    String.valueOf(DefaultConfig.RUNTIME_THREADS));
        }
        return Collections.unmodifiableMap(defaults);
    }

    static boolean runningAgentsRequireReload(
            List<String> previousProxyAddresses,
            List<String> synchronizedProxyAddresses,
            boolean configDefaultsChanged) {
        return configDefaultsChanged
                || !previousProxyAddresses.equals(synchronizedProxyAddresses);
    }

    static RestoredProxyAction restoredProxyAction(
            String assignmentState,
            List<String> managedProxyAddresses) {
        boolean hasAddresses =
                managedProxyAddresses != null && !managedProxyAddresses.isEmpty();
        if (AgentSessionStore.PROXY_ASSIGNMENT_ASSIGNED.equals(assignmentState)) {
            return hasAddresses
                    ? RestoredProxyAction.KEEP_RUNNING
                    : RestoredProxyAction.STOP_MISSING;
        }
        if (AgentSessionStore.PROXY_ASSIGNMENT_MISSING.equals(assignmentState)) {
            return RestoredProxyAction.STOP_MISSING;
        }
        return RestoredProxyAction.STOP_LEGACY;
    }
}
