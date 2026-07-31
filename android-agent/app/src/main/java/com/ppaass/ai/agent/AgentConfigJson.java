package com.ppaass.ai.agent;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

final class AgentConfigJson {
    private AgentConfigJson() {
    }

    static JSONObject build(Context context) throws JSONException {
        SharedPreferences prefs = context.getSharedPreferences("ppaass_agent", Context.MODE_PRIVATE);
        boolean canEditEgress = AgentAuthSession.hasPermission(
                context,
                AgentPermissions.EGRESS_EDIT);
        boolean canEditRuntime = AgentAuthSession.hasPermission(
                context,
                AgentPermissions.RUNTIME_THREADS_EDIT);
        List<String> proxyAddresses = ManagedProxyAddresses.load(context);
        if (proxyAddresses.isEmpty()) {
            throw new JSONException(
                    "Proxy Registry 未为当前账户分配可用的 Proxy 地址，请重新登录或联系管理员");
        }
        String quicPolicy = selectedQuicPolicy(prefs, canEditEgress);
        String transportMode = normalizeTransportMode(
                controlledString(
                        prefs,
                        "transport_mode",
                        DefaultConfig.TRANSPORT_MODE,
                        canEditEgress));
        int configuredTunMtu = parseInt(
                prefs.getString("mtu", String.valueOf(DefaultConfig.TUN_MTU)),
                DefaultConfig.TUN_MTU);
        int effectiveTunMtu = !"tcp".equals(transportMode)
                ? Math.min(configuredTunMtu, DefaultConfig.NATIVE_UDP_MAX_TUN_MTU)
                : configuredTunMtu;

        JSONObject tunJson = new JSONObject()
                .put("ipv4", prefs.getString("tun_ipv4", DefaultConfig.TUN_IPV4))
                .put("ipv6", prefs.getString("tun_ipv6", DefaultConfig.TUN_IPV6))
                .put("mtu", effectiveTunMtu)
                .put("proxy_dns", true)
                .put("quic_policy", quicPolicy);
        JSONObject yamuxJson = new JSONObject()
                .put("udp", buildUdpYamuxTransportJson(prefs, canEditEgress));
        JSONObject directAccessJson = new JSONObject()
                .put("mode", normalizeDirectAccessMode(
                        prefs.getString("direct_access_mode", DefaultConfig.DIRECT_ACCESS_MODE)))
                .put("rules", new JSONArray(tokens(
                        prefs.getString("direct_access_rules", DefaultConfig.DIRECT_ACCESS_RULES))));
        final String username;
        final String privateKeyPem;
        try {
            username = ManagedCredentials.username(context);
            privateKeyPem = ManagedCredentials.readPrivateKey(context);
        } catch (IOException error) {
            throw new JSONException(error.getMessage());
        }

        return new JSONObject()
                .put("proxy_addrs", new JSONArray(proxyAddresses))
                .put("username", username)
                .put("private_key_pem", privateKeyPem)
                .put("transport_mode", transportMode)
                .put("udp_session_pool_size", parseClampedInt(
                        controlledString(
                                prefs,
                                "udp_session_pool_size",
                                String.valueOf(DefaultConfig.UDP_SESSION_POOL_SIZE),
                                canEditEgress),
                        DefaultConfig.UDP_SESSION_POOL_SIZE,
                        DefaultConfig.MIN_UDP_SESSION_POOL_SIZE,
                        DefaultConfig.MAX_UDP_SESSION_POOL_SIZE))
                .put("async_runtime_stack_size_mb", DefaultConfig.ASYNC_RUNTIME_STACK_SIZE_MB)
                .put("runtime_threads", parsePositiveInt(
                        controlledString(
                                prefs,
                                "runtime_threads",
                                String.valueOf(DefaultConfig.RUNTIME_THREADS),
                                canEditRuntime),
                        DefaultConfig.RUNTIME_THREADS))
                .put("connect_timeout_secs", parsePositiveInt(
                        controlledString(
                                prefs,
                                "connect_timeout_secs",
                                String.valueOf(DefaultConfig.CONNECT_TIMEOUT_SECS),
                                canEditEgress),
                        DefaultConfig.CONNECT_TIMEOUT_SECS))
                .put("http_proxy_max_concurrent_connects", parsePositiveInt(
                        prefs.getString(
                                "http_proxy_max_concurrent_connects",
                                String.valueOf(DefaultConfig.HTTP_PROXY_MAX_CONCURRENT_CONNECTS)),
                        DefaultConfig.HTTP_PROXY_MAX_CONCURRENT_CONNECTS))
                .put("compression_mode", normalizeCompressionMode(
                        controlledString(
                                prefs,
                                "compression_mode",
                                DefaultConfig.COMPRESSION_MODE,
                                canEditEgress)))
                .put("yamux", yamuxJson)
                .put("direct_access", directAccessJson)
                .put("tun", tunJson);
    }

    static JSONObject buildHttpProxy(Context context) throws JSONException {
        SharedPreferences prefs = context.getSharedPreferences("ppaass_agent", Context.MODE_PRIVATE);
        return build(context)
                .put("runtime_threads", parsePositiveInt(
                        prefs.getString(
                                "http_proxy_threads",
                                String.valueOf(DefaultConfig.HTTP_PROXY_THREADS)),
                        DefaultConfig.HTTP_PROXY_THREADS));
    }

    private static JSONObject buildUdpYamuxTransportJson(
            SharedPreferences prefs,
            boolean canEditEgress) throws JSONException {
        String prefix = "yamux_udp_";
        int defaultSessions = DefaultConfig.UDP_YAMUX_SESSIONS;
        int defaultMaxStreams = DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION;
        int defaultOpenTimeout = DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS;
        int defaultKeepalive = DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS;
        int defaultWriteTimeout = DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS;
        int defaultWindowSize = DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB;

        return new JSONObject()
                .put("sessions", parsePositiveInt(
                        controlledString(
                                prefs,
                                prefix + "sessions",
                                String.valueOf(defaultSessions),
                                canEditEgress),
                        defaultSessions))
                .put("max_streams_per_session", parsePositiveInt(
                        controlledString(
                                prefs,
                                prefix + "max_streams_per_session",
                                String.valueOf(defaultMaxStreams),
                                canEditEgress),
                        defaultMaxStreams))
                .put("open_stream_timeout_secs", parsePositiveInt(
                        controlledString(
                                prefs,
                                prefix + "open_stream_timeout_secs",
                                String.valueOf(defaultOpenTimeout),
                                canEditEgress),
                        defaultOpenTimeout))
                .put("keepalive_interval_secs", parseNonNegativeInt(
                        controlledString(
                                prefs,
                                prefix + "keepalive_interval_secs",
                                String.valueOf(defaultKeepalive),
                                canEditEgress),
                        defaultKeepalive))
                .put("connection_write_timeout_secs", parsePositiveInt(
                        controlledString(
                                prefs,
                                prefix + "connection_write_timeout_secs",
                                String.valueOf(defaultWriteTimeout),
                                canEditEgress),
                        defaultWriteTimeout))
                .put("stream_window_size_kb", parseMinInt(
                        controlledString(
                                prefs,
                                prefix + "stream_window_size_kb",
                                String.valueOf(defaultWindowSize),
                                canEditEgress),
                        defaultWindowSize,
                        DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB));
    }

    private static String controlledString(
            SharedPreferences preferences,
            String key,
            String defaultValue,
            boolean allowed) {
        if (!allowed) {
            return defaultValue;
        }
        return preferences.getString(key, defaultValue);
    }

    private static int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static int parseNonNegativeInt(String value, int fallback) {
        return Math.max(0, parseInt(value, fallback));
    }

    private static int parsePositiveInt(String value, int fallback) {
        return Math.max(1, parseInt(value, fallback));
    }

    private static int parseMinInt(String value, int fallback, int min) {
        return Math.max(min, parseInt(value, fallback));
    }

    private static int parseClampedInt(String value, int fallback, int min, int max) {
        return Math.max(min, Math.min(max, parseInt(value, fallback)));
    }

    private static String normalizeCompressionMode(String value) {
        if (value == null) {
            return DefaultConfig.COMPRESSION_MODE;
        }
        String normalized = value.trim().toLowerCase();
        if ("none".equals(normalized)
                || "lz4".equals(normalized)
                || "gzip".equals(normalized)
                || "zstd".equals(normalized)) {
            return normalized;
        }
        return DefaultConfig.COMPRESSION_MODE;
    }

    private static String normalizeTransportMode(String value) throws JSONException {
        if (value == null) {
            return DefaultConfig.TRANSPORT_MODE;
        }
        String normalized = value.trim().toLowerCase();
        if ("auto".equals(normalized) || "udp".equals(normalized) || "tcp".equals(normalized)) {
            return normalized;
        }
        throw new JSONException(
                "transport_mode must be 'auto', 'udp', or 'tcp'; removed mode 'quic' is not supported");
    }

    private static String normalizeDirectAccessMode(String value) {
        if (value == null) {
            return DefaultConfig.DIRECT_ACCESS_MODE;
        }
        String normalized = value.trim().toLowerCase();
        if ("proxy_all".equals(normalized)
                || "direct_all".equals(normalized)
                || "rules".equals(normalized)) {
            return normalized;
        }
        return DefaultConfig.DIRECT_ACCESS_MODE;
    }

    private static String selectedQuicPolicy(
            SharedPreferences prefs,
            boolean canEditEgress) {
        return normalizeQuicPolicy(controlledString(
                prefs,
                "quic_policy",
                DefaultConfig.QUIC_POLICY,
                canEditEgress));
    }

    private static String normalizeQuicPolicy(String value) {
        if (value == null) {
            return DefaultConfig.QUIC_POLICY;
        }
        String normalized = value.trim().toLowerCase();
        if ("allow".equals(normalized) || "block".equals(normalized)) {
            return normalized;
        }
        return DefaultConfig.QUIC_POLICY;
    }

    private static List<String> tokens(String value) {
        List<String> result = new ArrayList<>();
        if (value == null) {
            return result;
        }
        for (String item : value.split("[,\\n]")) {
            String trimmed = item.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}
