package com.ppaass.ai.agent;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

final class AgentConfigJson {
    private AgentConfigJson() {
    }

    static JSONObject build(Context context) throws JSONException {
        SharedPreferences prefs = context.getSharedPreferences("ppaass_agent", Context.MODE_PRIVATE);
        String quicPolicy = selectedQuicPolicy(prefs);
        String transportMode = normalizeTransportMode(
                prefs.getString("transport_mode", DefaultConfig.TRANSPORT_MODE));
        int configuredTunMtu = parseInt(
                prefs.getString("mtu", String.valueOf(DefaultConfig.TUN_MTU)),
                DefaultConfig.TUN_MTU);
        int effectiveTunMtu = "udp".equals(transportMode)
                ? Math.min(configuredTunMtu, DefaultConfig.NATIVE_UDP_MAX_TUN_MTU)
                : configuredTunMtu;

        JSONObject tunJson = new JSONObject()
                .put("ipv4", prefs.getString("tun_ipv4", DefaultConfig.TUN_IPV4))
                .put("ipv6", prefs.getString("tun_ipv6", DefaultConfig.TUN_IPV6))
                .put("mtu", effectiveTunMtu)
                .put("proxy_dns", true)
                .put("quic_policy", quicPolicy);
        JSONObject yamuxJson = new JSONObject()
                .put("udp", buildUdpYamuxTransportJson(prefs));
        JSONObject directAccessJson = new JSONObject()
                .put("mode", normalizeDirectAccessMode(
                        prefs.getString("direct_access_mode", DefaultConfig.DIRECT_ACCESS_MODE)))
                .put("rules", new JSONArray(tokens(
                        prefs.getString("direct_access_rules", DefaultConfig.DIRECT_ACCESS_RULES))));

        return new JSONObject()
                .put("proxy_addrs", new JSONArray(tokens(prefs.getString("proxy_addrs", DefaultConfig.PROXY_ADDR))))
                .put("username", prefs.getString("username", DefaultConfig.USERNAME))
                .put("private_key_pem", DefaultConfig.normalizePrivateKeyPem(
                        prefs.getString("private_key_pem", DefaultConfig.PRIVATE_KEY_PEM)))
                .put("transport_mode", transportMode)
                .put("udp_session_pool_size", parseClampedInt(
                        prefs.getString(
                                "udp_session_pool_size",
                                String.valueOf(DefaultConfig.UDP_SESSION_POOL_SIZE)),
                        DefaultConfig.UDP_SESSION_POOL_SIZE,
                        DefaultConfig.MIN_UDP_SESSION_POOL_SIZE,
                        DefaultConfig.MAX_UDP_SESSION_POOL_SIZE))
                .put("async_runtime_stack_size_mb", DefaultConfig.ASYNC_RUNTIME_STACK_SIZE_MB)
                .put("runtime_threads", parsePositiveInt(
                        prefs.getString("runtime_threads", String.valueOf(DefaultConfig.RUNTIME_THREADS)),
                        DefaultConfig.RUNTIME_THREADS))
                .put("connect_timeout_secs", parsePositiveInt(
                        prefs.getString(
                                "connect_timeout_secs",
                                String.valueOf(DefaultConfig.CONNECT_TIMEOUT_SECS)),
                        DefaultConfig.CONNECT_TIMEOUT_SECS))
                .put("http_proxy_max_concurrent_connects", parsePositiveInt(
                        prefs.getString(
                                "http_proxy_max_concurrent_connects",
                                String.valueOf(DefaultConfig.HTTP_PROXY_MAX_CONCURRENT_CONNECTS)),
                        DefaultConfig.HTTP_PROXY_MAX_CONCURRENT_CONNECTS))
                .put("compression_mode", normalizeCompressionMode(
                        prefs.getString("compression_mode", DefaultConfig.COMPRESSION_MODE)))
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

    private static JSONObject buildUdpYamuxTransportJson(SharedPreferences prefs) throws JSONException {
        String prefix = "yamux_udp_";
        int defaultSessions = DefaultConfig.UDP_YAMUX_SESSIONS;
        int defaultMaxStreams = DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION;
        int defaultOpenTimeout = DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS;
        int defaultKeepalive = DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS;
        int defaultWriteTimeout = DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS;
        int defaultWindowSize = DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB;

        return new JSONObject()
                .put("sessions", parsePositiveInt(
                        prefs.getString(prefix + "sessions", String.valueOf(defaultSessions)),
                        defaultSessions))
                .put("max_streams_per_session", parsePositiveInt(
                        prefs.getString(
                                prefix + "max_streams_per_session",
                                String.valueOf(defaultMaxStreams)),
                        defaultMaxStreams))
                .put("open_stream_timeout_secs", parsePositiveInt(
                        prefs.getString(
                                prefix + "open_stream_timeout_secs",
                                String.valueOf(defaultOpenTimeout)),
                        defaultOpenTimeout))
                .put("keepalive_interval_secs", parseNonNegativeInt(
                        prefs.getString(
                                prefix + "keepalive_interval_secs",
                                String.valueOf(defaultKeepalive)),
                        defaultKeepalive))
                .put("connection_write_timeout_secs", parsePositiveInt(
                        prefs.getString(
                                prefix + "connection_write_timeout_secs",
                                String.valueOf(defaultWriteTimeout)),
                        defaultWriteTimeout))
                .put("stream_window_size_kb", parseMinInt(
                        prefs.getString(
                                prefix + "stream_window_size_kb",
                                String.valueOf(defaultWindowSize)),
                        defaultWindowSize,
                        DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB));
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
        if ("udp".equals(normalized) || "tcp".equals(normalized)) {
            return normalized;
        }
        throw new JSONException(
                "transport_mode must be 'udp' or 'tcp'; removed mode 'quic' is not supported");
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

    private static String selectedQuicPolicy(SharedPreferences prefs) {
        String stored = prefs.getString("quic_policy", null);
        if (stored != null) {
            return normalizeQuicPolicy(stored);
        }
        return DefaultConfig.QUIC_POLICY;
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
