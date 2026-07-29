package com.ppaass.ai.agent;

final class DefaultConfig {
    static final String TUN_IPV4 = "10.10.10.2/24";
    static final String TUN_IPV6 = "";
    static final int TUN_MTU = 1500;
    // Matches protocol::udp_transport::UDP_NATIVE_MAX_TUN_MTU.
    static final int NATIVE_UDP_MAX_TUN_MTU = 1280;
    static final int HTTP_PROXY_PORT = 18080;
    static final int HTTP_PROXY_THREADS = 4;
    static final int HTTP_PROXY_MAX_CONCURRENT_CONNECTS = 16;
    static final int CONNECT_TIMEOUT_SECS = 30;
    static final String QUIC_POLICY = "allow";
    static final String COMPRESSION_MODE = "none";
    static final String TRANSPORT_MODE = BuildConfig.DEBUG ? "tcp" : "udp";
    static final int UDP_SESSION_POOL_SIZE = 4;
    static final int MIN_UDP_SESSION_POOL_SIZE = 1;
    static final int MAX_UDP_SESSION_POOL_SIZE = 8;
    static final String DIRECT_ACCESS_MODE = "proxy_all";
    static final String DIRECT_ACCESS_RULES =
            "localhost\n"
                    + "*.local\n"
                    + "127.0.0.0/8\n"
                    + "10.0.0.0/8\n"
                    + "172.16.0.0/12\n"
                    + "192.168.0.0/16\n"
                    + "::1";
    static final int UDP_YAMUX_SESSIONS = 5;
    static final int UDP_YAMUX_MAX_STREAMS_PER_SESSION = 256;
    static final int UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS = 10;
    static final int UDP_YAMUX_KEEPALIVE_INTERVAL_SECS = 30;
    static final int UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS = 10;
    static final int UDP_YAMUX_STREAM_WINDOW_SIZE_KB = 8192;
    static final int MIN_YAMUX_STREAM_WINDOW_SIZE_KB = 256;
    static final int ASYNC_RUNTIME_STACK_SIZE_MB = 4;
    static final int RUNTIME_THREADS = 4;

    private DefaultConfig() {
    }
}
