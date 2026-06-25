package com.ppaass.ai.agent;

final class DefaultConfig {
    static final String PROXY_ADDR = "140.82.30.214:80";
    static final String USERNAME = "user1";
    static final String TUN_IPV4 = "10.10.10.2/24";
    static final String TUN_IPV6 = "";
    static final int TUN_MTU = 1500;
    static final int HTTP_PROXY_PORT = 18080;
    static final int HTTP_PROXY_THREADS = 4;
    static final String QUIC_POLICY = "allow";
    static final String COMPRESSION_MODE = "none";
    static final String DIRECT_ACCESS_MODE = "proxy_all";
    static final String DIRECT_ACCESS_RULES =
            "localhost\n"
                    + "*.local\n"
                    + "127.0.0.0/8\n"
                    + "10.0.0.0/8\n"
                    + "172.16.0.0/12\n"
                    + "192.168.0.0/16\n"
                    + "::1";
    static final int TCP_YAMUX_SESSIONS = 5;
    static final int UDP_YAMUX_SESSIONS = 5;
    static final int TCP_YAMUX_MAX_STREAMS_PER_SESSION = 256;
    static final int UDP_YAMUX_MAX_STREAMS_PER_SESSION = 256;
    static final int TCP_YAMUX_OPEN_STREAM_TIMEOUT_SECS = 10;
    static final int UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS = 10;
    static final int TCP_YAMUX_KEEPALIVE_INTERVAL_SECS = 30;
    static final int UDP_YAMUX_KEEPALIVE_INTERVAL_SECS = 30;
    static final int TCP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS = 10;
    static final int UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS = 10;
    static final int TCP_YAMUX_STREAM_WINDOW_SIZE_KB = 8192;
    static final int UDP_YAMUX_STREAM_WINDOW_SIZE_KB = 8192;
    static final int MIN_YAMUX_STREAM_WINDOW_SIZE_KB = 256;
    static final int ASYNC_RUNTIME_STACK_SIZE_MB = 4;
    static final int RUNTIME_THREADS = 4;
    static final String PRIVATE_KEY_PEM =
            "-----BEGIN PRIVATE KEY-----\n"
                    + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2bpTBcj9mZStY\n"
                    + "8X2CRey+aeH/vu9yLXpoYkFm/0Ezv7C5jaaXua91gVsZU+IoH0sLi2528aa/b3xe\n"
                    + "55wrG7MdGhLCymPaqevzADWqyMeVUpoAJUopKBqOVEThuQHHKXJ8hmZcY5CuvO+6\n"
                    + "7rUq7dLEA8zN1bkRQhoccnlt3TVl8Qnq+wkosbxxP0jKP6ywQPylFNGnaNu1Un+w\n"
                    + "2pzS1LUzOcMYRU5rxTPJlRrxoZpCMZATEDNEIIPOHdx5J50iGnjJKzoq53uexBKA\n"
                    + "VVzSnFw/HM7z8iZevkpaKBpOeR9NUYXMUevOBN2o8mIu01E8KbFAAxmm79T2fEID\n"
                    + "lhjbFHnLAgMBAAECggEACFQkFnDQ1CvqPrVHtZrbpBXRa4ucAupwnDNgKQOeRm6J\n"
                    + "8u60nFit2f992TorKQnEs1I6SNPfeP3t/6czSgSJuNpn4Ny8kk8Ppphr2tAvzHFo\n"
                    + "9ni9WgOqsrTGMEfx/NW3lFfOdIlXIaMejro3Ky6QYMKLpxoKyO7rokDXqlxfA7hZ\n"
                    + "jsnkaHvP1KqHduKF8qZcckGNy2229HNJQdtW1/YX8WpoiM1hm2nhkGXzv0E5ZqY2\n"
                    + "plbZE0gFYlTh9VNhzl3qorW7sxCAN2rID6aUXX1zkvn4Qw4VFXSqjonKElDvpV2u\n"
                    + "7PK+Ok9F6V2mS0Flr6o1SAwyIpgQBM/787oWKiK9AQKBgQDyXoygemuZ9smx81F9\n"
                    + "juo6tahKF7KUU/nXUDmT56WrrfJsya1YThrG2/3TXaqf/SKMxlayHpf44sm7C+9w\n"
                    + "rbbSPMjHzNYABIMWI/6QkoPg3eOKQwBotmfxSxg1yM1PJbh8MV208+aYSoz0oEqV\n"
                    + "FDfWsvy/4qw6ijNIWKj2cavpuQKBgQDAsRlCJVtTuIvS9DGJCmHJaW9DXtAV6V5U\n"
                    + "bez0Gf3DD1hIV6ubAqwNlrOsb/IhS+/B4ihxOJr3jVv6OL25T3NO4Trh3xPwqF8l\n"
                    + "6Bd7IdKSnatNKN8/aIehVz8SCCbakTzyyrnCvZVaiIeugY4hXraQbsfgB9c63Iqe\n"
                    + "/0lhBhRxowKBgGBwKKqOK5R2syigdZNtM1wq/gyFQ2RryaTX4iEs8inOrACHevcB\n"
                    + "FPx9epEI2ySP15iGLubu729z5esMQ7jlFjKvRwDhS2F0aih8KAWklt75y1kvcdE4\n"
                    + "i0FirP5xqOfOTYr1JaEjz2RXfaC0yxholBNU4ucDLZ6ZcPBfftOYxVvZAoGBALNU\n"
                    + "3x4JaFqdeTwmWeehiuqJPqyjk+OgolLPT2TKv7oHEPGa7jHApeGrrKJCOUU1x/hY\n"
                    + "g60Dsm3L2JsirafGQplZ0pQeKg+ik5LS0u+cxb4AEUopTMRVg0zrxt4ASjDGVMPd\n"
                    + "Wk7cZCCyyhvlpSJ3ZE89WrWsdmnokPZyvpcWsnYjAoGAVRhzNJzJOUjK714V0PjE\n"
                    + "LcAEF5V8Gd+T3Xutmj6oulPS6CYyLFWjyusQJJ6qdt4F5N1j3a6Rv+MzP4668b1P\n"
                    + "m0mTTUmIbZIhM67IfVe7lj4uopgTujn8HpsZvjwXPyQclR9fmti61RUKLdK0A3Kq\n"
                    + "zqEo5pxPu+OUjA5iOBQJ0yc=\n"
                    + "-----END PRIVATE KEY-----\n";

    private DefaultConfig() {
    }

    static String normalizePrivateKeyPem(String pem) {
        if (pem == null || pem.trim().isEmpty()) {
            pem = PRIVATE_KEY_PEM;
        }

        String[] lines = pem.replace("\r\n", "\n").replace('\r', '\n').split("\n");
        StringBuilder normalized = new StringBuilder();
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                normalized.append(trimmed).append('\n');
            }
        }
        return normalized.toString();
    }
}
