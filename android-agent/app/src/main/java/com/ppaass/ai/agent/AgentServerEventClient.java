package com.ppaass.ai.agent;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

final class AgentServerEventClient {
    static final String SYNC = "sync";
    static final String PROFILE_CHANGED = "profile_changed";
    static final String PROFILES_CHANGED = "profiles_changed";
    static final String KEY_REQUEST_CHANGED = "key_request_changed";
    static final String ADMIN_KEY_REQUESTS_CHANGED =
            "admin_key_requests_changed";

    private static final int CONNECT_TIMEOUT_MS = 8_000;
    private static final int MAX_LINE_BYTES = 8 * 1024;
    private static final int MAX_ERROR_BYTES = 32 * 1024;

    interface Listener {
        boolean onEvent(String event);
    }

    static final class EventException extends Exception {
        final boolean unauthorized;

        EventException(String message, boolean unauthorized) {
            super(message);
            this.unauthorized = unauthorized;
        }

        EventException(String message, Throwable cause) {
            super(message, cause);
            this.unauthorized = false;
        }
    }

    private final AgentAuthHttpTransport connectionFactory;
    private final String baseUrl;
    private volatile boolean cancelled;
    private volatile HttpURLConnection activeConnection;

    AgentServerEventClient(android.content.Context context, String baseUrl) {
        this.baseUrl = AgentAuthConfig.normalizeProxyRegistryUrl(baseUrl);
        this.connectionFactory =
                new AgentAuthHttpTransport(context, this.baseUrl);
    }

    void listen(String accessToken, Listener listener)
            throws EventException {
        if (cancelled) {
            return;
        }
        HttpURLConnection connection = null;
        try {
            connection = connectionFactory.openConnection(
                    new URL(baseUrl + "/api/v1/agent/events"));
            activeConnection = connection;
            configure(connection, accessToken);
            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                readError(connection);
                throw new EventException(
                        "Agent SSE 返回 HTTP " + status,
                        status == HttpURLConnection.HTTP_UNAUTHORIZED
                                || status == HttpURLConnection.HTTP_FORBIDDEN);
            }
            String contentType = connection.getContentType();
            if (contentType == null
                    || !"text/event-stream".equalsIgnoreCase(
                    contentType.split(";", 2)[0].trim())) {
                throw new EventException("Proxy Registry SSE 响应类型无效", false);
            }
            readEvents(connection.getInputStream(), listener);
        } catch (EventException error) {
            throw error;
        } catch (IOException | RuntimeException error) {
            if (!cancelled) {
                throw new EventException("Agent SSE 连接中断", error);
            }
        } finally {
            activeConnection = null;
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    void cancel() {
        cancelled = true;
        HttpURLConnection connection = activeConnection;
        if (connection != null) {
            connection.disconnect();
        }
    }

    private void configure(
            HttpURLConnection connection,
            String accessToken) throws IOException {
        connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
        connection.setReadTimeout(0);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Accept", "text/event-stream");
        connection.setRequestProperty(
                "User-Agent",
                "ppaass-android-agent/" + BuildConfig.VERSION_NAME);
        connection.setRequestProperty(
                "Authorization",
                "Bearer " + accessToken);
    }

    private void readEvents(InputStream stream, Listener listener)
            throws IOException, EventException {
        try (BufferedInputStream input = new BufferedInputStream(stream)) {
            String event = null;
            while (!cancelled) {
                String line = readLine(input);
                if (line == null) {
                    return;
                }
                if (line.isEmpty()) {
                    if (isSupported(event)) {
                        if (!listener.onEvent(event)) {
                            return;
                        }
                    }
                    event = null;
                } else if (!line.startsWith(":")
                        && line.startsWith("event:")) {
                    event = line.substring("event:".length()).trim();
                }
            }
        }
    }

    private static String readLine(BufferedInputStream input)
            throws IOException, EventException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        while (true) {
            int next = input.read();
            if (next == -1) {
                return line.size() == 0
                        ? null
                        : new String(
                        line.toByteArray(),
                        StandardCharsets.UTF_8);
            }
            if (next == '\n') {
                byte[] bytes = line.toByteArray();
                int length = bytes.length;
                if (length > 0 && bytes[length - 1] == '\r') {
                    length--;
                }
                return new String(bytes, 0, length, StandardCharsets.UTF_8);
            }
            if (line.size() >= MAX_LINE_BYTES) {
                throw new EventException("Agent SSE 单行数据过大", false);
            }
            line.write(next);
        }
    }

    private static boolean isSupported(String event) {
        return SYNC.equals(event)
                || PROFILE_CHANGED.equals(event)
                || PROFILES_CHANGED.equals(event)
                || KEY_REQUEST_CHANGED.equals(event)
                || ADMIN_KEY_REQUESTS_CHANGED.equals(event);
    }

    private static void readError(HttpURLConnection connection) {
        InputStream stream = connection.getErrorStream();
        if (stream == null) {
            return;
        }
        try (InputStream input = stream) {
            byte[] buffer = new byte[1024];
            int total = 0;
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > MAX_ERROR_BYTES) {
                    break;
                }
            }
        } catch (IOException ignored) {
            // HTTP 状态码已经足够决定重连策略。
        }
    }
}
