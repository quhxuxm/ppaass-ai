package com.ppaass.ai.agent;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.NoRouteToHostException;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLException;

final class AgentAuthHttpTransport {
    private static final String TAG = "PpaassAgentAuth";
    private static final int CONNECT_TIMEOUT_MS = 8_000;
    private static final int READ_TIMEOUT_MS = 20_000;
    private static final String SESSION_COOKIE_NAME = "ppaass_session";
    private static final int MAX_SESSION_COOKIE_BYTES = 4 * 1024;
    private static final int MAX_RETRY_AFTER_SECONDS = 5 * 60;

    private final Context context;
    private final String baseUrl;
    private final Object connectionLock = new Object();
    private volatile boolean cancelled;
    private HttpURLConnection activeConnection;
    private String sessionCookie;

    AgentAuthHttpTransport(Context context, String baseUrl) {
        this.context = context.getApplicationContext();
        this.baseUrl = baseUrl;
    }

    Response execute(
            String method,
            String path,
            Object body,
            String csrfToken,
            String bearerToken,
            int maximumBytes) throws AgentAuthClient.AuthException {
        return execute(
                method,
                path,
                body,
                csrfToken,
                bearerToken,
                maximumBytes,
                false);
    }

    <T> T requestObject(
            String method,
            String path,
            Object body,
            String bearerToken,
            int maximumBytes,
            Class<T> responseType) throws AgentAuthClient.AuthException {
        Response response = execute(
                method,
                path,
                body,
                null,
                bearerToken,
                maximumBytes);
        if (!response.isSuccessful()) {
            throw AgentAuthErrors.apiError(response.status, response.body);
        }
        return AgentAuthJsonCodec.decode(response.body, responseType);
    }

    void bestEffortLogout(String csrfToken, int maximumBytes) {
        try {
            Response response = execute(
                    "POST",
                    "/api/v1/auth/logout",
                    null,
                    csrfToken,
                    null,
                    maximumBytes,
                    true);
            if (!response.isSuccessful()) {
                throw AgentAuthErrors.apiError(response.status, response.body);
            }
        } catch (AgentAuthClient.AuthException error) {
            Log.w(TAG, "Failed to clear temporary Proxy Registry session");
        }
    }

    void cancel() {
        cancelled = true;
        synchronized (connectionLock) {
            if (activeConnection != null) {
                activeConnection.disconnect();
            }
        }
    }

    boolean isCancelled() {
        return cancelled;
    }

    private Response execute(
            String method,
            String path,
            Object body,
            String csrfToken,
            String bearerToken,
            int maximumBytes,
            boolean ignoreCancellation) throws AgentAuthClient.AuthException {
        HttpURLConnection connection = null;
        try {
            throwIfCancelled(ignoreCancellation);
            connection = openConnection(new URL(baseUrl + path));
            synchronized (connectionLock) {
                throwIfCancelled(ignoreCancellation);
                activeConnection = connection;
            }
            configure(connection, method, csrfToken, bearerToken);
            if (body != null) {
                writeJsonBody(connection, body);
            }
            int status = connection.getResponseCode();
            adoptSessionCookie(connection);
            int retryAfter = parseRetryAfterSeconds(
                    connection.getHeaderField("Retry-After"));
            byte[] responseBody = readBounded(
                    status >= 400
                            ? connection.getErrorStream()
                            : connection.getInputStream(),
                    maximumBytes);
            throwIfCancelled(ignoreCancellation);
            return new Response(status, responseBody, retryAfter);
        } catch (AgentAuthClient.AuthException error) {
            throw error;
        } catch (SSLException error) {
            throwIfCancelled(ignoreCancellation);
            throw new AgentAuthClient.AuthException(
                    "认证服务 TLS 或证书校验失败，请联系管理员",
                    error);
        } catch (SocketTimeoutException error) {
            throwIfCancelled(ignoreCancellation);
            throw new AgentAuthClient.AuthException("连接认证服务超时，请稍后重试", error);
        } catch (ConnectException | UnknownHostException | NoRouteToHostException error) {
            throwIfCancelled(ignoreCancellation);
            throw new AgentAuthClient.AuthException(
                    "无法连接认证服务，请联系管理员检查 Agent 配置和服务状态",
                    error);
        } catch (IOException | RuntimeException error) {
            throwIfCancelled(ignoreCancellation);
            Log.w(TAG, "Authentication service request failed", error);
            throw new AgentAuthClient.AuthException("认证服务请求失败，请稍后重试", error);
        } finally {
            synchronized (connectionLock) {
                if (activeConnection == connection) {
                    activeConnection = null;
                }
            }
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void configure(
            HttpURLConnection connection,
            String method,
            String csrfToken,
            String bearerToken) throws IOException {
        connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
        connection.setReadTimeout(READ_TIMEOUT_MS);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestMethod(method);
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty(
                "User-Agent",
                "ppaass-android-agent/" + BuildConfig.VERSION_NAME);
        if (sessionCookie != null) {
            connection.setRequestProperty("Cookie", sessionCookie);
        }
        if (csrfToken != null && !csrfToken.isEmpty()) {
            connection.setRequestProperty("X-CSRF-Token", csrfToken);
        }
        if (bearerToken != null && !bearerToken.isEmpty()) {
            connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
        }
    }

    private static void writeJsonBody(HttpURLConnection connection, Object body)
            throws IOException, AgentAuthClient.AuthException {
        byte[] payload = AgentAuthJsonCodec.encode(body);
        connection.setDoOutput(true);
        connection.setFixedLengthStreamingMode(payload.length);
        connection.setRequestProperty("Content-Type", "application/json");
        try (OutputStream output = connection.getOutputStream()) {
            output.write(payload);
        }
    }

    @SuppressWarnings("deprecation")
    HttpURLConnection openConnection(URL url) throws IOException {
        return AgentRegistryTlsPolicy.apply(openNetworkConnection(url));
    }

    @SuppressWarnings("deprecation")
    private HttpURLConnection openNetworkConnection(URL url) throws IOException {
        if (AgentAuthConfig.isLoopbackHost(url.getHost())) {
            return (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
        }
        ConnectivityManager manager =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) {
            return (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
        }
        Network active = manager.getActiveNetwork();
        if (isUsableUnderlyingNetwork(manager, active)) {
            return (HttpURLConnection) active.openConnection(url, Proxy.NO_PROXY);
        }
        Network validatedFallback = null;
        Network unvalidatedFallback = null;
        for (Network network : manager.getAllNetworks()) {
            if (!isUsableUnderlyingNetwork(manager, network)) {
                continue;
            }
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                        || capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_ETHERNET)) {
                    return (HttpURLConnection) network.openConnection(url, Proxy.NO_PROXY);
                }
                if (validatedFallback == null) {
                    validatedFallback = network;
                }
            } else if (unvalidatedFallback == null) {
                unvalidatedFallback = network;
            }
        }
        Network fallback =
                validatedFallback == null ? unvalidatedFallback : validatedFallback;
        return fallback == null
                ? (HttpURLConnection) url.openConnection(Proxy.NO_PROXY)
                : (HttpURLConnection) fallback.openConnection(url, Proxy.NO_PROXY);
    }

    private static boolean isUsableUnderlyingNetwork(
            ConnectivityManager manager,
            Network network) {
        if (network == null) {
            return false;
        }
        NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
        return capabilities != null
                && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
    }

    private void adoptSessionCookie(HttpURLConnection connection)
            throws AgentAuthClient.AuthException {
        for (Map.Entry<String, List<String>> header
                : connection.getHeaderFields().entrySet()) {
            if (header.getKey() == null
                    || !"Set-Cookie".equalsIgnoreCase(header.getKey())) {
                continue;
            }
            for (String value : header.getValue()) {
                int separator = value.indexOf(';');
                String pair = (separator < 0
                        ? value
                        : value.substring(0, separator)).trim();
                String prefix = SESSION_COOKIE_NAME + "=";
                if (!pair.startsWith(prefix)) {
                    continue;
                }
                String token = pair.substring(prefix.length());
                if (token.isEmpty()) {
                    sessionCookie = null;
                } else if (token.length() > MAX_SESSION_COOKIE_BYTES
                        || !isUrlSafeToken(token)) {
                    throw new AgentAuthClient.AuthException(
                            "Proxy Registry 会话响应无效");
                } else {
                    sessionCookie = pair;
                }
            }
        }
    }

    private static byte[] readBounded(InputStream stream, int maximumBytes)
            throws IOException, AgentAuthClient.AuthException {
        if (stream == null) {
            return new byte[0];
        }
        try (InputStream input = stream;
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > maximumBytes) {
                    throw new AgentAuthClient.AuthException(
                            "Proxy Registry 响应过大，已拒绝处理");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private void throwIfCancelled(boolean ignoreCancellation)
            throws AgentAuthClient.CancelledException {
        if (!ignoreCancellation && cancelled) {
            throw new AgentAuthClient.CancelledException();
        }
    }

    private static int parseRetryAfterSeconds(String value) {
        if (value == null || value.isEmpty()) {
            return 0;
        }
        try {
            long seconds = Long.parseLong(value.trim());
            return seconds < 1
                    ? 0
                    : (int) Math.min(seconds, MAX_RETRY_AFTER_SECONDS);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static boolean isUrlSafeToken(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!(Character.isLetterOrDigit(character)
                    || character == '-'
                    || character == '_')) {
                return false;
            }
        }
        return true;
    }

    static final class Response {
        final int status;
        final byte[] body;
        final int retryAfterSeconds;

        Response(int status, byte[] body, int retryAfterSeconds) {
            this.status = status;
            this.body = body;
            this.retryAfterSeconds = retryAfterSeconds;
        }

        boolean isSuccessful() {
            return status >= 200 && status < 300;
        }
    }
}
