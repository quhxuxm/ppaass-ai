package com.ppaass.ai.agent;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLException;

final class AgentAuthClient {
    private static final String TAG = "PpaassAgentAuth";
    private static final int CONNECT_TIMEOUT_MS = 8_000;
    private static final int READ_TIMEOUT_MS = 20_000;
    private static final int MAX_NORMAL_RESPONSE_BYTES = 64 * 1024;
    private static final int MAX_PRIVATE_KEY_RESPONSE_BYTES = 256 * 1024;
    private static final int MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES = 64 * 1024;
    private static final String SESSION_COOKIE_NAME = "ppaass_session";
    private static final int MAX_SESSION_COOKIE_BYTES = 4 * 1024;
    private static final int MAX_DEVICE_AUTHORIZATION_SECONDS = 60 * 60;
    private static final int MAX_DEVICE_POLL_DELAY_SECONDS = 5 * 60;

    private final Context context;
    private final String baseUrl;
    private final Object connectionLock = new Object();
    private volatile boolean cancelled;
    private HttpURLConnection activeConnection;
    private String sessionCookie;

    AgentAuthClient(Context context, String baseUrl) {
        this.context = context.getApplicationContext();
        this.baseUrl = AgentAuthConfig.normalizeProxyWebUrl(baseUrl);
    }

    DeviceAuthorization startDeviceAuthorization() throws AuthException {
        JSONObject body = new JSONObject();
        try {
            body.put("platform", "android");
            body.put("client_name", "PPAASS Android Agent");
        } catch (JSONException error) {
            throw new AuthException("无法创建设备登录请求", error);
        }

        JSONObject response = requestJson(
                "POST",
                "/api/v1/agent/device-authorizations",
                body,
                null,
                MAX_NORMAL_RESPONSE_BYTES);
        String deviceCode = requiredString(response, "device_code");
        String userCode = requiredString(response, "user_code");
        String verificationUri = requiredString(response, "verification_uri");
        String verificationUriComplete =
                requiredString(response, "verification_uri_complete");
        long expiresIn = requiredLong(response, "expires_in");
        long interval = requiredLong(response, "interval");
        if (deviceCode.length() != 43
                || !isUrlSafeToken(deviceCode)
                || userCode.length() > 64
                || expiresIn < 1
                || expiresIn > MAX_DEVICE_AUTHORIZATION_SECONDS
                || interval < 1
                || interval > MAX_DEVICE_POLL_DELAY_SECONDS) {
            throw new AuthException("Proxy Web 返回的设备登录参数无效");
        }

        final String verificationUrl;
        try {
            AgentAuthConfig.resolveServiceRelativeUrl(baseUrl, verificationUri);
            verificationUrl =
                    AgentAuthConfig.resolveServiceRelativeUrl(baseUrl, verificationUriComplete);
        } catch (IllegalArgumentException error) {
            throw new AuthException("Proxy Web 返回的设备登录地址无效", error);
        }
        return new DeviceAuthorization(
                deviceCode,
                verificationUrl,
                (int) expiresIn,
                (int) interval);
    }

    DevicePollResult pollDeviceAuthorization(
            String deviceCode,
            int currentIntervalSeconds) throws AuthException {
        JSONObject body = new JSONObject();
        try {
            body.put("device_code", deviceCode);
        } catch (JSONException error) {
            throw new AuthException("无法创建设备登录轮询请求", error);
        }

        Response response = requestAllowingHttpErrors(
                "POST",
                "/api/v1/agent/device-authorizations/token",
                body,
                null,
                MAX_PRIVATE_KEY_RESPONSE_BYTES);
        JSONObject json = parseJsonResponse(response.body);
        if (response.status >= 200 && response.status < 300) {
            String csrfToken = nullableString(json, "csrf_token");
            try {
                LoginResult result = parseDeviceLoginResult(json);
                if (cancelled) {
                    throw new CancelledException();
                }
                return DevicePollResult.authorized(result);
            } finally {
                if (csrfToken != null && !csrfToken.isEmpty()) {
                    bestEffortLogout(csrfToken);
                }
            }
        }

        JSONObject error = json.optJSONObject("error");
        String code = error == null ? "" : error.optString("code");
        if (response.status == 428 && "authorization_pending".equals(code)) {
            return DevicePollResult.pending(devicePollDelaySeconds(
                    currentIntervalSeconds,
                    response.retryAfterSeconds,
                    false));
        }
        int rateLimitDelaySeconds = devicePollRateLimitDelaySeconds(
                response.status,
                code,
                currentIntervalSeconds,
                response.retryAfterSeconds);
        if (rateLimitDelaySeconds > 0) {
            return "slow_down".equals(code)
                    ? DevicePollResult.slowDown(rateLimitDelaySeconds)
                    : DevicePollResult.pending(rateLimitDelaySeconds);
        }
        if (response.status == 403 && "access_denied".equals(code)) {
            throw new AuthException("你已在浏览器中拒绝这次 Agent 登录");
        }
        if (response.status == 403 && "authorization_invalidated".equals(code)) {
            throw new AuthException("账号状态已变化，请重新开始登录");
        }
        if (response.status == 400 && "expired_token".equals(code)) {
            throw new AuthException("浏览器登录请求已过期，请重新开始");
        }
        if (response.status == 400 && "invalid_device_code".equals(code)) {
            throw new AuthException("浏览器登录请求无效或已被使用，请重新开始");
        }
        throw apiError(response.status, response.body);
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

    LoginResult authenticate(String username, String password) throws AuthException {
        String normalizedUsername = username == null ? "" : username.trim();
        if (normalizedUsername.isEmpty()) {
            throw new AuthException("请输入用户名");
        }
        if (password == null || password.length() < 8) {
            throw new AuthException("密码至少需要 8 位");
        }

        JSONObject loginBody = new JSONObject();
        try {
            loginBody.put("username", normalizedUsername);
            loginBody.put("password", password);
        } catch (JSONException error) {
            throw new AuthException("无法创建认证请求", error);
        }

        JSONObject login = requestJson(
                "POST",
                "/api/v1/auth/login",
                loginBody,
                null,
                MAX_NORMAL_RESPONSE_BYTES);
        String csrfToken = requiredString(login, "csrf_token");

        try {
            JSONObject account = requiredObject(login, "account");
            if (!"user".equals(requiredString(account, "role"))) {
                throw new AuthException("管理员账号不能用于 Agent，请使用普通用户账号登录");
            }
            if (!"active".equals(requiredString(account, "status"))) {
                throw new AuthException("账号已停用");
            }
            String linkedUsername = nullableString(account, "linked_username");

            JSONObject me = requestJson(
                    "GET",
                    "/api/v1/me",
                    null,
                    null,
                    MAX_NORMAL_RESPONSE_BYTES);
            JSONObject profile = requireActiveProfile(me);
            String profileUsername = requiredString(profile, "username");
            if (linkedUsername != null && !linkedUsername.equals(profileUsername)) {
                throw new AuthException("账号与 Proxy 用户绑定关系不一致，请联系管理员");
            }
            if (!profile.optBoolean("enabled", false)) {
                throw new AuthException("Proxy 用户已停用");
            }
            if (!contains(requiredArray(profile, "permissions"), "key.private.read")) {
                throw new AuthException("当前账号没有读取私钥的权限");
            }

            long expiresAt = requiredLong(profile, "expires_at");
            long keyVersion = requiredLong(profile, "key_version");

            JSONObject privateKey = requestJson(
                    "GET",
                    "/api/v1/me/private-key",
                    null,
                    null,
                    MAX_PRIVATE_KEY_RESPONSE_BYTES);
            String returnedUsername = requiredString(privateKey, "username");
            long returnedKeyVersion = requiredLong(privateKey, "key_version");
            if (!profileUsername.equals(returnedUsername)
                    || keyVersion != returnedKeyVersion) {
                throw new AuthException("Proxy Web 返回的密钥与当前账号版本不一致");
            }

            String privateKeyPem = requiredString(privateKey, "private_key_pem");
            String publicKeyPem = requiredString(privateKey, "public_key_pem");
            String proxyIdentityPublicKeyPem =
                    requiredString(privateKey, "proxy_identity_public_key_pem");
            validateMatchingKeyPair(privateKeyPem, publicKeyPem);
            validateProxyIdentityPublicKey(proxyIdentityPublicKeyPem);

            Log.i(TAG, "Agent user authenticated and managed key validated");
            return new LoginResult(
                    profileUsername,
                    keyVersion,
                    expiresAt,
                    privateKeyPem,
                    proxyIdentityPublicKeyPem);
        } finally {
            bestEffortLogout(csrfToken);
        }
    }

    private LoginResult parseDeviceLoginResult(JSONObject response) throws AuthException {
        JSONObject account = requiredObject(response, "account");
        if (!"user".equals(requiredString(account, "role"))) {
            throw new AuthException("管理员账号不能用于 Agent，请使用普通用户账号登录");
        }
        if (!"active".equals(requiredString(account, "status"))) {
            throw new AuthException("账号已停用");
        }

        JSONObject profile = requiredObject(response, "profile");
        String username = requiredString(profile, "username");
        String linkedUsername = nullableString(account, "linked_username");
        if (linkedUsername != null && !linkedUsername.equals(username)) {
            throw new AuthException("账号与 Proxy 用户绑定关系不一致，请联系管理员");
        }
        if (!contains(requiredArray(profile, "permissions"), "key.private.read")) {
            throw new AuthException("当前账号没有读取私钥的权限");
        }
        long keyVersion = requiredLong(profile, "key_version");
        long expiresAt = requiredLong(profile, "expires_at");
        if (keyVersion < 1) {
            throw new AuthException("Proxy Web 返回的密钥版本无效");
        }
        requiredLong(response, "session_expires_at");

        String privateKeyPem = requiredString(response, "private_key_pem");
        String publicKeyPem = requiredString(response, "public_key_pem");
        String proxyIdentityPublicKeyPem =
                requiredString(response, "proxy_identity_public_key_pem");
        validateMatchingKeyPair(privateKeyPem, publicKeyPem);
        validateProxyIdentityPublicKey(proxyIdentityPublicKeyPem);
        Log.i(TAG, "Browser-authorized Agent key validated");
        return new LoginResult(
                username,
                keyVersion,
                expiresAt,
                privateKeyPem,
                proxyIdentityPublicKeyPem);
    }

    private static void validateMatchingKeyPair(
            String privateKeyPem,
            String publicKeyPem) throws AuthException {
        final boolean matchingKeyPair;
        try {
            matchingKeyPair = NativeAgent.validateKeyPair(privateKeyPem, publicKeyPem);
        } catch (RuntimeException | UnsatisfiedLinkError error) {
            throw new AuthException("无法校验 Proxy Web 返回的私钥", error);
        }
        if (!matchingKeyPair) {
            throw new AuthException("Proxy Web 返回的公钥和私钥不匹配");
        }
    }

    static void validateProxyIdentityPublicKey(String publicKeyPem) throws AuthException {
        if (publicKeyPem == null
                || publicKeyPem.isEmpty()
                || publicKeyPem.getBytes(StandardCharsets.UTF_8).length
                > MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES) {
            throw new AuthException("Proxy Web 返回的 Proxy 身份公钥大小无效");
        }
        final String begin = "-----BEGIN PUBLIC KEY-----";
        final String end = "-----END PUBLIC KEY-----";
        String normalized = publicKeyPem.trim();
        if (!normalized.startsWith(begin) || !normalized.endsWith(end)) {
            throw new AuthException("Proxy Web 返回的 Proxy 身份公钥格式无效");
        }
        String encoded = normalized.substring(
                begin.length(),
                normalized.length() - end.length()).replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(encoded);
            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
            int bits = publicKey.getModulus().bitLength();
            if (bits < 2048 || bits > 8192) {
                throw new AuthException("Proxy Web 返回的 Proxy 身份公钥强度无效");
            }
        } catch (IllegalArgumentException
                 | GeneralSecurityException
                 | ClassCastException error) {
            throw new AuthException("Proxy Web 返回的 Proxy 身份公钥格式无效", error);
        }
    }

    private JSONObject requireActiveProfile(JSONObject me) throws AuthException {
        String keyState = requiredString(me, "key_state");
        if ("active".equals(keyState)) {
            return requiredObject(me, "profile");
        }
        if ("missing".equals(keyState) || "expired".equals(keyState)) {
            JSONObject pending = me.optJSONObject("pending_request");
            if (pending != null && "pending".equals(pending.optString("status"))) {
                throw new AuthException("密钥申请正在等待管理员审批");
            }
            throw new AuthException(
                    "当前没有可用密钥，请先在用户中心提交申请并等待管理员批准");
        }
        if ("disabled".equals(keyState)) {
            throw new AuthException("Proxy 用户已停用");
        }
        throw new AuthException("Proxy Web 返回了未知的密钥状态");
    }

    private JSONObject requestJson(
            String method,
            String path,
            JSONObject body,
            String csrfToken,
            int maximumBytes) throws AuthException {
        Response response = request(method, path, body, csrfToken, maximumBytes);
        return parseJsonResponse(response.body);
    }

    private static JSONObject parseJsonResponse(byte[] responseBody) throws AuthException {
        if (responseBody.length == 0) {
            throw new AuthException("Proxy Web 响应格式无效");
        }
        try {
            return new JSONObject(new String(responseBody, StandardCharsets.UTF_8));
        } catch (JSONException error) {
            throw new AuthException("Proxy Web 响应格式无效", error);
        }
    }

    private Response request(
            String method,
            String path,
            JSONObject body,
            String csrfToken,
            int maximumBytes) throws AuthException {
        Response response = executeRequest(
                method,
                path,
                body,
                csrfToken,
                maximumBytes,
                false);
        if (response.status < 200 || response.status >= 300) {
            throw apiError(response.status, response.body);
        }
        return response;
    }

    private Response requestAllowingHttpErrors(
            String method,
            String path,
            JSONObject body,
            String csrfToken,
            int maximumBytes) throws AuthException {
        return executeRequest(method, path, body, csrfToken, maximumBytes, false);
    }

    private Response executeRequest(
            String method,
            String path,
            JSONObject body,
            String csrfToken,
            int maximumBytes,
            boolean ignoreCancellation) throws AuthException {
        HttpURLConnection connection = null;
        try {
            throwIfCancelled(ignoreCancellation);
            URL url = new URL(baseUrl + path);
            connection = openConnection(url);
            synchronized (connectionLock) {
                throwIfCancelled(ignoreCancellation);
                activeConnection = connection;
            }
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod(method);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty(
                    "User-Agent",
                    "ppaass-android-agent/" + BuildConfig.VERSION_NAME);
            applySessionCookie(connection);
            if (csrfToken != null && !csrfToken.isEmpty()) {
                connection.setRequestProperty("X-CSRF-Token", csrfToken);
            }
            if (body != null) {
                byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);
                connection.setDoOutput(true);
                connection.setFixedLengthStreamingMode(payload.length);
                connection.setRequestProperty("Content-Type", "application/json");
                try (OutputStream output = connection.getOutputStream()) {
                    output.write(payload);
                }
            }

            int status = connection.getResponseCode();
            adoptSessionCookie(connection);
            int retryAfterSeconds =
                    parseRetryAfterSeconds(connection.getHeaderField("Retry-After"));
            byte[] responseBody = readBounded(
                    status >= 400 ? connection.getErrorStream() : connection.getInputStream(),
                    maximumBytes);
            throwIfCancelled(ignoreCancellation);
            return new Response(status, responseBody, retryAfterSeconds);
        } catch (AuthException error) {
            throw error;
        } catch (SSLException error) {
            throwIfCancelled(ignoreCancellation);
            throw new AuthException("认证服务 TLS 或证书校验失败，请联系管理员", error);
        } catch (SocketTimeoutException error) {
            throwIfCancelled(ignoreCancellation);
            throw new AuthException("连接认证服务超时，请稍后重试", error);
        } catch (ConnectException | UnknownHostException | NoRouteToHostException error) {
            throwIfCancelled(ignoreCancellation);
            throw new AuthException(
                    "无法连接认证服务，请联系管理员检查 Agent 配置和服务状态",
                    error);
        } catch (IOException | RuntimeException error) {
            throwIfCancelled(ignoreCancellation);
            Log.w(TAG, "Authentication service request failed", error);
            throw new AuthException("认证服务请求失败，请稍后重试", error);
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

    private void throwIfCancelled(boolean ignoreCancellation) throws CancelledException {
        if (!ignoreCancellation && cancelled) {
            throw new CancelledException();
        }
    }

    @SuppressWarnings("deprecation")
    private HttpURLConnection openConnection(URL url) throws IOException {
        if (AgentAuthConfig.isLoopbackHost(url.getHost())) {
            return (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
        }
        ConnectivityManager manager =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager != null) {
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
            if (fallback != null) {
                return (HttpURLConnection) fallback.openConnection(url, Proxy.NO_PROXY);
            }
        }
        return (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
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

    private void applySessionCookie(HttpURLConnection connection) {
        if (sessionCookie != null) {
            connection.setRequestProperty("Cookie", sessionCookie);
        }
    }

    private void adoptSessionCookie(HttpURLConnection connection) throws AuthException {
        for (Map.Entry<String, List<String>> header :
                connection.getHeaderFields().entrySet()) {
            if (header.getKey() == null
                    || !"Set-Cookie".equalsIgnoreCase(header.getKey())) {
                continue;
            }
            for (String value : header.getValue()) {
                int separator = value.indexOf(';');
                String pair = (separator < 0 ? value : value.substring(0, separator)).trim();
                String prefix = SESSION_COOKIE_NAME + "=";
                if (!pair.startsWith(prefix)) {
                    continue;
                }
                String token = pair.substring(prefix.length());
                if (token.isEmpty()) {
                    sessionCookie = null;
                    continue;
                }
                if (token.getBytes(StandardCharsets.US_ASCII).length
                        > MAX_SESSION_COOKIE_BYTES
                        || !isUrlSafeToken(token)) {
                    throw new AuthException("Proxy Web 会话响应无效");
                }
                sessionCookie = pair;
            }
        }
    }

    private static boolean isUrlSafeToken(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if ((character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character == '-'
                    || character == '_') {
                continue;
            }
            return false;
        }
        return true;
    }

    private void bestEffortLogout(String csrfToken) {
        try {
            Response response = executeRequest(
                    "POST",
                    "/api/v1/auth/logout",
                    null,
                    csrfToken,
                    MAX_NORMAL_RESPONSE_BYTES,
                    true);
            if (response.status < 200 || response.status >= 300) {
                throw apiError(response.status, response.body);
            }
        } catch (AuthException error) {
            Log.w(TAG, "Failed to clear temporary Proxy Web session");
        }
    }

    private static int parseRetryAfterSeconds(String value) {
        if (value == null || value.isEmpty()) {
            return 0;
        }
        try {
            long seconds = Long.parseLong(value.trim());
            if (seconds < 1) {
                return 0;
            }
            return (int) Math.min(seconds, MAX_DEVICE_POLL_DELAY_SECONDS);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    static int devicePollDelaySeconds(
            int currentIntervalSeconds,
            int retryAfterSeconds,
            boolean slowDown) {
        int current = Math.max(
                1,
                Math.min(currentIntervalSeconds, MAX_DEVICE_POLL_DELAY_SECONDS));
        int required = slowDown
                ? Math.min(current + 5, MAX_DEVICE_POLL_DELAY_SECONDS)
                : current;
        if (retryAfterSeconds > 0) {
            required = Math.max(
                    required,
                    Math.min(retryAfterSeconds, MAX_DEVICE_POLL_DELAY_SECONDS));
        }
        return required;
    }

    static int devicePollRateLimitDelaySeconds(
            int status,
            String code,
            int currentIntervalSeconds,
            int retryAfterSeconds) {
        if (status != 429) {
            return 0;
        }
        if ("slow_down".equals(code)) {
            return devicePollDelaySeconds(
                    currentIntervalSeconds,
                    retryAfterSeconds,
                    true);
        }
        if ("rate_limited".equals(code)) {
            return devicePollDelaySeconds(
                    currentIntervalSeconds,
                    retryAfterSeconds,
                    false);
        }
        return 0;
    }

    private static byte[] readBounded(InputStream stream, int maximumBytes)
            throws IOException, AuthException {
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
                    throw new AuthException("Proxy Web 响应过大，已拒绝处理");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static AuthException apiError(int status, byte[] responseBody) {
        try {
            JSONObject root = new JSONObject(new String(responseBody, StandardCharsets.UTF_8));
            JSONObject error = root.optJSONObject("error");
            String code = error == null ? "" : error.optString("code");
            if ("invalid_credentials".equals(code)) {
                return new AuthException("用户名或密码错误");
            }
            if ("key_request_required".equals(code)) {
                return new AuthException(
                        "当前没有可用密钥，请先在用户中心提交申请并等待管理员批准");
            }
            if ("unauthorized".equals(code)) {
                return new AuthException("Proxy Web 会话已失效，请重新登录");
            }
        } catch (JSONException ignored) {
        }
        return new AuthException("认证服务返回 HTTP " + status);
    }

    private static JSONObject requiredObject(JSONObject source, String key) throws AuthException {
        JSONObject value = source.optJSONObject(key);
        if (value == null) {
            throw new AuthException("Proxy Web 响应格式无效");
        }
        return value;
    }

    private static JSONArray requiredArray(JSONObject source, String key) throws AuthException {
        JSONArray value = source.optJSONArray(key);
        if (value == null) {
            throw new AuthException("Proxy Web 响应格式无效");
        }
        return value;
    }

    private static String requiredString(JSONObject source, String key) throws AuthException {
        String value = nullableString(source, key);
        if (value == null || value.isEmpty()) {
            throw new AuthException("Proxy Web 响应格式无效");
        }
        return value;
    }

    private static String nullableString(JSONObject source, String key) {
        if (!source.has(key) || source.isNull(key)) {
            return null;
        }
        Object value = source.opt(key);
        return value instanceof String ? (String) value : null;
    }

    private static long requiredLong(JSONObject source, String key) throws AuthException {
        if (!source.has(key) || source.isNull(key)) {
            throw new AuthException("Proxy Web 响应格式无效");
        }
        try {
            return source.getLong(key);
        } catch (JSONException error) {
            throw new AuthException("Proxy Web 响应格式无效", error);
        }
    }

    private static boolean contains(JSONArray values, String expected) {
        for (int index = 0; index < values.length(); index++) {
            if (expected.equals(values.optString(index))) {
                return true;
            }
        }
        return false;
    }

    static final class DeviceAuthorization {
        final String deviceCode;
        final String verificationUrl;
        final int expiresInSeconds;
        final int intervalSeconds;

        DeviceAuthorization(
                String deviceCode,
                String verificationUrl,
                int expiresInSeconds,
                int intervalSeconds) {
            this.deviceCode = deviceCode;
            this.verificationUrl = verificationUrl;
            this.expiresInSeconds = expiresInSeconds;
            this.intervalSeconds = intervalSeconds;
        }
    }

    static final class DevicePollResult {
        enum Status {
            AUTHORIZED,
            PENDING,
            SLOW_DOWN
        }

        final Status status;
        final int nextPollDelaySeconds;
        final LoginResult loginResult;

        private DevicePollResult(
                Status status,
                int nextPollDelaySeconds,
                LoginResult loginResult) {
            this.status = status;
            this.nextPollDelaySeconds = nextPollDelaySeconds;
            this.loginResult = loginResult;
        }

        static DevicePollResult authorized(LoginResult result) {
            return new DevicePollResult(Status.AUTHORIZED, 0, result);
        }

        static DevicePollResult pending(int nextPollDelaySeconds) {
            return new DevicePollResult(Status.PENDING, nextPollDelaySeconds, null);
        }

        static DevicePollResult slowDown(int nextPollDelaySeconds) {
            return new DevicePollResult(Status.SLOW_DOWN, nextPollDelaySeconds, null);
        }
    }

    static final class LoginResult {
        final String username;
        final long keyVersion;
        final long expiresAt;
        final String privateKeyPem;
        final String proxyIdentityPublicKeyPem;

        LoginResult(
                String username,
                long keyVersion,
                long expiresAt,
                String privateKeyPem,
                String proxyIdentityPublicKeyPem) {
            this.username = username;
            this.keyVersion = keyVersion;
            this.expiresAt = expiresAt;
            this.privateKeyPem = privateKeyPem;
            this.proxyIdentityPublicKeyPem = proxyIdentityPublicKeyPem;
        }
    }

    static final class CancelledException extends AuthException {
        CancelledException() {
            super("设备登录已取消");
        }
    }

    static class AuthException extends Exception {
        AuthException(String message) {
            super(message);
        }

        AuthException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final class Response {
        final int status;
        final byte[] body;
        final int retryAfterSeconds;

        Response(int status, byte[] body, int retryAfterSeconds) {
            this.status = status;
            this.body = body;
            this.retryAfterSeconds = retryAfterSeconds;
        }
    }
}
