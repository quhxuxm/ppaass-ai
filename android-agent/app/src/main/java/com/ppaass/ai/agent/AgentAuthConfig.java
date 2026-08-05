package com.ppaass.ai.agent;

import android.content.Context;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Properties;

final class AgentAuthConfig {
    private static final String ASSET_NAME = "agent.properties";
    private static final String PROXY_REGISTRY_URL_KEY = "proxy_registry_url";

    private AgentAuthConfig() {
    }

    static String proxyRegistryUrl(Context context) throws IOException {
        Properties properties = new Properties();
        try (InputStream input = context.getAssets().open(ASSET_NAME)) {
            properties.load(input);
        }
        String value = properties.getProperty(PROXY_REGISTRY_URL_KEY);
        try {
            return normalizeProxyRegistryUrl(value);
        } catch (IllegalArgumentException error) {
            throw new IOException("Agent 认证服务配置无效，请联系管理员", error);
        }
    }

    static String registrationUrl(Context context) throws IOException {
        return proxyRegistryUrl(context) + "/";
    }

    static String resolveServiceRelativeUrl(String baseUrl, String relativeUrl) {
        String normalizedBase = normalizeProxyRegistryUrl(baseUrl);
        if (relativeUrl == null || relativeUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("missing service-relative URL");
        }

        final URI relative;
        try {
            relative = new URI(relativeUrl.trim());
        } catch (URISyntaxException error) {
            throw new IllegalArgumentException("invalid service-relative URL", error);
        }
        String rawPath = relative.getRawPath();
        if (relative.isAbsolute()
                || relative.getRawAuthority() != null
                || relative.getRawUserInfo() != null
                || rawPath == null
                || !rawPath.startsWith("/")
                || rawPath.startsWith("//")) {
            throw new IllegalArgumentException("URL must be relative to the configured service");
        }
        return normalizedBase + relative;
    }

    static String normalizeProxyRegistryUrl(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("missing proxy_registry_url");
        }

        final URI parsed;
        try {
            parsed = new URI(value.trim());
        } catch (URISyntaxException error) {
            throw new IllegalArgumentException("invalid proxy_registry_url", error);
        }

        String scheme = parsed.getScheme();
        String host = parsed.getHost();
        if (scheme == null || host == null) {
            throw new IllegalArgumentException("proxy_registry_url must include scheme and host");
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new IllegalArgumentException("unsupported proxy_registry_url scheme");
        }
        if (parsed.getRawUserInfo() != null
                || parsed.getRawQuery() != null
                || parsed.getRawFragment() != null
                || !(parsed.getRawPath() == null
                || parsed.getRawPath().isEmpty()
                || "/".equals(parsed.getRawPath()))) {
            throw new IllegalArgumentException("proxy_registry_url must be a service root");
        }
        try {
            return new URI(
                    scheme,
                    null,
                    host.toLowerCase(Locale.ROOT),
                    parsed.getPort(),
                    null,
                    null,
                    null).toString();
        } catch (URISyntaxException error) {
            throw new IllegalArgumentException("invalid proxy_registry_url", error);
        }
    }

    static boolean isLoopbackHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        if ("localhost".equals(normalized)
                || "::1".equals(normalized)
                || "[::1]".equals(normalized)) {
            return true;
        }
        String[] octets = normalized.split("\\.", -1);
        if (octets.length != 4 || !"127".equals(octets[0])) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                return false;
            }
            int value = 0;
            for (int index = 0; index < octet.length(); index++) {
                char character = octet.charAt(index);
                if (character < '0' || character > '9') {
                    return false;
                }
                value = value * 10 + character - '0';
            }
            if (value > 255) {
                return false;
            }
        }
        return true;
    }
}
