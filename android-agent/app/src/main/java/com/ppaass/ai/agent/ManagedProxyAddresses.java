package com.ppaass.ai.agent;

import android.content.Context;
import android.content.SharedPreferences;

import com.google.common.net.InetAddresses;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

final class ManagedProxyAddresses {
    static final String PREF_PROXY_ADDRESSES = "managed_proxy_addresses";
    private static final int MAX_ADDRESSES = 32;
    private static final int MAX_ADDRESS_LENGTH = 512;

    private ManagedProxyAddresses() {
    }

    static List<String> require(List<String> values)
            throws AgentAuthClient.AuthException {
        List<String> normalized = normalize(values);
        if (normalized.isEmpty()) {
            throw new AgentAuthClient.AuthException(
                    "Proxy Web 未为当前账户分配 Proxy 地址");
        }
        return normalized;
    }

    static List<String> normalize(List<String> values)
            throws AgentAuthClient.AuthException {
        if (values == null || values.size() > MAX_ADDRESSES) {
            throw invalidResponse();
        }
        ArrayList<String> normalized = new ArrayList<>();
        LinkedHashSet<String> unique = new LinkedHashSet<>();
        for (String value : values) {
            String endpoint = normalizeEndpoint(value);
            if (!unique.add(endpoint.toLowerCase(Locale.US))) {
                throw invalidResponse();
            }
            normalized.add(endpoint);
        }
        return Collections.unmodifiableList(normalized);
    }

    static String serialize(List<String> addresses) {
        return String.join("\n", addresses);
    }

    static List<String> load(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(
                ManagedCredentials.PREFERENCES_NAME,
                Context.MODE_PRIVATE);
        String serialized;
        try {
            serialized = preferences.getString(PREF_PROXY_ADDRESSES, "");
        } catch (ClassCastException error) {
            return Collections.emptyList();
        }
        if (serialized == null || serialized.isEmpty()) {
            return Collections.emptyList();
        }
        try {
            return normalize(List.of(serialized.split("\n", -1)));
        } catch (AgentAuthClient.AuthException error) {
            return Collections.emptyList();
        }
    }

    private static String normalizeEndpoint(String value)
            throws AgentAuthClient.AuthException {
        if (value == null
                || value.isEmpty()
                || value.length() > MAX_ADDRESS_LENGTH
                || !value.equals(value.trim())) {
            throw invalidResponse();
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isISOControl(character)
                    || Character.isWhitespace(character)
                    || character == '/'
                    || character == '@'
                    || character == '#'
                    || character == '?') {
                throw invalidResponse();
            }
        }
        int portSeparator = value.lastIndexOf(':');
        if (portSeparator <= 0 || portSeparator == value.length() - 1) {
            throw invalidResponse();
        }
        String host = value.substring(0, portSeparator);
        if (host.startsWith("[")) {
            if (!host.endsWith("]") || host.length() < 3) {
                throw invalidResponse();
            }
            String ipv6 = host.substring(1, host.length() - 1);
            if (!ipv6.contains(":") || !InetAddresses.isInetAddress(ipv6)) {
                throw invalidResponse();
            }
        } else {
            if (!validHostname(host)) {
                throw invalidResponse();
            }
        }
        String portText = value.substring(portSeparator + 1);
        int port = 0;
        for (int index = 0; index < portText.length(); index++) {
            char digit = portText.charAt(index);
            if (digit < '0' || digit > '9') {
                throw invalidResponse();
            }
            port = port * 10 + digit - '0';
            if (port > 65_535) {
                throw invalidResponse();
            }
        }
        if (port == 0) {
            throw invalidResponse();
        }
        return value;
    }

    private static boolean validHostname(String host) {
        if (host.isEmpty() || host.length() > 253 || host.indexOf(':') >= 0) {
            return false;
        }
        String[] labels = host.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty()
                    || label.length() > 63
                    || !asciiAlphaNumeric(label.charAt(0))
                    || !asciiAlphaNumeric(label.charAt(label.length() - 1))) {
                return false;
            }
            for (int index = 0; index < label.length(); index++) {
                char character = label.charAt(index);
                if (!asciiAlphaNumeric(character) && character != '-') {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean asciiAlphaNumeric(char character) {
        return character >= 'a' && character <= 'z'
                || character >= 'A' && character <= 'Z'
                || character >= '0' && character <= '9';
    }

    private static AgentAuthClient.AuthException invalidResponse() {
        return new AgentAuthClient.AuthException("Proxy Web 返回的 Proxy 地址无效");
    }
}
