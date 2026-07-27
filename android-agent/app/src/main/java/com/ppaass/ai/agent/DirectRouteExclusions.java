package com.ppaass.ai.agent;

import com.google.common.net.InetAddresses;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Converts direct-access IP rules into VPN route exclusions.
 *
 * <p>Domain rules stay in the native data path because their resolved addresses can change.
 * Literal IP/CIDR rules are stable and can bypass the userspace TUN stack entirely on Android 13+.
 */
final class DirectRouteExclusions {
    private DirectRouteExclusions() {
    }

    static List<Prefix> from(String mode, List<String> rules, boolean ipv6Enabled) {
        String normalizedMode = mode == null ? "" : mode.trim().toLowerCase(Locale.US);
        if ("direct_all".equals(normalizedMode)) {
            List<Prefix> result = new ArrayList<>();
            result.add(parsePrefix("0.0.0.0/0"));
            if (ipv6Enabled) {
                result.add(parsePrefix("::/0"));
            }
            return result;
        }
        if (!"rules".equals(normalizedMode)) {
            return Collections.emptyList();
        }

        LinkedHashSet<Prefix> result = new LinkedHashSet<>();
        for (String rule : rules) {
            Prefix prefix = parsePrefix(rule);
            if (prefix != null && (ipv6Enabled || prefix.address.getAddress().length == 4)) {
                result.add(prefix);
            }
        }
        return new ArrayList<>(result);
    }

    private static Prefix parsePrefix(String value) {
        String normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.startsWith("*.")) {
            return null;
        }

        String addressText = normalized;
        Integer prefixLength = null;
        int slash = normalized.indexOf('/');
        if (slash >= 0) {
            if (slash == 0 || slash == normalized.length() - 1
                    || normalized.indexOf('/', slash + 1) >= 0) {
                return null;
            }
            addressText = normalized.substring(0, slash);
            try {
                prefixLength = Integer.parseInt(normalized.substring(slash + 1));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }

        if (!InetAddresses.isInetAddress(addressText)) {
            return null;
        }
        InetAddress address = InetAddresses.forString(addressText);
        int addressBits = address.getAddress().length * 8;
        int effectivePrefix = prefixLength == null ? addressBits : prefixLength;
        if (effectivePrefix < 0 || effectivePrefix > addressBits) {
            return null;
        }
        return new Prefix(networkAddress(address, effectivePrefix), effectivePrefix);
    }

    private static InetAddress networkAddress(InetAddress address, int prefixLength) {
        byte[] bytes = address.getAddress();
        int wholeBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        if (remainingBits != 0) {
            int mask = 0xFF << (8 - remainingBits);
            bytes[wholeBytes] = (byte) (bytes[wholeBytes] & mask);
            wholeBytes++;
        }
        for (int index = wholeBytes; index < bytes.length; index++) {
            bytes[index] = 0;
        }
        try {
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException impossible) {
            throw new AssertionError("validated IP address changed length", impossible);
        }
    }

    static final class Prefix {
        final InetAddress address;
        final int length;

        Prefix(InetAddress address, int length) {
            this.address = address;
            this.length = length;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof Prefix)) {
                return false;
            }
            Prefix prefix = (Prefix) other;
            return length == prefix.length && address.equals(prefix.address);
        }

        @Override
        public int hashCode() {
            return 31 * address.hashCode() + length;
        }

        @Override
        public String toString() {
            return address.getHostAddress() + "/" + length;
        }
    }
}
