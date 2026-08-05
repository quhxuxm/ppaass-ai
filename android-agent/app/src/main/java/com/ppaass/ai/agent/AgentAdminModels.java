package com.ppaass.ai.agent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class AgentAdminModels {
    private AgentAdminModels() {
    }

    static final class KeyRequest {
        final String id;
        final String username;
        final String displayName;
        final String avatarUrl;
        final String email;
        final List<String> proxyAddressIds;
        final String message;
        final String kind;
        final long requestedAt;

        KeyRequest(
                String id,
                String username,
                String displayName,
                String avatarUrl,
                String email,
                List<String> proxyAddressIds,
                String message,
                String kind,
                long requestedAt) {
            this.id = id;
            this.username = username;
            this.displayName = displayName;
            this.avatarUrl = avatarUrl;
            this.email = email;
            this.proxyAddressIds = immutableCopy(proxyAddressIds);
            this.message = message;
            this.kind = kind;
            this.requestedAt = requestedAt;
        }

        String title() {
            return displayName.isEmpty() ? username : displayName;
        }
    }

    static final class ProxyAddress {
        final String id;
        final String label;
        final String address;
        final boolean enabled;

        ProxyAddress(String id, String label, String address, boolean enabled) {
            this.id = id;
            this.label = label;
            this.address = address;
            this.enabled = enabled;
        }

        String title() {
            return label.isEmpty() ? address : label;
        }
    }

    static final class Dashboard {
        final List<KeyRequest> requests;
        final List<ProxyAddress> proxyAddresses;

        Dashboard(List<KeyRequest> requests, List<ProxyAddress> proxyAddresses) {
            this.requests = immutableCopy(requests);
            this.proxyAddresses = immutableCopy(proxyAddresses);
        }
    }

    private static <T> List<T> immutableCopy(List<T> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }
}
