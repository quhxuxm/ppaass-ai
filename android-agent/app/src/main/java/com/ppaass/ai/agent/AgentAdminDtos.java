package com.ppaass.ai.agent;

import java.util.List;

final class AgentAdminDtos {
    private AgentAdminDtos() {
    }

    static final class Account {
        public String account_id;
        public String login_name;
        public String display_name;
        public String avatar_url;
        public String email;

        public Account() {
        }
    }

    static final class KeyRequest {
        public String request_id;
        public Account account;
        public List<String> proxy_address_ids;
        public String request_message;
        public String kind;
        public String status;
        public Long requested_at;

        public KeyRequest() {
        }
    }

    static final class KeyRequestsResponse {
        public List<KeyRequest> requests;

        public KeyRequestsResponse() {
        }
    }

    static final class ProxyAddress {
        public String proxy_address_id;
        public String label;
        public String address;
        public Boolean enabled;

        public ProxyAddress() {
        }
    }

    static final class ProxyAddressesResponse {
        public List<ProxyAddress> proxy_addresses;

        public ProxyAddressesResponse() {
        }
    }

    static final class ApproveKeyRequest {
        public final long expires_at;
        public final List<String> proxy_address_ids;
        public final String reason;

        ApproveKeyRequest(
                long expiresAt,
                List<String> proxyAddressIds,
                String reason) {
            this.expires_at = expiresAt;
            this.proxy_address_ids = proxyAddressIds;
            this.reason = reason;
        }
    }

    static final class RejectKeyRequest {
        public final String reason;

        RejectKeyRequest(String reason) {
            this.reason = reason;
        }
    }

    static final class DecisionResponse {
        public KeyRequest request;
        public Object user;

        public DecisionResponse() {
        }
    }
}
