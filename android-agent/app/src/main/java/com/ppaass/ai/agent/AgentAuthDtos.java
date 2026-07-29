package com.ppaass.ai.agent;

import java.util.List;

final class AgentAuthDtos {
    private AgentAuthDtos() {
    }

    static final class PasswordLoginRequest {
        public final String username;
        public final String password;

        PasswordLoginRequest(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    static final class DeviceStartRequest {
        public final String platform;
        public final String client_name;

        DeviceStartRequest(String platform, String clientName) {
            this.platform = platform;
            this.client_name = clientName;
        }
    }

    static final class DeviceTokenRequest {
        public final String device_code;

        DeviceTokenRequest(String deviceCode) {
            this.device_code = deviceCode;
        }
    }

    static final class DeviceStartResponse {
        public String device_code;
        public String user_code;
        public String verification_uri;
        public String verification_uri_complete;
        public Long expires_in;
        public Long interval;

        public DeviceStartResponse() {
        }
    }

    static final class Account {
        public String account_id;
        public String login_name;
        public String role;
        public String status;
        public String linked_username;

        public Account() {
        }
    }

    static final class Profile {
        public String username;
        public List<String> permissions;
        public List<String> proxy_addresses;
        public Boolean enabled;
        public Long key_version;
        public Long expires_at;

        public Profile() {
        }
    }

    static final class CredentialResponse {
        public Account account;
        public Profile profile;
        public String public_key_pem;
        public String proxy_identity_public_key_pem;
        public String private_key_pem;
        public String csrf_token;
        public Long session_expires_at;
        public String agent_access_token;
        public Long agent_access_token_expires_at;
        public Long refresh_after_seconds;

        public CredentialResponse() {
        }
    }

    static final class ProfileSyncResponse {
        public Account account;
        public Profile profile;
        public String key_state;
        public String agent_access_token;
        public Long agent_access_token_expires_at;
        public Long refresh_after_seconds;

        public ProfileSyncResponse() {
        }
    }

    static final class ApiErrorEnvelope {
        public ApiError error;

        public ApiErrorEnvelope() {
        }
    }

    static final class ApiError {
        public String code;
        public String message;

        public ApiError() {
        }
    }
}
