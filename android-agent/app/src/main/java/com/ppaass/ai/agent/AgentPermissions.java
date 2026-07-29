package com.ppaass.ai.agent;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

final class AgentPermissions {
    static final String PACKET_CAPTURE = "agent.packet_capture";
    static final String CONFIG_VIEW = "agent.config.view";
    static final String EGRESS_EDIT = "agent.egress.edit";
    static final String RUNTIME_THREADS_EDIT = "agent.runtime_threads.edit";

    static final String ROLE_USER = "user";
    static final String ROLE_ADMIN = "admin";

    private AgentPermissions() {
    }

    static boolean isSupportedRole(String role) {
        return ROLE_USER.equals(role) || ROLE_ADMIN.equals(role);
    }

    static boolean isValidPermission(String permission) {
        if (permission == null || permission.isEmpty() || permission.length() > 128) {
            return false;
        }
        for (int index = 0; index < permission.length(); index++) {
            char value = permission.charAt(index);
            boolean valid = value >= 'a' && value <= 'z'
                    || value >= 'A' && value <= 'Z'
                    || value >= '0' && value <= '9'
                    || value == '.'
                    || value == '_'
                    || value == '-'
                    || value == ':';
            if (!valid) {
                return false;
            }
        }
        return true;
    }

    static Set<String> immutableCopy(Collection<String> permissions) {
        LinkedHashSet<String> copy = new LinkedHashSet<>();
        if (permissions != null) {
            for (String permission : permissions) {
                if (isValidPermission(permission)) {
                    copy.add(permission);
                }
            }
        }
        return Collections.unmodifiableSet(copy);
    }

    static boolean allows(String role, Collection<String> permissions, String permission) {
        return ROLE_ADMIN.equals(role)
                || permissions != null && permissions.contains(permission);
    }
}
