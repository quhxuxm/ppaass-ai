package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class AgentUiPermissionPolicyTest {
    @Test
    public void captureActionsFailClosedWithoutPermission() {
        assertFalse(AgentUiPermissionPolicy.captureOperationAllowed(
                false,
                false,
                false,
                true));
        assertTrue(AgentUiPermissionPolicy.captureOperationAllowed(
                true,
                false,
                false,
                true));
    }

    @Test
    public void protectedConfigKeepsStoredValueWhenEditingIsDenied() {
        assertEquals(
                "proxy.example:1234",
                AgentUiPermissionPolicy.guardedConfigValue(
                        false,
                        "proxy.example:1234",
                        "attacker.example:9999"));
        assertEquals(
                "attacker.example:9999",
                AgentUiPermissionPolicy.guardedConfigValue(
                        true,
                        "proxy.example:1234",
                        "attacker.example:9999"));
    }

    @Test
    public void roleParticipatesInPermissionFingerprint() {
        assertEquals(
                "U1111",
                AgentUiPermissionPolicy.permissionFingerprint(
                        false, true, true, true, true));
        assertEquals(
                "A1111",
                AgentUiPermissionPolicy.permissionFingerprint(
                        true, true, true, true, true));
    }
}
