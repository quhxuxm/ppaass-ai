package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Collections;
import java.util.Set;

public class AgentPermissionsTest {
    @Test
    public void administratorInherentlyHasEveryAgentCapability() {
        assertTrue(AgentPermissions.allows(
                AgentPermissions.ROLE_ADMIN,
                Collections.emptySet(),
                AgentPermissions.PACKET_CAPTURE));
        assertTrue(AgentPermissions.allows(
                AgentPermissions.ROLE_ADMIN,
                Collections.emptySet(),
                AgentPermissions.RUNTIME_THREADS_EDIT));
    }

    @Test
    public void ordinaryUserDefaultsToDeniedAndOnlyGetsAssignedPermission() {
        assertFalse(AgentPermissions.allows(
                AgentPermissions.ROLE_USER,
                Collections.emptySet(),
                AgentPermissions.CONFIG_VIEW));
        assertTrue(AgentPermissions.allows(
                AgentPermissions.ROLE_USER,
                Set.of(AgentPermissions.EGRESS_EDIT),
                AgentPermissions.EGRESS_EDIT));
        assertFalse(AgentPermissions.allows(
                AgentPermissions.ROLE_USER,
                Set.of(AgentPermissions.EGRESS_EDIT),
                AgentPermissions.PACKET_CAPTURE));
    }

    @Test
    public void permissionCodesCannotInjectStoredSetSeparators() {
        assertFalse(AgentPermissions.isValidPermission("agent.config.view\nother"));
        assertTrue(AgentPermissions.isValidPermission(
                AgentPermissions.RUNTIME_THREADS_EDIT));
    }

    @Test
    public void profileRefreshIntervalIsAlwaysBounded() {
        assertEquals(60, AgentProfileSyncManager.boundedInterval(1));
        assertEquals(300, AgentProfileSyncManager.boundedInterval(300));
        assertEquals(3600, AgentProfileSyncManager.boundedInterval(99_999));
    }
}
