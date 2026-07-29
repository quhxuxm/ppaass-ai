package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AgentAuthSessionPolicyTest {
    @Test
    public void authenticatedIdentityDoesNotExpireFromLocalClock() {
        AgentAuthSession.authenticate("alice", 3, 1);
        try {
            assertTrue(AgentAuthSession.isActive(null));
            assertTrue(ManagedCredentials.isRestorableMetadata("alice", 3, 1));
        } finally {
            AgentAuthSession.clear();
        }
    }

    @Test
    public void missingIdentityIsNotAuthenticated() {
        assertFalse(AgentAuthSession.hasAuthenticatedIdentity("", 3));
        assertFalse(AgentAuthSession.hasAuthenticatedIdentity(null, 3));
        assertFalse(AgentAuthSession.hasAuthenticatedIdentity("alice", -1));
    }

    @Test
    public void onlyVerifiedNativeStatusesChangeTheDisplayedServerState() {
        assertEquals(
                -1,
                AgentAuthSession.serverStatusForNativeStatus(
                        NativeAgent.AUTHENTICATION_UNCONFIRMED));
        assertEquals(
                0,
                AgentAuthSession.serverStatusForNativeStatus(
                        NativeAgent.AUTHENTICATION_VERIFIED_ACTIVE));
        assertEquals(
                1,
                AgentAuthSession.serverStatusForNativeStatus(
                        NativeAgent.AUTHENTICATION_USER_EXPIRED));
        assertEquals(
                2,
                AgentAuthSession.serverStatusForNativeStatus(
                        NativeAgent.AUTHENTICATION_USER_DISABLED));
        assertEquals(-1, AgentAuthSession.serverStatusForNativeStatus(99));
    }
}
