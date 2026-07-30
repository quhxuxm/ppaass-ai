package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Set;

public final class AgentAdminRequestStateTest {
    @Test
    public void sameAdministratorOnlyNotifiesNewRequestIds() {
        assertEquals(
                Set.of("req_new"),
                AgentAdminRequestStore.newlyPendingIds(
                        "admin",
                        Set.of("req_old"),
                        "admin",
                        Set.of("req_old", "req_new")));
    }

    @Test
    public void replacementAtSameCountStillDetectsNewRequest() {
        assertEquals(
                Set.of("req_two"),
                AgentAdminRequestStore.newlyPendingIds(
                        "admin",
                        Set.of("req_one"),
                        "admin",
                        Set.of("req_two")));
    }

    @Test
    public void anotherAdministratorGetsAnIndependentFirstNotification() {
        assertEquals(
                Set.of("req_one"),
                AgentAdminRequestStore.newlyPendingIds(
                        "first-admin",
                        Set.of("req_one"),
                        "second-admin",
                        Set.of("req_one")));
        assertTrue(AgentAdminRequestStore.newlyPendingIds(
                "admin",
                Set.of("req_one"),
                "admin",
                Set.of("req_one")).isEmpty());
    }
}
