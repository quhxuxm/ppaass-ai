package com.ppaass.ai.agent;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicBoolean;

public class AgentAuthenticationCoordinatorTest {
    @Before
    public void resetCoordinator() {
        AgentAuthenticationCoordinator.cancelAll();
    }

    @Test
    public void onlyNewestAttemptCanCommit() throws Exception {
        long stale = AgentAuthenticationCoordinator.begin();
        long current = AgentAuthenticationCoordinator.begin();
        AtomicBoolean staleActionRan = new AtomicBoolean();
        AtomicBoolean currentActionRan = new AtomicBoolean();

        assertFalse(AgentAuthenticationCoordinator.commitIfCurrent(
                stale,
                () -> staleActionRan.set(true)));
        assertTrue(AgentAuthenticationCoordinator.commitIfCurrent(
                current,
                () -> currentActionRan.set(true)));

        assertFalse(staleActionRan.get());
        assertTrue(currentActionRan.get());
        assertTrue(AgentAuthenticationCoordinator.isLatest(current));
    }

    @Test
    public void destroyedActivityCanCancelItsPendingCommit() throws Exception {
        long attempt = AgentAuthenticationCoordinator.begin();
        AtomicBoolean actionRan = new AtomicBoolean();

        assertTrue(AgentAuthenticationCoordinator.cancel(attempt));
        assertFalse(AgentAuthenticationCoordinator.commitIfCurrent(
                attempt,
                () -> actionRan.set(true)));
        assertFalse(actionRan.get());
    }
}
