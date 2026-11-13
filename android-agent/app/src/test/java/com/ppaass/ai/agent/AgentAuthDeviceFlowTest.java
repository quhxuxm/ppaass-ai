package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class AgentAuthDeviceFlowTest {
    @Test
    public void pendingPollHonorsConfiguredIntervalAndRetryAfter() {
        assertEquals(5, AgentAuthClient.devicePollDelaySeconds(5, 2));
        assertEquals(9, AgentAuthClient.devicePollDelaySeconds(5, 9));
    }

    @Test
    public void pollDelayIsBounded() {
        assertEquals(1, AgentAuthClient.devicePollDelaySeconds(0, 0));
        assertEquals(300, AgentAuthClient.devicePollDelaySeconds(299, 999));
    }
}
