package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class AgentAuthDeviceFlowTest {
    @Test
    public void pendingPollNeverRunsFasterThanConfiguredInterval() {
        assertEquals(5, AgentAuthClient.devicePollDelaySeconds(5, 2, false));
        assertEquals(9, AgentAuthClient.devicePollDelaySeconds(5, 9, false));
    }

    @Test
    public void slowDownAddsFiveSecondsAndHonorsRetryAfter() {
        assertEquals(10, AgentAuthClient.devicePollDelaySeconds(5, 0, true));
        assertEquals(17, AgentAuthClient.devicePollDelaySeconds(10, 17, true));
    }

    @Test
    public void pollDelayIsBounded() {
        assertEquals(1, AgentAuthClient.devicePollDelaySeconds(0, 0, false));
        assertEquals(300, AgentAuthClient.devicePollDelaySeconds(299, 999, true));
    }

    @Test
    public void proxyRegistryRateLimitRetriesUsingRetryAfterOrCurrentInterval() {
        assertEquals(
                5,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        429,
                        "rate_limited",
                        5,
                        0));
        assertEquals(
                17,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        429,
                        "rate_limited",
                        5,
                        17));
    }

    @Test
    public void devicePollOnlyRetriesRecognizedRateLimitResponses() {
        assertEquals(
                10,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        429,
                        "slow_down",
                        5,
                        0));
        assertEquals(
                0,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        429,
                        "unexpected",
                        5,
                        17));
        assertEquals(
                0,
                AgentAuthClient.devicePollRateLimitDelaySeconds(
                        500,
                        "rate_limited",
                        5,
                        17));
    }

}
