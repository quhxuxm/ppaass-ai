package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.util.Arrays;

import org.junit.Test;

public final class MainActivityDnsPanelTest {
    @Test
    public void dnsStateKeyChangesWithDirectRules() {
        String initial = MainActivityDnsPanel.dnsRecordsStateKey(
                true,
                "direct",
                Arrays.asList("*.example.com", "203.0.113.8"),
                "[{\"query\":\"api.example.com\"}]");
        String changed = MainActivityDnsPanel.dnsRecordsStateKey(
                true,
                "direct",
                Arrays.asList("*.example.net", "203.0.113.8"),
                "[{\"query\":\"api.example.com\"}]");

        assertNotEquals(initial, changed);
    }

    @Test
    public void dnsStateKeyIsStableForIdenticalInputsAndUnambiguousParts() {
        String first = MainActivityDnsPanel.dnsRecordsStateKey(
                false,
                "a|1:b",
                Arrays.asList("c", "d|2:e"),
                "[]");
        String same = MainActivityDnsPanel.dnsRecordsStateKey(
                false,
                "a|1:b",
                Arrays.asList("c", "d|2:e"),
                "[]");
        String repartitioned = MainActivityDnsPanel.dnsRecordsStateKey(
                false,
                "a",
                Arrays.asList("1:b|c", "d|2:e"),
                "[]");

        assertEquals(first, same);
        assertNotEquals(first, repartitioned);
    }
}
