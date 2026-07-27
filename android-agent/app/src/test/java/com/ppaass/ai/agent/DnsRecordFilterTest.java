package com.ppaass.ai.agent;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

public class DnsRecordFilterTest {
    @Test
    public void matchesAllWhitespaceSeparatedTermsAcrossRecordFields() {
        assertTrue(DnsRecordFilter.matches(
                "example 203.0.113",
                "api.example.com",
                Arrays.asList("203.0.113.8"),
                "10.0.0.2:53000",
                "1.1.1.1:53",
                "agent",
                "A",
                "NOERROR",
                12,
                false));
        assertFalse(DnsRecordFilter.matches(
                "example missing",
                "api.example.com",
                Arrays.asList("203.0.113.8"),
                "10.0.0.2:53000",
                "1.1.1.1:53",
                "agent",
                "A",
                "NOERROR",
                12,
                false));
    }

    @Test
    public void matchesChineseAndEnglishStatusResolverAliases() {
        assertTrue(matches("成功 cache"));
        assertTrue(matches("success 缓存"));
        assertTrue(matches("NOERROR agent-cache"));
        assertFalse(matches("timeout"));
    }

    @Test
    public void matchesClientUpstreamTypeDurationAndDirectAliasCaseInsensitively() {
        assertTrue(matches("10.0.0.2 1.1.1.1 a 12"));
        assertTrue(matches("DIRECT"));
        assertTrue(matches("已直连"));
    }

    private static boolean matches(String filter) {
        return DnsRecordFilter.matches(
                filter,
                "api.example.com",
                Arrays.asList("203.0.113.8"),
                "10.0.0.2:53000",
                "1.1.1.1:53",
                "agent-cache",
                "A",
                "NOERROR",
                12,
                true);
    }
}
