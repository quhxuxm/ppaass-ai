package com.ppaass.ai.agent;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

public class DirectRuleDomainsTest {
    @Test
    public void convertsOnlyDomainsWithARegistrableParent() {
        assertEquals("*.example.com", DirectRuleDomains.toDirectRule("api.example.com"));
        assertEquals("*.service.example.com", DirectRuleDomains.toDirectRule("a.service.example.com."));
        assertEquals("example.com", DirectRuleDomains.toDirectRule("example.com"));
        assertEquals("foo.co.uk", DirectRuleDomains.toDirectRule("foo.co.uk"));
        assertEquals("tenant.github.io", DirectRuleDomains.toDirectRule("tenant.github.io"));
    }

    @Test
    public void collapsesSiblingDomainsAndMatchesWildcardCoverage() {
        assertEquals(
                Arrays.asList("*.example.com", "example.net"),
                DirectRuleDomains.toDirectRules(Arrays.asList(
                        "api.example.com",
                        "www.example.com",
                        "example.net")));
        assertTrue(DirectRuleDomains.ruleCoversDomain("*.example.com", "api.example.com"));
        assertFalse(DirectRuleDomains.ruleCoversDomain("*.example.com", "example.com"));
        assertTrue(DirectRuleDomains.ruleCoversDomain("example.com", "EXAMPLE.COM."));
    }

    @Test
    public void includesOnlyValidResolvedIpAddresses() {
        assertEquals(
                Arrays.asList("*.example.com", "203.0.113.8", "2001:db8::8"),
                DirectRuleDomains.toDirectRules(
                        Arrays.asList("api.example.com"),
                        Arrays.asList(
                                "203.0.113.8",
                                "2001:db8::8",
                                "alias.example.com",
                                "203.0.113.8",
                                "203.0.113.999")));
    }
}
