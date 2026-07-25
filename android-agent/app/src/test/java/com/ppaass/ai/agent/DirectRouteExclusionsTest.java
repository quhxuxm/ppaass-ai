package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Test;

public class DirectRouteExclusionsTest {
    @Test
    public void directAllExcludesEnabledAddressFamilies() {
        assertEquals(
                Arrays.asList("0.0.0.0/0", "0:0:0:0:0:0:0:0/0"),
                strings(DirectRouteExclusions.from("direct_all", Collections.emptyList(), true)));
        assertEquals(
                Collections.singletonList("0.0.0.0/0"),
                strings(DirectRouteExclusions.from("direct_all", Collections.emptyList(), false)));
    }

    @Test
    public void rulesOnlyExcludeLiteralIpPrefixes() {
        assertEquals(
                Arrays.asList("203.0.113.7/32", "10.0.0.0/8", "2001:db8:0:0:0:0:0:0/32"),
                strings(DirectRouteExclusions.from(
                        "rules",
                        Arrays.asList(
                                "example.com",
                                "*.example.net",
                                "203.0.113.7",
                                "10.23.45.67/8",
                                "2001:db8:abcd::7/32",
                                "10.0.0.0/99"),
                        true)));
    }

    @Test
    public void equivalentCidrsAreCanonicalizedAndDeduplicated() {
        assertEquals(
                Collections.singletonList("10.0.0.0/8"),
                strings(DirectRouteExclusions.from(
                        "rules",
                        Arrays.asList("10.23.45.67/8", "10.200.1.2/8"),
                        false)));
    }

    @Test
    public void proxyAllAndDisabledIpv6DoNotAddUnexpectedExclusions() {
        assertEquals(
                Collections.emptyList(),
                strings(DirectRouteExclusions.from(
                        "proxy_all", Collections.singletonList("203.0.113.7"), true)));
        assertEquals(
                Collections.singletonList("203.0.113.7/32"),
                strings(DirectRouteExclusions.from(
                        "rules",
                        Arrays.asList("203.0.113.7", "2001:db8::7"),
                        false)));
    }

    private static List<String> strings(List<DirectRouteExclusions.Prefix> prefixes) {
        return prefixes.stream().map(Object::toString).collect(Collectors.toList());
    }
}
