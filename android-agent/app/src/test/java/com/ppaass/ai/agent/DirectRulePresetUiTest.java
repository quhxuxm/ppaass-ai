package com.ppaass.ai.agent;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

public class DirectRulePresetUiTest {
    @Test
    public void teamsPresetIncludesCurrentServiceAndTokenRefreshDomains() {
        List<String> rules = Arrays.asList(DirectRulePresetUi.teamsRules());

        assertTrue(rules.contains("teams.cloud.microsoft"));
        assertTrue(rules.contains("*.teams.cloud.microsoft"));
        assertTrue(rules.contains("login.microsoftonline.com"));
        assertTrue(rules.contains("device.login.microsoftonline.com"));
        assertTrue(rules.contains("*.microsoftonline.com"));
        assertTrue(rules.contains("*.msftauth.net"));
        assertTrue(rules.contains("*.phonefactor.net"));
        assertTrue(rules.contains("login.live.com"));
        assertTrue(rules.contains("*.cloud.microsoft"));
        assertTrue(rules.contains("20.190.128.0/18"));
        assertTrue(rules.contains("52.112.0.0/14"));
        assertTrue(rules.contains("2603:1063::/38"));
    }
}
