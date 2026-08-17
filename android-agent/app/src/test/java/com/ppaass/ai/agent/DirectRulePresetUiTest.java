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
    }
}
