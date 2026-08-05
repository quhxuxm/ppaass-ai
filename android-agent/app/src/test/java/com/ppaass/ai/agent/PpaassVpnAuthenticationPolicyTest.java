package com.ppaass.ai.agent;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class PpaassVpnAuthenticationPolicyTest {
    @Test
    public void onlyCleanupActionsCanRunWithoutAuthentication() {
        assertFalse(PpaassVpnService.actionRequiresAuthentication(
                PpaassVpnService.ACTION_STOP));
        assertFalse(PpaassVpnService.actionRequiresAuthentication(
                PpaassVpnService.ACTION_STOP_MOCK_GEO));

        assertTrue(PpaassVpnService.actionRequiresAuthentication(
                PpaassVpnService.ACTION_START));
        assertTrue(PpaassVpnService.actionRequiresAuthentication(
                PpaassVpnService.ACTION_RELOAD));
        assertTrue(PpaassVpnService.actionRequiresAuthentication(
                PpaassVpnService.ACTION_START_MOCK_GEO));
        assertTrue(PpaassVpnService.actionRequiresAuthentication(
                PpaassVpnService.ACTION_UPDATE_MOCK_GEO));
        assertTrue(PpaassVpnService.actionRequiresAuthentication(null));
    }
}
