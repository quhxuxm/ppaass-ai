package com.ppaass.ai.agent;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class ServiceReloadPolicyTest {
    @Test
    public void directRuleUpdateReloadsOnlyAConfirmedLiveService() {
        assertTrue(MainActivityServiceState.serviceWasRunningForRuleReload(true, true));
        assertFalse(MainActivityServiceState.serviceWasRunningForRuleReload(true, false));
        assertFalse(MainActivityServiceState.serviceWasRunningForRuleReload(false, true));
        assertFalse(MainActivityServiceState.serviceWasRunningForRuleReload(false, false));
    }

    @Test
    public void httpReloadFailureGetsOnePreservingRecoveryAttempt() {
        assertTrue(PpaassHttpProxyService.reloadFailureShouldScheduleRetry(true, true));
        assertFalse(PpaassHttpProxyService.reloadFailureShouldScheduleRetry(false, true));
        assertFalse(PpaassHttpProxyService.reloadFailureShouldScheduleRetry(true, false));
    }

    @Test
    public void vpnReloadRecognizesEveryLiveOrStartingOwner() {
        assertTrue(PpaassVpnService.vpnWasRunningForReload(
                true, false, false, false, false));
        assertTrue(PpaassVpnService.vpnWasRunningForReload(
                false, true, false, false, false));
        assertTrue(PpaassVpnService.vpnWasRunningForReload(
                false, false, true, false, false));
        assertTrue(PpaassVpnService.vpnWasRunningForReload(
                false, false, false, true, false));
        assertTrue(PpaassVpnService.vpnWasRunningForReload(
                false, false, false, false, true));
        assertFalse(PpaassVpnService.vpnWasRunningForReload(
                false, false, false, false, false));
    }
}
