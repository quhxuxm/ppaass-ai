package com.ppaass.ai.agent;

import android.app.Application;
import android.util.Log;

public final class PpaassApplication extends Application {
    private static final String TAG = "PpaassApplication";

    @Override
    public void onCreate() {
        super.onCreate();
        if (AgentAuthSession.restore(this)) {
            Log.i(TAG, "Restored persistent Agent login");
            AgentPermissionConfigPolicy.RestoredProxyAction proxyAction =
                    AgentPermissionConfigPolicy.restoredProxyAction(
                            AgentSessionStore.proxyAssignmentState(this),
                            ManagedProxyAddresses.load(this));
            AgentPermissionConfigEnforcer.enforce(
                    this,
                    proxyAction
                            == AgentPermissionConfigPolicy.RestoredProxyAction.KEEP_RUNNING);
            if (proxyAction
                    == AgentPermissionConfigPolicy.RestoredProxyAction.STOP_LEGACY) {
                AgentSessionStore.recordLegacyManagedProxyAddressFailure(this);
                AgentPermissionConfigEnforcer.stopRunningAgents(this);
                Log.w(TAG, "Restored legacy login has no managed Proxy assignment state");
            } else if (proxyAction
                    == AgentPermissionConfigPolicy.RestoredProxyAction.STOP_MISSING) {
                if (!AgentSessionStore.PROXY_ASSIGNMENT_MISSING.equals(
                        AgentSessionStore.proxyAssignmentState(this))) {
                    AgentSessionStore.recordManagedProxyAddressFailure(this);
                }
                AgentPermissionConfigEnforcer.stopRunningAgents(this);
                Log.w(TAG, "Restored login has no valid managed Proxy assignment");
            }
            AgentProfileSyncManager.start(this);
        } else {
            Log.i(TAG, "No persistent Agent login to restore");
            AgentProfileSyncManager.stop();
        }
    }
}
