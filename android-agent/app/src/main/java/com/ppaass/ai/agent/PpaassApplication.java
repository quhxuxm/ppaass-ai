package com.ppaass.ai.agent;

import android.app.Application;
import android.util.Log;

public final class PpaassApplication extends Application {
    private static final String TAG = "PpaassApplication";

    @Override
    public void onCreate() {
        super.onCreate();
        AgentAuthSession.clear();
        if (!ManagedCredentials.clear(this)) {
            Log.e(
                    TAG,
                    "Failed to completely remove stale managed credentials during process start");
        }
    }
}
