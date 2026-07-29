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
        } else {
            Log.i(TAG, "No persistent Agent login to restore");
        }
    }
}
