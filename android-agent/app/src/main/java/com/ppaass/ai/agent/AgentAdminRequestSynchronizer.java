package com.ppaass.ai.agent;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.util.List;

final class AgentAdminRequestSynchronizer {
    private static final String TAG = "PpaassAdminRequests";

    private AgentAdminRequestSynchronizer() {
    }

    static void synchronize(Context context, String accessToken) {
        if (!AgentAuthSession.isAdmin(context)) {
            clear(context);
            return;
        }
        try {
            String baseUrl = AgentAuthConfig.proxyRegistryUrl(context);
            List<AgentAdminModels.KeyRequest> requests =
                    new AgentAdminClient(context, baseUrl)
                            .listKeyRequests(accessToken);
            AgentAdminRequestStore.Update update =
                    AgentAdminRequestStore.replace(
                            context,
                            AgentAuthSession.username(),
                            requests);
            if (update.changed()) {
                AgentAdminRequestNotifier.update(
                        context,
                        update.pendingCount,
                        update.hasNewRequests());
            }
            Log.i(TAG, "Administrator key requests synchronized");
        } catch (AgentAdminClient.AdminException | IOException | RuntimeException error) {
            Log.w(TAG, "Administrator key request synchronization unavailable");
        }
    }

    static void prepare(Context context) {
        AgentAdminRequestStore.prepare(
                context,
                AgentAuthSession.username(),
                AgentAuthSession.isAdmin(context));
        if (!AgentAuthSession.isAdmin(context)) {
            AgentAdminRequestNotifier.cancel(context);
        }
    }

    static void clear(Context context) {
        AgentAdminRequestStore.clear(context);
        AgentAdminRequestNotifier.cancel(context);
    }
}
