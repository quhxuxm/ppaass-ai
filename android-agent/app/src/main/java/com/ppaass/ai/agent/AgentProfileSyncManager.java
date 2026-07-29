package com.ppaass.ai.agent;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

final class AgentProfileSyncManager {
    private static final String TAG = "PpaassAgentSync";
    private static final ScheduledExecutorService EXECUTOR =
            Executors.newSingleThreadScheduledExecutor(new SyncThreadFactory());

    private static Context applicationContext;
    private static ScheduledFuture<?> scheduled;
    private static long generation;

    private AgentProfileSyncManager() {
    }

    static synchronized void start(Context context) {
        applicationContext = context.getApplicationContext();
        generation++;
        cancelScheduled();
        schedule(generation, 0);
    }

    static synchronized void stop() {
        generation++;
        cancelScheduled();
    }

    static int boundedInterval(int seconds) {
        return AgentSessionStore.clampedRefresh(seconds);
    }

    private static void runSync(long expectedGeneration) {
        Context context;
        synchronized (AgentProfileSyncManager.class) {
            if (expectedGeneration != generation || applicationContext == null) {
                return;
            }
            context = applicationContext;
            scheduled = null;
        }
        if (!AgentAuthSession.isActive(context)) {
            return;
        }

        AgentSessionStore.StoredSession stored = AgentSessionStore.load(context);
        if (stored.needsRelogin || stored.accessToken.isEmpty()) {
            AgentSessionStore.recordLegacySession(context);
            return;
        }

        int nextInterval = stored.refreshSeconds;
        try {
            String baseUrl = AgentAuthConfig.proxyWebUrl(context);
            AgentAuthClient.ProfileSyncResult result =
                    new AgentAuthClient(context, baseUrl).syncProfile(
                            stored.accessToken,
                            AgentAuthSession.username());
            if (!isCurrent(expectedGeneration, context)) {
                return;
            }
            AgentAuthSession.applySynchronizedProfile(context, result);
            nextInterval = result.refreshAfterSeconds;
            Log.i(TAG, "Agent account permissions synchronized");
        } catch (AgentAuthClient.SyncException error) {
            if (!isCurrent(expectedGeneration, context)) {
                return;
            }
            if (AgentSyncFailurePolicy.requiresManagedProxyShutdown(error.failure)) {
                AgentSessionStore.recordManagedProxyAddressFailure(context);
                AgentPermissionConfigEnforcer.stopRunningAgents(context);
            } else {
                AgentSessionStore.recordSyncFailure(context, error.failure);
            }
            Log.w(TAG, "Agent account permission synchronization failed");
        } catch (IOException | RuntimeException error) {
            if (!isCurrent(expectedGeneration, context)) {
                return;
            }
            AgentSessionStore.recordSyncFailure(
                    context,
                    AgentAuthClient.SyncFailure.TRANSIENT);
            Log.w(TAG, "Agent account permission synchronization unavailable");
        }
        synchronized (AgentProfileSyncManager.class) {
            if (expectedGeneration == generation && AgentAuthSession.isActive(context)) {
                schedule(expectedGeneration, boundedInterval(nextInterval));
            }
        }
    }

    private static synchronized boolean isCurrent(
            long expectedGeneration,
            Context context) {
        return expectedGeneration == generation
                && AgentAuthSession.isActive(context);
    }

    private static void schedule(long expectedGeneration, int delaySeconds) {
        scheduled = EXECUTOR.schedule(
                () -> runSync(expectedGeneration),
                Math.max(0, delaySeconds),
                TimeUnit.SECONDS);
    }

    private static void cancelScheduled() {
        if (scheduled != null) {
            scheduled.cancel(false);
            scheduled = null;
        }
    }

    private static final class SyncThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "ppaass-agent-profile-sync");
            thread.setDaemon(true);
            return thread;
        }
    }
}
