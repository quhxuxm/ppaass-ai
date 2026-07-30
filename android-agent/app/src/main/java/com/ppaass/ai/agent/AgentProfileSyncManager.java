package com.ppaass.ai.agent;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;

final class AgentProfileSyncManager {
    private static final String TAG = "PpaassAgentEvents";
    private static final int MIN_RECONNECT_SECONDS = 1;
    private static final int MAX_RECONNECT_SECONDS = 60;
    private static final ExecutorService EXECUTOR =
            Executors.newSingleThreadExecutor(new EventThreadFactory());

    private static Context applicationContext;
    private static Future<?> worker;
    private static AgentServerEventClient activeClient;
    private static long generation;

    private AgentProfileSyncManager() {
    }

    static synchronized void start(Context context) {
        applicationContext = context.getApplicationContext();
        AgentAdminRequestSynchronizer.prepare(applicationContext);
        generation++;
        cancelWorker();
        long expectedGeneration = generation;
        worker = EXECUTOR.submit(() -> runEventLoop(expectedGeneration));
    }

    static synchronized void stop() {
        Context context = applicationContext;
        generation++;
        cancelWorker();
        applicationContext = null;
        if (context != null) {
            AgentAdminRequestSynchronizer.clear(context);
        }
    }

    static synchronized void requestImmediateSync(Context context) {
        applicationContext = context.getApplicationContext();
        if (!AgentAuthSession.isActive(applicationContext)) {
            return;
        }
        if (worker == null || worker.isDone()) {
            start(applicationContext);
        }
    }

    static int nextReconnectDelay(int currentSeconds) {
        return Math.min(
                Math.max(MIN_RECONNECT_SECONDS, currentSeconds) * 2,
                MAX_RECONNECT_SECONDS);
    }

    private static void runEventLoop(long expectedGeneration) {
        int reconnectSeconds = MIN_RECONNECT_SECONDS;
        while (isCurrent(expectedGeneration)) {
            Context context = currentContext(expectedGeneration);
            if (context == null) {
                return;
            }
            AgentSessionStore.StoredSession stored = AgentSessionStore.load(context);
            if (stored.needsRelogin || stored.accessToken.isEmpty()) {
                AgentSessionStore.recordLegacySession(context);
                return;
            }

            AgentServerEventClient client;
            try {
                client = new AgentServerEventClient(
                        context,
                        AgentAuthConfig.proxyRegistryUrl(context));
            } catch (IOException | RuntimeException error) {
                recordConnectionFailure(context, error);
                if (!waitForReconnect(expectedGeneration, reconnectSeconds)) {
                    return;
                }
                reconnectSeconds = nextReconnectDelay(reconnectSeconds);
                continue;
            }
            setActiveClient(expectedGeneration, client);
            try {
                reconnectSeconds = MIN_RECONNECT_SECONDS;
                client.listen(
                        stored.accessToken,
                        event -> handleEvent(context, expectedGeneration, event));
            } catch (AgentServerEventClient.EventException error) {
                if (isCurrent(expectedGeneration)) {
                    AgentSessionStore.recordSyncFailure(
                            context,
                            error.unauthorized
                                    ? AgentAuthClient.SyncFailure.UNAUTHORIZED
                                    : AgentAuthClient.SyncFailure.TRANSIENT);
                    Log.w(TAG, "Agent SSE event stream unavailable", error);
                }
            } finally {
                clearActiveClient(client);
            }
            if (!waitForReconnect(expectedGeneration, reconnectSeconds)) {
                return;
            }
            reconnectSeconds = nextReconnectDelay(reconnectSeconds);
        }
    }

    private static boolean handleEvent(
            Context context,
            long expectedGeneration,
            String event) {
        if (!isCurrent(expectedGeneration)) {
            return false;
        }
        if (AgentServerEventClient.ADMIN_KEY_REQUESTS_CHANGED.equals(event)) {
            synchronizeAdminRequests(context);
            return true;
        }
        if (AgentServerEventClient.SYNC.equals(event)
                || AgentServerEventClient.PROFILE_CHANGED.equals(event)
                || AgentServerEventClient.PROFILES_CHANGED.equals(event)
                || AgentServerEventClient.KEY_REQUEST_CHANGED.equals(event)) {
            return synchronizeProfile(context, expectedGeneration);
        }
        return true;
    }

    private static boolean synchronizeProfile(
            Context context,
            long expectedGeneration) {
        AgentSessionStore.StoredSession stored = AgentSessionStore.load(context);
        if (stored.needsRelogin || stored.accessToken.isEmpty()) {
            AgentSessionStore.recordLegacySession(context);
            return false;
        }
        try {
            AgentAuthClient.ProfileSyncResult result =
                    new AgentAuthClient(
                            context,
                            AgentAuthConfig.proxyRegistryUrl(context))
                            .syncProfile(
                                    stored.accessToken,
                                    AgentAuthSession.username());
            if (!isCurrent(expectedGeneration)) {
                return false;
            }
            AgentAuthSession.applySynchronizedProfile(context, result);
            AgentAdminRequestSynchronizer.synchronize(
                    context,
                    result.accessToken);
            Log.i(TAG, "Agent state synchronized after SSE event");
            return true;
        } catch (AgentAuthClient.SyncException error) {
            if (!isCurrent(expectedGeneration)) {
                return false;
            }
            if (AgentSyncFailurePolicy.requiresManagedProxyShutdown(error.failure)) {
                AgentSessionStore.recordManagedProxyAddressFailure(context);
                AgentPermissionConfigEnforcer.stopRunningAgents(context);
            } else {
                AgentSessionStore.recordSyncFailure(context, error.failure);
            }
            Log.w(TAG, "Agent state synchronization failed after SSE event");
        } catch (IOException | RuntimeException error) {
            if (isCurrent(expectedGeneration)) {
                AgentSessionStore.recordSyncFailure(
                        context,
                        AgentAuthClient.SyncFailure.TRANSIENT);
                Log.w(TAG, "Agent state synchronization unavailable", error);
            }
        }
        return false;
    }

    private static void synchronizeAdminRequests(Context context) {
        AgentSessionStore.StoredSession stored = AgentSessionStore.load(context);
        if (!stored.accessToken.isEmpty()) {
            AgentAdminRequestSynchronizer.synchronize(
                    context,
                    stored.accessToken);
        }
    }

    private static synchronized Context currentContext(long expectedGeneration) {
        return expectedGeneration == generation ? applicationContext : null;
    }

    private static synchronized boolean isCurrent(long expectedGeneration) {
        return expectedGeneration == generation
                && applicationContext != null
                && AgentAuthSession.isActive(applicationContext);
    }

    private static synchronized void setActiveClient(
            long expectedGeneration,
            AgentServerEventClient client) {
        if (expectedGeneration == generation) {
            activeClient = client;
        } else {
            client.cancel();
        }
    }

    private static synchronized void clearActiveClient(
            AgentServerEventClient client) {
        if (activeClient == client) {
            activeClient = null;
        }
    }

    private static synchronized void cancelWorker() {
        if (activeClient != null) {
            activeClient.cancel();
            activeClient = null;
        }
        if (worker != null) {
            worker.cancel(true);
            worker = null;
        }
    }

    private static boolean waitForReconnect(
            long expectedGeneration,
            int delaySeconds) {
        if (!isCurrent(expectedGeneration)) {
            return false;
        }
        try {
            Thread.sleep(Math.max(1, delaySeconds) * 1000L);
            return isCurrent(expectedGeneration);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void recordConnectionFailure(
            Context context,
            Throwable error) {
        AgentSessionStore.recordSyncFailure(
                context,
                AgentAuthClient.SyncFailure.TRANSIENT);
        Log.w(TAG, "Unable to create Agent SSE connection", error);
    }

    private static final class EventThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "ppaass-agent-events");
            thread.setDaemon(true);
            return thread;
        }
    }
}
