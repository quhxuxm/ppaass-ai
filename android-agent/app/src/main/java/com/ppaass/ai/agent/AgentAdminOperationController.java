package com.ppaass.ai.agent;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.util.List;

final class AgentAdminOperationController {
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private long generation;
    private AgentAdminClient activeClient;

    synchronized void loadDashboard(
            Context context,
            String baseUrl,
            String accessToken,
            Callback callback) {
        cancelLocked();
        long current = generation;
        AgentAdminClient client = new AgentAdminClient(context, baseUrl);
        activeClient = client;
        new Thread(() -> {
            try {
                AgentAdminModels.Dashboard dashboard =
                        client.loadDashboard(accessToken);
                deliver(current, () -> callback.onDashboard(dashboard));
            } catch (AgentAdminClient.AdminException error) {
                deliver(current, () -> callback.onFailure(error));
            } catch (RuntimeException error) {
                deliver(current, () -> callback.onFailure(
                        clientFailure(error)));
            }
        }, "ppaass-admin-key-dashboard").start();
    }

    synchronized void decide(
            Context context,
            String baseUrl,
            String accessToken,
            AgentAdminModels.KeyRequest request,
            long expiresAt,
            List<String> proxyAddressIds,
            String rejectionReason,
            boolean approve,
            Callback callback) {
        cancelLocked();
        long current = generation;
        AgentAdminClient client = new AgentAdminClient(context, baseUrl);
        activeClient = client;
        new Thread(() -> {
            try {
                if (approve) {
                    client.approve(
                            accessToken,
                            request.id,
                            expiresAt,
                            proxyAddressIds);
                } else {
                    client.reject(accessToken, request.id, rejectionReason);
                }
                AgentAdminModels.Dashboard dashboard =
                        client.loadDashboard(accessToken);
                deliver(current, () -> callback.onDashboard(dashboard));
            } catch (AgentAdminClient.AdminException error) {
                deliver(current, () -> callback.onFailure(error));
            } catch (RuntimeException error) {
                deliver(current, () -> callback.onFailure(
                        clientFailure(error)));
            }
        }, "ppaass-admin-key-decision").start();
    }

    synchronized void cancel() {
        cancelLocked();
    }

    private synchronized void deliver(long expected, Runnable action) {
        if (expected != generation) {
            return;
        }
        activeClient = null;
        mainHandler.post(() -> {
            synchronized (AgentAdminOperationController.this) {
                if (expected != generation) {
                    return;
                }
            }
            action.run();
        });
    }

    private void cancelLocked() {
        generation++;
        if (activeClient != null) {
            activeClient.cancel();
            activeClient = null;
        }
    }

    private static AgentAdminClient.AdminException clientFailure(
            RuntimeException error) {
        return new AgentAdminClient.AdminException(
                0,
                "client_error",
                "管理员操作失败",
                error);
    }

    interface Callback {
        void onDashboard(AgentAdminModels.Dashboard dashboard);

        void onFailure(AgentAdminClient.AdminException error);
    }
}
