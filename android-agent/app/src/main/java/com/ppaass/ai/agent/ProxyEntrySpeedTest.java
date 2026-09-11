package com.ppaass.ai.agent;

import org.json.JSONObject;

import java.io.IOException;
import java.util.Locale;

final class ProxyEntrySpeedTest {
    interface Listener {
        void onSuccess(Result result);

        void onFailure(String message);
    }

    static final class Result {
        final long latencyMs;
        final long bytesPerSecond;

        Result(long latencyMs, long bytesPerSecond) {
            this.latencyMs = latencyMs;
            this.bytesPerSecond = bytesPerSecond;
        }

        String summary() {
            double megabits = bytesPerSecond * 8.0 / 1_000_000.0;
            return String.format(Locale.US, "%.1f Mbps · %d ms", megabits, latencyMs);
        }
    }

    private ProxyEntrySpeedTest() {
    }

    static void start(
            MainActivityConfigScreen host,
            ManagedProxyEntries.Entry entry,
            Listener listener) {
        new Thread(() -> {
            try {
                ManagedProxyEntries.Entry current = refreshEntry(host, entry.id);
                JSONObject config = AgentConfigJson.buildSpeedTest(host, current.address);
                JSONObject response = new JSONObject(NativeAgent.speedTest(config.toString()));
                String error = response.optString("error", "").trim();
                if (!error.isEmpty()) {
                    throw new IllegalStateException(error);
                }
                long latencyMs = response.getLong("latency_ms");
                long bytesPerSecond = response.getLong("bytes_per_second");
                if (latencyMs < 1 || bytesPerSecond < 1) {
                    throw new IllegalStateException("Proxy Entry 返回了无效测速结果");
                }
                Result result = new Result(latencyMs, bytesPerSecond);
                host.runOnUiThread(() -> listener.onSuccess(result));
            } catch (Exception error) {
                String message = error.getMessage();
                host.runOnUiThread(() -> listener.onFailure(
                        message == null || message.trim().isEmpty()
                                ? "Proxy Entry 测速失败"
                                : message));
            }
        }, "proxy-entry-speed-test").start();
    }

    private static ManagedProxyEntries.Entry refreshEntry(
            MainActivityConfigScreen host,
            String entryId) throws Exception {
        AgentSessionStore.StoredSession session = AgentSessionStore.load(host);
        AgentAuthClient.ProfileSyncResult result = new AgentAuthClient(
                host,
                AgentAuthConfig.proxyRegistryUrl(host)).syncProfile(
                session.accessToken,
                AgentAuthSession.username());
        if (!AgentAuthSession.applySynchronizedProfile(host, result)) {
            throw new IOException("无法保存最新的 Proxy Entry 配置");
        }
        for (ManagedProxyEntries.Entry candidate : result.proxyEntries) {
            if (candidate.id.equals(entryId)) {
                return candidate;
            }
        }
        throw new IOException("该 Proxy Entry 已被管理员取消分配或停用");
    }
}
