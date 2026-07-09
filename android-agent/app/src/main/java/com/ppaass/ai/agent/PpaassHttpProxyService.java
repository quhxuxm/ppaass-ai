package com.ppaass.ai.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Collections;
import java.util.Set;

public class PpaassHttpProxyService extends Service {
    public static final String ACTION_START = "com.ppaass.ai.agent.HTTP_PROXY_START";
    public static final String ACTION_STOP = "com.ppaass.ai.agent.HTTP_PROXY_STOP";
    public static final String PREF_BLOCKED_CLIENTS = "http_proxy_blocked_clients";
    public static final String PREF_ENABLED = "http_proxy_enabled";
    public static final String PREF_RUNNING = "http_proxy_running";

    private static final String TAG = "PpaassHttpProxyService";
    private static final String CHANNEL_ID = "ppaass_http_proxy";
    private static final int NOTIFICATION_ID = 7002;
    private static final long HEALTH_CHECK_INTERVAL_MS = 2_000L;
    private static final long NATIVE_RESTART_DELAY_MS = 1_000L;

    private static volatile boolean runningInProcess;

    private long nativeHandle;
    private int listenPort = DefaultConfig.HTTP_PROXY_PORT;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Runnable nativeHealthCheck = new Runnable() {
        @Override
        public void run() {
            if (nativeHandle == 0) {
                return;
            }
            if (!NativeAgent.isRunning(nativeHandle)) {
                Log.w(TAG, "Native HTTP / SOCKS5 proxy exited; restarting");
                restartNativeProxy();
                return;
            }
            mainHandler.postDelayed(this, HEALTH_CHECK_INTERVAL_MS);
        }
    };
    private final Runnable nativeRestart = new Runnable() {
        @Override
        public void run() {
            if (isEnabled()) {
                startProxy();
            }
        }
    };

    static boolean isRunningInProcess() {
        return runningInProcess;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            setEnabled(false);
            stopProxy();
            return START_NOT_STICKY;
        }

        // enabled 表示“用户希望显式代理长驻”；running 只表示当前 native 实例是否活着。
        if (intent == null && !isEnabled()) {
            stopSelf();
            return START_NOT_STICKY;
        }
        setEnabled(true);
        startProxy();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopProxyNative();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void startProxy() {
        if (nativeHandle != 0) {
            if (!NativeAgent.isRunning(nativeHandle)) {
                NativeAgent.stop(nativeHandle);
                nativeHandle = 0;
            } else {
                runningInProcess = true;
                startNativeHealthChecks();
                setRunning(true);
                return;
            }
        }

        if (!isEnabled()) {
            stopProxy();
            return;
        }

        mainHandler.removeCallbacks(nativeRestart);
        listenPort = parseListenPort();
        startForeground(NOTIFICATION_ID, notification());

        try {
            applyBlockedClients();
            JSONObject config = AgentConfigJson.buildHttpProxy(this);
            long handle = NativeAgent.startHttpProxy(config.toString(), listenPort);
            if (handle == 0) {
                throw new IllegalStateException("Native HTTP / SOCKS5 proxy returned an empty handle");
            }
            nativeHandle = handle;
            runningInProcess = true;
            startNativeHealthChecks();
            setRunning(true);
        } catch (RuntimeException | JSONException error) {
            Log.e(TAG, "Failed to start PPAASS HTTP / SOCKS5 proxy", error);
            setEnabled(false);
            stopProxy();
        }
    }

    private void stopProxy() {
        stopProxyNative();
        stopSelf();
    }

    private void stopProxyNative() {
        mainHandler.removeCallbacks(nativeRestart);
        stopNativeHealthChecks();
        if (nativeHandle != 0) {
            NativeAgent.stop(nativeHandle);
            nativeHandle = 0;
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        runningInProcess = false;
        setRunning(false);
    }

    private void restartNativeProxy() {
        stopNativeHealthChecks();
        if (nativeHandle != 0) {
            NativeAgent.stop(nativeHandle);
            nativeHandle = 0;
        }
        runningInProcess = false;
        setRunning(false);
        mainHandler.removeCallbacks(nativeRestart);
        // native 层偶发退出时保留前台 service，并按用户期望自动拉起新的监听实例。
        if (isEnabled()) {
            mainHandler.postDelayed(nativeRestart, NATIVE_RESTART_DELAY_MS);
        } else {
            stopProxy();
        }
    }

    private void startNativeHealthChecks() {
        mainHandler.removeCallbacks(nativeHealthCheck);
        mainHandler.postDelayed(nativeHealthCheck, HEALTH_CHECK_INTERVAL_MS);
    }

    private void stopNativeHealthChecks() {
        mainHandler.removeCallbacks(nativeHealthCheck);
    }

    private void setRunning(boolean running) {
        getSharedPreferences("ppaass_agent", MODE_PRIVATE)
                .edit()
                .putBoolean(PREF_RUNNING, running)
                .apply();
    }

    private void setEnabled(boolean enabled) {
        getSharedPreferences("ppaass_agent", MODE_PRIVATE)
                .edit()
                .putBoolean(PREF_ENABLED, enabled)
                .apply();
    }

    private boolean isEnabled() {
        return getSharedPreferences("ppaass_agent", MODE_PRIVATE)
                .getBoolean(PREF_ENABLED, false);
    }

    private void applyBlockedClients() {
        SharedPreferences prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        Set<String> blocked = prefs.getStringSet(PREF_BLOCKED_CLIENTS, Collections.emptySet());
        // 禁止列表要跨 service 重启保留，启动 native 前重新灌入内存 registry。
        for (String ip : blocked) {
            NativeAgent.blockHttpProxyClient(ip);
        }
    }

    private int parseListenPort() {
        SharedPreferences prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        String value = prefs.getString(
                "http_proxy_port",
                String.valueOf(DefaultConfig.HTTP_PROXY_PORT));
        try {
            int parsed = Integer.parseInt(value == null ? "" : value.trim());
            if (parsed >= 1 && parsed <= 65535) {
                return parsed;
            }
        } catch (NumberFormatException ignored) {
        }
        return DefaultConfig.HTTP_PROXY_PORT;
    }

    @SuppressWarnings("deprecation")
    private Notification notification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.http_proxy_channel_name),
                    NotificationManager.IMPORTANCE_LOW);
            getSystemService(NotificationManager.class).createNotificationChannel(channel);
        }

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }

        return builder
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentTitle("PPAASS HTTP / SOCKS5 代理")
                .setContentText("HTTP 与 SOCKS5 监听 0.0.0.0:" + listenPort)
                .setOngoing(true)
                .build();
    }
}
