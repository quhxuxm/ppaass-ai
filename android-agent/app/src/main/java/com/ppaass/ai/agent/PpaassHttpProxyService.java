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

public class PpaassHttpProxyService extends Service {
    public static final String ACTION_START = "com.ppaass.ai.agent.HTTP_PROXY_START";
    public static final String ACTION_STOP = "com.ppaass.ai.agent.HTTP_PROXY_STOP";
    public static final String PREF_RUNNING = "http_proxy_running";

    private static final String TAG = "PpaassHttpProxyService";
    private static final String CHANNEL_ID = "ppaass_http_proxy";
    private static final int NOTIFICATION_ID = 7002;
    private static final long HEALTH_CHECK_INTERVAL_MS = 2_000L;

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
                Log.w(TAG, "Native HTTP proxy exited; stopping service");
                stopProxy();
                return;
            }
            mainHandler.postDelayed(this, HEALTH_CHECK_INTERVAL_MS);
        }
    };

    static boolean isRunningInProcess() {
        return runningInProcess;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopProxy();
            return START_NOT_STICKY;
        }

        startProxy();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        stopProxy();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void startProxy() {
        if (nativeHandle != 0) {
            runningInProcess = true;
            startNativeHealthChecks();
            setRunning(true);
            return;
        }

        listenPort = parseListenPort();
        startForeground(NOTIFICATION_ID, notification());

        try {
            JSONObject config = AgentConfigJson.build(this);
            long handle = NativeAgent.startHttpProxy(config.toString(), listenPort);
            if (handle == 0) {
                throw new IllegalStateException("Native HTTP proxy returned an empty handle");
            }
            nativeHandle = handle;
            runningInProcess = true;
            startNativeHealthChecks();
            setRunning(true);
        } catch (RuntimeException | JSONException error) {
            Log.e(TAG, "Failed to start PPAASS HTTP proxy", error);
            stopProxy();
        }
    }

    private void stopProxy() {
        stopNativeHealthChecks();
        if (nativeHandle != 0) {
            NativeAgent.stop(nativeHandle);
            nativeHandle = 0;
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        runningInProcess = false;
        setRunning(false);
        stopSelf();
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
                .setContentTitle("PPAASS HTTP Proxy")
                .setContentText("监听 0.0.0.0:" + listenPort)
                .setOngoing(true)
                .build();
    }
}
