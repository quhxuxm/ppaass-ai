package com.ppaass.ai.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class PpaassVpnService extends VpnService {
    public static final String ACTION_START = "com.ppaass.ai.agent.START";
    public static final String ACTION_STOP = "com.ppaass.ai.agent.STOP";
    public static final String EXTRA_STARTED_BY_APP = "com.ppaass.ai.agent.STARTED_BY_APP";
    public static final String PREF_RUNNING = "vpn_running";
    public static final String PREF_SYSTEM_MANAGED = "vpn_system_managed";

    private static final String TAG = "PpaassVpnService";
    private static final String CHANNEL_ID = "ppaass_vpn";
    private static final int NOTIFICATION_ID = 7001;
    private static final long HEALTH_CHECK_INTERVAL_MS = 2_000L;

    private static volatile boolean runningInProcess;

    private long nativeHandle;
    private ParcelFileDescriptor tun;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Runnable nativeHealthCheck = new Runnable() {
        @Override
        public void run() {
            if (nativeHandle == 0) {
                return;
            }
            if (!NativeAgent.isRunning(nativeHandle)) {
                Log.w(TAG, "Native VPN agent exited; stopping service");
                stopAgent();
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
            stopAgent();
            return START_NOT_STICKY;
        } else {
            boolean startedByApp = intent != null
                    && intent.getBooleanExtra(EXTRA_STARTED_BY_APP, false);
            startAgent(!startedByApp || isAlwaysOnVpn());
            return START_STICKY;
        }
    }

    @Override
    public void onDestroy() {
        stopAgent();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Log.w(TAG, "VPN permission revoked by the system");
        stopAgent();
        super.onRevoke();
    }

    public boolean protectSocket(int socketFd) {
        return protect(socketFd);
    }

    private void startAgent(boolean systemManaged) {
        if (nativeHandle != 0) {
            runningInProcess = true;
            startNativeHealthChecks();
            setRunning(true);
            setSystemManaged(systemManaged);
            return;
        }

        startForeground(NOTIFICATION_ID, notification());

        int rawFd = -1;
        try {
            JSONObject config = buildConfigJson();
            JSONObject tunConfig = config.getJSONObject("tun");
            Cidr ipv4 = parseCidr(tunConfig.getString("ipv4"));
            int mtu = tunConfig.optInt("mtu", 1500);

            Builder builder = new Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(mtu)
                    .setBlocking(false)
                    .addAddress(ipv4.address, ipv4.prefix)
                    .addRoute("0.0.0.0", 0);

            String ipv6 = tunConfig.optString("ipv6", "").trim();
            if (!ipv6.isEmpty()) {
                Cidr parsedIpv6 = parseCidr(ipv6);
                builder.addAddress(parsedIpv6.address, parsedIpv6.prefix);
                builder.addRoute("::", 0);
            }

            builder.addDnsServer("8.8.8.8");

            applyAppSelection(builder);

            tun = builder.establish();
            if (tun == null) {
                throw new IllegalStateException("VpnService establish returned null");
            }

            rawFd = tun.detachFd();
            tun = null;
            long handle = NativeAgent.start(rawFd, config.toString(), this);
            rawFd = -1;
            if (handle == 0) {
                throw new IllegalStateException("Native agent returned an empty handle");
            }
            nativeHandle = handle;
            runningInProcess = true;
            startNativeHealthChecks();
            setRunning(true);
            setSystemManaged(systemManaged);
        } catch (RuntimeException | JSONException error) {
            closeDetachedFd(rawFd);
            stopAgent();
            throw new IllegalStateException("Failed to start PPAASS VPN", error);
        }
    }

    private void stopAgent() {
        stopNativeHealthChecks();
        if (nativeHandle != 0) {
            NativeAgent.stop(nativeHandle);
            nativeHandle = 0;
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
            }
            tun = null;
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        runningInProcess = false;
        setRunning(false);
        setSystemManaged(false);
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

    private void setSystemManaged(boolean managed) {
        getSharedPreferences("ppaass_agent", MODE_PRIVATE)
                .edit()
                .putBoolean(PREF_SYSTEM_MANAGED, managed)
                .apply();
    }

    private boolean isAlwaysOnVpn() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isAlwaysOn();
    }

    private void closeDetachedFd(int rawFd) {
        if (rawFd < 0) {
            return;
        }
        try {
            ParcelFileDescriptor.adoptFd(rawFd).close();
        } catch (IOException ignored) {
        }
    }

    private JSONObject buildConfigJson() throws JSONException {
        return AgentConfigJson.build(this);
    }

    private void applyAppSelection(Builder builder) {
        SharedPreferences prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        Set<String> selected = new HashSet<>(prefs.getStringSet("vpn_apps", Collections.emptySet()));
        if (selected.isEmpty()) {
            return;
        }

        int configuredAppCount = 0;
        for (String packageName : selected) {
            if (!getPackageName().equals(packageName)) {
                configuredAppCount++;
            }
        }
        selected.add(getPackageName());
        int configuredAllowed = 0;
        for (String packageName : selected) {
            try {
                builder.addAllowedApplication(packageName);
                if (!getPackageName().equals(packageName)) {
                    configuredAllowed++;
                }
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }

        if (configuredAppCount > 0 && configuredAllowed == 0) {
            throw new IllegalStateException("No selected VPN apps are installed");
        }
    }

    @SuppressWarnings("deprecation")
    private Notification notification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.vpn_channel_name),
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
                .setContentTitle(getString(R.string.app_name))
                .setContentText("运行中")
                .setOngoing(true)
                .build();
    }

    private Cidr parseCidr(String cidr) {
        String[] parts = cidr.trim().split("/", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid CIDR: " + cidr);
        }
        return new Cidr(parts[0], Integer.parseInt(parts[1]));
    }

    private static final class Cidr {
        final String address;
        final int prefix;

        Cidr(String address, int prefix) {
            this.address = address;
            this.prefix = prefix;
        }
    }
}
