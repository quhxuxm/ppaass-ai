package com.ppaass.ai.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.google.android.gms.tasks.Task;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class PpaassVpnService extends VpnService {
    public static final String ACTION_START = "com.ppaass.ai.agent.START";
    public static final String ACTION_STOP = "com.ppaass.ai.agent.STOP";
    public static final String ACTION_UPDATE_MOCK_GEO = "com.ppaass.ai.agent.UPDATE_MOCK_GEO";
    public static final String EXTRA_STARTED_BY_APP = "com.ppaass.ai.agent.STARTED_BY_APP";
    public static final String EXTRA_USER_VISIBLE = "com.ppaass.ai.agent.USER_VISIBLE";
    public static final String PREF_RUNNING = "vpn_running";
    public static final String PREF_SYSTEM_MANAGED = "vpn_system_managed";
    public static final String PREF_MOCK_GEO_ACTIVE = "mock_geo_active";
    public static final String PREF_MOCK_GEO_ERROR = "mock_geo_error";
    public static final String PREF_MOCK_GEO_WAITING_FOR_FOREGROUND =
            "mock_geo_waiting_for_foreground";
    public static final String PREF_MOCK_GEO_DIRTY = "mock_geo_dirty";
    public static final String PREF_MOCK_GEO_SESSION_TOKEN = "mock_geo_session_token";
    public static final String PREF_MOCK_GEO_GOOGLE_FUSED_USED =
            "mock_geo_google_fused_used";

    private static final String TAG = "PpaassVpnService";
    private static final String CHANNEL_ID = "ppaass_vpn";
    private static final int NOTIFICATION_ID = 7001;
    private static final long HEALTH_CHECK_INTERVAL_MS = 2_000L;

    private static volatile boolean runningInProcess;

    private long nativeHandle;
    private ParcelFileDescriptor tun;
    private MockLocationController mockLocationController;
    private int activeForegroundServiceTypes;
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
        } else if (intent != null && ACTION_UPDATE_MOCK_GEO.equals(intent.getAction())) {
            if (nativeHandle != 0) {
                applyMockGeoConfig(intent.getBooleanExtra(EXTRA_USER_VISIBLE, false));
                return START_STICKY;
            }
            return START_NOT_STICKY;
        } else {
            boolean startedByApp = intent != null
                    && intent.getBooleanExtra(EXTRA_STARTED_BY_APP, false);
            startAgent(!startedByApp || isAlwaysOnVpn(), startedByApp);
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

    private void startAgent(boolean systemManaged, boolean userVisible) {
        if (nativeHandle != 0) {
            runningInProcess = true;
            startNativeHealthChecks();
            setRunning(true);
            setSystemManaged(systemManaged);
            applyMockGeoConfig(userVisible);
            return;
        }

        startVpnForeground(false);

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
            applyMockGeoConfig(userVisible);
        } catch (RuntimeException | JSONException error) {
            closeDetachedFd(rawFd);
            stopAgent();
            throw new IllegalStateException("Failed to start PPAASS VPN", error);
        }
    }

    private void stopAgent() {
        stopNativeHealthChecks();
        stopMockLocation(false, "");
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
        activeForegroundServiceTypes = 0;
        runningInProcess = false;
        setRunning(false);
        setSystemManaged(false);
        stopSelf();
    }

    private void applyMockGeoConfig(boolean userVisible) {
        MockGeoConfig.Selection selection = MockGeoConfig.load(
                getSharedPreferences("ppaass_agent", MODE_PRIVATE));
        if (!selection.enabled()) {
            stopMockLocation(false, "");
            return;
        }

        if (!userVisible) {
            stopMockLocation(true, "");
            return;
        }

        setMockGeoState(false, "");
        try {
            ensureMockGeoForegroundReady();
        } catch (RuntimeException error) {
            String message = "模拟 GEO 未生效：" + readableMessage(error);
            stopMockLocation(false, message);
            Log.e(TAG, message, error);
            return;
        }

        if (!markMockGeoSessionDirty()) {
            String message = "模拟 GEO 未生效：无法持久化模拟定位会话状态";
            stopMockLocation(false, message);
            Log.e(TAG, message);
            return;
        }
        boolean starting = mockLocationController == null;
        if (starting) {
            mockLocationController = new MockLocationController(
                    this,
                    new MockLocationController.Listener() {
                        @Override
                        public void onMockLocationActive() {
                            setMockGeoState(true, "");
                            refreshVpnNotification();
                        }

                        @Override
                        public void onMockLocationError(String message) {
                            stopMockLocation(false, message);
                            Log.e(TAG, message);
                        }
                    });
        }
        try {
            if (starting) {
                mockLocationController.start(selection);
            } else {
                mockLocationController.update(selection);
            }
        } catch (RuntimeException error) {
            String message = "模拟 GEO 未生效：" + readableMessage(error);
            stopMockLocation(false, message);
            Log.e(TAG, message, error);
        }
    }

    private void stopMockLocation(boolean waitingForForeground, String errorAfterCleanup) {
        Task<Void> fusedCleanup = stopMockLocationController();
        SharedPreferences prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        boolean cleanupRequired = prefs.getBoolean(PREF_MOCK_GEO_DIRTY, false)
                || prefs.getBoolean(PREF_MOCK_GEO_ACTIVE, false);
        boolean googleFusedCleanupRequired = prefs.getBoolean(
                PREF_MOCK_GEO_GOOGLE_FUSED_USED,
                cleanupRequired);
        String cleanupToken = UUID.randomUUID().toString();
        SharedPreferences.Editor cleanupEditor = prefs.edit()
                .putString(PREF_MOCK_GEO_SESSION_TOKEN, cleanupToken);
        if (cleanupRequired) {
            cleanupEditor.putBoolean(PREF_MOCK_GEO_DIRTY, true);
        }
        if (!cleanupEditor.commit()) {
            Log.w(TAG, "Failed to persist mock-location cleanup token");
        }

        setMockGeoState(false, errorAfterCleanup, waitingForForeground);
        MockLocationController.cleanupResidualState(
                this,
                cleanupRequired,
                googleFusedCleanupRequired,
                fusedCleanup,
                (success, cleanupMessage) -> {
                    SharedPreferences currentPrefs =
                            getSharedPreferences("ppaass_agent", MODE_PRIVATE);
                    String currentToken = MockGeoConfig.readString(
                            currentPrefs,
                            PREF_MOCK_GEO_SESSION_TOKEN,
                            "");
                    if (!cleanupToken.equals(currentToken)) {
                        return;
                    }

                    SharedPreferences.Editor editor = currentPrefs.edit();
                    if (success) {
                        editor.putBoolean(PREF_MOCK_GEO_DIRTY, false)
                                .remove(PREF_MOCK_GEO_GOOGLE_FUSED_USED)
                                .remove(PREF_MOCK_GEO_SESSION_TOKEN);
                    } else {
                        editor.putBoolean(PREF_MOCK_GEO_DIRTY, true);
                    }
                    editor.apply();

                    if (success) {
                        setMockGeoState(false, errorAfterCleanup, waitingForForeground);
                    } else {
                        String message = cleanupMessage == null
                                || cleanupMessage.trim().isEmpty()
                                ? "上次模拟定位未能完全清理，请重新授权后重试或重启设备"
                                : cleanupMessage.trim();
                        setMockGeoState(false, message, false);
                    }
                    refreshVpnNotification();
                });
    }

    private Task<Void> stopMockLocationController() {
        if (mockLocationController != null) {
            Task<Void> cleanupTask = mockLocationController.stop();
            mockLocationController = null;
            return cleanupTask;
        }
        return null;
    }

    private boolean markMockGeoSessionDirty() {
        SharedPreferences prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        boolean googleFusedWasUsed = prefs.getBoolean(
                PREF_MOCK_GEO_GOOGLE_FUSED_USED,
                false);
        return prefs
                .edit()
                .putBoolean(PREF_MOCK_GEO_DIRTY, true)
                .putBoolean(
                        PREF_MOCK_GEO_GOOGLE_FUSED_USED,
                        googleFusedWasUsed
                                || MockLocationController.hasGooglePlayServices(this))
                .putString(PREF_MOCK_GEO_SESSION_TOKEN, UUID.randomUUID().toString())
                .commit();
    }

    private void setMockGeoState(boolean active, String error) {
        setMockGeoState(active, error, false);
    }

    private void setMockGeoState(
            boolean active,
            String error,
            boolean waitingForForeground) {
        SharedPreferences.Editor editor = getSharedPreferences("ppaass_agent", MODE_PRIVATE)
                .edit()
                .putBoolean(PREF_MOCK_GEO_ACTIVE, active)
                .putBoolean(PREF_MOCK_GEO_WAITING_FOR_FOREGROUND, waitingForForeground);
        if (error == null || error.trim().isEmpty()) {
            editor.remove(PREF_MOCK_GEO_ERROR);
        } else {
            editor.putString(PREF_MOCK_GEO_ERROR, error.trim());
        }
        editor.apply();
    }

    private String readableMessage(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return error.getClass().getSimpleName();
        }
        return message.trim();
    }

    private void refreshVpnNotification() {
        if (nativeHandle != 0 || runningInProcess) {
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.notify(NOTIFICATION_ID, notification());
            }
        }
    }

    private void ensureMockGeoForegroundReady() {
        if (!MockLocationController.isSystemLocationEnabled(this)) {
            throw new IllegalStateException("请先开启 Android 系统定位");
        }
        if (!MockLocationController.hasLocationPermission(this)) {
            throw new SecurityException("请允许定位权限，以便持续模拟 Android 定位");
        }
        if (!MockLocationController.isSelectedMockLocationApp(this)) {
            throw new SecurityException("请在开发者选项中将 PPAASS VPN 设为模拟位置信息应用");
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                && (activeForegroundServiceTypes
                & ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION) == 0) {
            startVpnForeground(true);
        }
    }

    private void startVpnForeground(boolean includeLocation) {
        Notification currentNotification = notification();
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, currentNotification);
            return;
        }

        int requestedTypes = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
                ? ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
                : ServiceInfo.FOREGROUND_SERVICE_TYPE_NONE;
        if (includeLocation) {
            requestedTypes |= ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION;
        }
        activeForegroundServiceTypes |= requestedTypes;
        startForeground(
                NOTIFICATION_ID,
                currentNotification,
                activeForegroundServiceTypes);
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

        SharedPreferences prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        MockGeoConfig.Selection selection = MockGeoConfig.load(prefs);
        String mockGeoError = MockGeoConfig.readString(prefs, PREF_MOCK_GEO_ERROR, "");
        boolean mockGeoActive = prefs.getBoolean(PREF_MOCK_GEO_ACTIVE, false);
        boolean mockGeoWaiting =
                prefs.getBoolean(PREF_MOCK_GEO_WAITING_FOR_FOREGROUND, false);
        Intent openApp = new Intent(this, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openAppIntent = PendingIntent.getActivity(
                this,
                0,
                openApp,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        String contentText;
        if (!selection.enabled()) {
            contentText = "运行中";
        } else if (mockGeoActive) {
            contentText = "运行中 · 模拟 GEO：" + selection.label;
        } else if (mockGeoWaiting) {
            contentText = "运行中 · 打开应用后恢复模拟 GEO";
        } else if (mockGeoError != null && !mockGeoError.trim().isEmpty()) {
            contentText = "运行中 · 模拟 GEO 未生效";
        } else {
            contentText = "运行中 · 模拟 GEO 启动中";
        }

        return builder
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(contentText)
                .setContentIntent(openAppIntent)
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
