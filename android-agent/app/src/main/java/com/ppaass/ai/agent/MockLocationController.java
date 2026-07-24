package com.ppaass.ai.agent;

import android.Manifest;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.location.provider.ProviderProperties;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationServices;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Injects a stationary Android test location while the VPN service is running.
 *
 * <p>Location providers are device-wide. Android does not expose a way for a regular
 * {@code VpnService} to limit mock locations to the packages in its VPN allow-list.</p>
 */
final class MockLocationController {
    interface Listener {
        void onMockLocationActive();

        void onMockLocationError(String message);
    }

    interface CleanupListener {
        void onCleanupComplete(boolean success, String message);
    }

    private static final String FUSED_PROVIDER = "fused";
    private static final String[] KNOWN_TEST_PROVIDERS = {
            LocationManager.GPS_PROVIDER,
            LocationManager.NETWORK_PROVIDER,
            FUSED_PROVIDER
    };
    private static final long UPDATE_INTERVAL_MS = 1_000L;
    private static final long FUSED_START_TIMEOUT_MS = 10_000L;
    private static final long FUSED_OPERATION_TIMEOUT_MS = 10_000L;
    private static final String TAG = "PpaassMockLocation";
    private static final Object FUSED_OPERATION_LOCK = new Object();
    private static Task<Void> fusedOperationTail = Tasks.forResult(null);

    private final Context context;
    private final LocationManager locationManager;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Listener listener;
    private final List<String> registeredProviders = new ArrayList<>();
    private final Runnable updateTask = new Runnable() {
        @Override
        public void run() {
            if (!running || selection == null) {
                return;
            }
            try {
                ensureRuntimeAccess();
                injectFrameworkLocations();
                injectFusedLocation(false);
                handler.postDelayed(this, UPDATE_INTERVAL_MS);
            } catch (RuntimeException error) {
                fail("模拟定位更新失败：" + readableMessage(error));
            }
        }
    };
    private final Runnable fusedStartTimeoutTask = new Runnable() {
        @Override
        public void run() {
            if (running && fusedClient != null && !fusedMockReady) {
                fail("Google 融合定位模拟启动超时");
            }
        }
    };

    private MockGeoConfig.Selection selection;
    private FusedLocationProviderClient fusedClient;
    private boolean fusedMockReady;
    private boolean fusedUpdatePending;
    private boolean fusedRefreshRequested;
    private boolean fusedNotifyRequested;
    private boolean running;
    private int generation;
    private Task<Void> fusedCleanupTask;

    MockLocationController(Context context, Listener listener) {
        this.context = context.getApplicationContext();
        this.locationManager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        this.listener = listener;
    }

    void start(MockGeoConfig.Selection nextSelection) {
        stop();
        fusedCleanupTask = null;
        if (nextSelection == null || !nextSelection.enabled()) {
            return;
        }
        if (locationManager == null) {
            throw new IllegalStateException("设备没有可用的 Android 定位服务");
        }
        if (!isSelectedMockLocationApp(context)) {
            throw new SecurityException("请在开发者选项中将 PPAASS VPN 设为模拟位置信息应用");
        }
        if (!isSystemLocationEnabled(context)) {
            throw new IllegalStateException("请先开启 Android 系统定位");
        }
        if (!hasLocationPermission(context)) {
            throw new SecurityException("请允许定位权限，以便持续模拟 Android 定位");
        }
        if (!removeKnownTestProviders(locationManager)) {
            throw new IllegalStateException("无法清理上次遗留的 Android 测试定位 provider");
        }

        selection = nextSelection;
        int startGeneration = ++generation;
        try {
            registerFrameworkProvider(LocationManager.GPS_PROVIDER, false, true, false, true);
            registerFrameworkProvider(LocationManager.NETWORK_PROVIDER, true, false, true, false);
            running = true;
            injectFrameworkLocations();

            if (hasGooglePlayServices()) {
                enableGoogleFusedMock(startGeneration);
            } else {
                registerFrameworkProvider(FUSED_PROVIDER, true, true, true, true);
                injectFrameworkLocations();
                notifyActive();
            }
            handler.postDelayed(updateTask, UPDATE_INTERVAL_MS);
        } catch (RuntimeException error) {
            stop();
            throw error;
        }
    }

    void update(MockGeoConfig.Selection nextSelection) {
        if (!running) {
            start(nextSelection);
            return;
        }
        if (nextSelection == null || !nextSelection.enabled()) {
            stop();
            return;
        }
        if (!isSelectedMockLocationApp(context)) {
            throw new SecurityException("请在开发者选项中将 PPAASS VPN 设为模拟位置信息应用");
        }
        if (!isSystemLocationEnabled(context)) {
            throw new IllegalStateException("请先开启 Android 系统定位");
        }
        if (!hasLocationPermission(context)) {
            throw new SecurityException("请允许定位权限，以便持续模拟 Android 定位");
        }

        selection = nextSelection;
        injectFrameworkLocations();
        if (fusedClient != null) {
            injectFusedLocation(true);
        } else {
            notifyActive();
        }
    }

    @SuppressLint("MissingPermission")
    Task<Void> stop() {
        generation++;
        running = false;
        selection = null;
        handler.removeCallbacks(updateTask);
        handler.removeCallbacks(fusedStartTimeoutTask);
        fusedUpdatePending = false;
        fusedRefreshRequested = false;
        fusedNotifyRequested = false;

        FusedLocationProviderClient client = fusedClient;
        fusedClient = null;
        fusedMockReady = false;
        if (client != null) {
            try {
                fusedCleanupTask = enqueueSetMockMode(client, false)
                        .addOnFailureListener(error -> Log.w(
                                TAG,
                                "Failed to disable Google fused mock mode",
                                error));
            } catch (RuntimeException ignored) {
                // Revoking the mock-location AppOp can make cleanup fail. The system also
                // clears the selected mock app when developer options are disabled.
            }
        }

        for (int i = registeredProviders.size() - 1; i >= 0; i--) {
            String provider = registeredProviders.get(i);
            try {
                locationManager.setTestProviderEnabled(provider, false);
            } catch (RuntimeException ignored) {
            }
            try {
                locationManager.removeTestProvider(provider);
            } catch (RuntimeException ignored) {
            }
        }
        registeredProviders.clear();
        return fusedCleanupTask;
    }

    static boolean isSelectedMockLocationApp(Context context) {
        AppOpsManager appOps = (AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
        if (appOps == null) {
            return false;
        }
        try {
            int mode;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                mode = appOps.unsafeCheckOpNoThrow(
                        AppOpsManager.OPSTR_MOCK_LOCATION,
                        Process.myUid(),
                        context.getPackageName());
            } else {
                mode = appOps.checkOpNoThrow(
                        AppOpsManager.OPSTR_MOCK_LOCATION,
                        Process.myUid(),
                        context.getPackageName());
            }
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    static boolean hasLocationPermission(Context context) {
        return context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
                        == PackageManager.PERMISSION_GRANTED
                || context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION)
                        == PackageManager.PERMISSION_GRANTED;
    }

    static boolean needsLocationPermission(Context context) {
        return true;
    }

    static boolean isSystemLocationEnabled(Context context) {
        LocationManager manager =
                (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        if (manager == null) {
            return false;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return manager.isLocationEnabled();
        }
        return Settings.Secure.getInt(
                context.getContentResolver(),
                Settings.Secure.LOCATION_MODE,
                Settings.Secure.LOCATION_MODE_OFF) != Settings.Secure.LOCATION_MODE_OFF;
    }

    /**
     * Removes test-provider state which may have survived an abrupt app-process death.
     *
     * <p>Framework test providers live in system_server, so an in-memory controller is not
     * sufficient ownership. Google fused mock mode is also explicitly disabled when the
     * required user grants are still available.</p>
     */
    @SuppressLint("MissingPermission")
    static void cleanupResidualState(
            Context sourceContext,
            boolean cleanupRequired,
            CleanupListener cleanupListener) {
        cleanupResidualState(
                sourceContext,
                cleanupRequired,
                cleanupRequired,
                null,
                cleanupListener);
    }

    @SuppressLint("MissingPermission")
    static void cleanupResidualState(
            Context sourceContext,
            boolean cleanupRequired,
            boolean googleFusedCleanupRequired,
            Task<Void> existingFusedCleanup,
            CleanupListener cleanupListener) {
        Context context = sourceContext.getApplicationContext();
        LocationManager manager =
                (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        boolean frameworkClean = removeKnownTestProviders(manager);

        if (cleanupRequired && !isSelectedMockLocationApp(context)) {
            notifyCleanup(
                    cleanupListener,
                    false,
                    "检测到上次模拟定位可能仍未清理。请在开发者选项中重新选择"
                            + " PPAASS VPN 后返回，或重启设备");
            return;
        }
        if (existingFusedCleanup != null) {
            observeFusedCleanup(
                    existingFusedCleanup,
                    cleanupRequired,
                    googleFusedCleanupRequired,
                    frameworkClean,
                    cleanupListener);
            return;
        }
        if (!hasGooglePlayServices(context)) {
            boolean success = !cleanupRequired
                    || (frameworkClean && !googleFusedCleanupRequired);
            notifyCleanup(
                    cleanupListener,
                    success,
                    success
                            ? ""
                            : googleFusedCleanupRequired
                            ? "Google Play 服务暂不可用，无法确认融合定位已清理"
                            : "Android 测试定位 provider 清理失败");
            return;
        }
        if (!isSelectedMockLocationApp(context)) {
            notifyCleanup(
                    cleanupListener,
                    !cleanupRequired,
                    cleanupRequired
                            ? "检测到上次模拟定位可能仍未清理。请在开发者选项中重新选择"
                            + " PPAASS VPN 后返回，或重启设备"
                            : "");
            return;
        }
        if (!hasLocationPermission(context)) {
            boolean success = !cleanupRequired
                    || (frameworkClean && !googleFusedCleanupRequired);
            notifyCleanup(
                    cleanupListener,
                    success,
                    success
                            ? ""
                            : "检测到上次模拟定位可能仍未清理。请重新授予定位权限后返回，"
                            + "或重启设备");
            return;
        }

        try {
            FusedLocationProviderClient client =
                    LocationServices.getFusedLocationProviderClient(context);
            observeFusedCleanup(
                    enqueueSetMockMode(client, false),
                    cleanupRequired,
                    googleFusedCleanupRequired,
                    frameworkClean,
                    cleanupListener);
        } catch (RuntimeException error) {
            boolean success = !cleanupRequired
                    || (frameworkClean && !googleFusedCleanupRequired);
            notifyCleanup(
                    cleanupListener,
                    success,
                    success
                            ? ""
                            : "Google 融合定位清理失败：" + readableMessage(error));
        }
    }

    private static void observeFusedCleanup(
            Task<Void> cleanupTask,
            boolean cleanupRequired,
            boolean googleFusedCleanupRequired,
            boolean frameworkClean,
            CleanupListener cleanupListener) {
        cleanupTask
                .addOnSuccessListener(unused -> {
                    boolean success = !cleanupRequired || frameworkClean;
                    notifyCleanup(
                            cleanupListener,
                            success,
                            success ? "" : "Android 测试定位 provider 清理失败");
                })
                .addOnFailureListener(error -> {
                    boolean success = !cleanupRequired
                            || (frameworkClean && !googleFusedCleanupRequired);
                    notifyCleanup(
                            cleanupListener,
                            success,
                            success
                                    ? ""
                                    : "Google 融合定位清理失败："
                                    + readableMessage(error));
                });
    }

    private static boolean removeKnownTestProviders(LocationManager manager) {
        if (manager == null) {
            return false;
        }
        boolean clean = true;
        for (String provider : KNOWN_TEST_PROVIDERS) {
            try {
                manager.removeTestProvider(provider);
            } catch (IllegalArgumentException ignored) {
                // No test-provider override exists for this provider.
            } catch (RuntimeException error) {
                clean = false;
                Log.w(TAG, "Failed to remove residual test provider " + provider, error);
            }
        }
        return clean;
    }

    private static void notifyCleanup(
            CleanupListener listener,
            boolean success,
            String message) {
        if (listener != null) {
            listener.onCleanupComplete(success, message == null ? "" : message);
        }
    }

    @SuppressLint("MissingPermission")
    private void enableGoogleFusedMock(int startGeneration) {
        if (!hasLocationPermission(context)) {
            throw new SecurityException("请允许定位权限，以便同步 Google 融合定位");
        }
        FusedLocationProviderClient client = LocationServices.getFusedLocationProviderClient(context);
        fusedClient = client;
        handler.removeCallbacks(fusedStartTimeoutTask);
        enqueueSetMockMode(
                client,
                true,
                () -> handler.post(() -> {
                    if (running
                            && generation == startGeneration
                            && fusedClient == client) {
                        handler.removeCallbacks(fusedStartTimeoutTask);
                        handler.postDelayed(
                                fusedStartTimeoutTask,
                                FUSED_START_TIMEOUT_MS);
                    }
                }))
                .addOnSuccessListener(unused -> {
                    if (!running || generation != startGeneration || fusedClient != client) {
                        return;
                    }
                    handler.removeCallbacks(fusedStartTimeoutTask);
                    fusedMockReady = true;
                    injectFusedLocation(true);
                })
                .addOnFailureListener(error -> {
                    if (running && generation == startGeneration && fusedClient == client) {
                        handler.removeCallbacks(fusedStartTimeoutTask);
                        fail("Google 融合定位模拟启动失败：" + readableMessage(error));
                    }
                });
    }

    private boolean hasGooglePlayServices() {
        return hasGooglePlayServices(context);
    }

    static boolean hasGooglePlayServices(Context context) {
        try {
            return GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context)
                    == ConnectionResult.SUCCESS;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private void ensureRuntimeAccess() {
        if (!isSelectedMockLocationApp(context)) {
            throw new SecurityException("模拟位置系统授权已被撤销");
        }
        if (!isSystemLocationEnabled(context)) {
            throw new IllegalStateException("Android 系统定位已关闭");
        }
        if (!hasLocationPermission(context)) {
            throw new SecurityException("定位权限已被撤销");
        }
    }

    @SuppressLint("WrongConstant")
    private void registerFrameworkProvider(
            String provider,
            boolean requiresNetwork,
            boolean requiresSatellite,
            boolean requiresCell,
            boolean fineAccuracy) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            Api31.addTestProvider(
                    locationManager,
                    provider,
                    requiresNetwork,
                    requiresSatellite,
                    requiresCell,
                    fineAccuracy);
        } else {
            locationManager.addTestProvider(
                    provider,
                    requiresNetwork,
                    requiresSatellite,
                    requiresCell,
                    false,
                    true,
                    true,
                    true,
                    requiresSatellite ? 3 : 1,
                    fineAccuracy ? 1 : 2);
        }
        registeredProviders.add(provider);
        locationManager.setTestProviderEnabled(provider, true);
    }

    private void injectFrameworkLocations() {
        MockGeoConfig.Selection current = selection;
        if (current == null) {
            return;
        }
        for (String provider : registeredProviders) {
            locationManager.setTestProviderLocation(provider, location(provider, current));
        }
    }

    @SuppressLint("MissingPermission")
    private void injectFusedLocation(boolean notifyWhenComplete) {
        MockGeoConfig.Selection current = selection;
        FusedLocationProviderClient client = fusedClient;
        if (!fusedMockReady || current == null || client == null) {
            return;
        }
        if (fusedUpdatePending) {
            fusedRefreshRequested = true;
            fusedNotifyRequested |= notifyWhenComplete;
            return;
        }
        fusedUpdatePending = true;
        int taskGeneration = generation;
        Task<Void> task = enqueueSetMockLocation(
                client,
                location(FUSED_PROVIDER, current));
        task.addOnSuccessListener(unused -> {
                    fusedUpdatePending = false;
                    boolean refreshAgain = fusedRefreshRequested;
                    boolean notifyAfterRefresh = fusedNotifyRequested;
                    fusedRefreshRequested = false;
                    fusedNotifyRequested = false;
                    if (refreshAgain && running && generation == taskGeneration) {
                        injectFusedLocation(notifyAfterRefresh || notifyWhenComplete);
                    } else if ((notifyWhenComplete || notifyAfterRefresh)
                            && running
                            && generation == taskGeneration) {
                        notifyActive();
                    }
                })
                .addOnFailureListener(error -> {
                    fusedUpdatePending = false;
                    fusedRefreshRequested = false;
                    fusedNotifyRequested = false;
                    if (running && generation == taskGeneration) {
                        fail("Google 融合定位更新失败：" + readableMessage(error));
                    }
                });
    }

    private Location location(String provider, MockGeoConfig.Selection current) {
        Location location = new Location(provider);
        location.setLatitude(current.latitude);
        location.setLongitude(current.longitude);
        location.setAccuracy(current.accuracyMeters);
        location.setTime(System.currentTimeMillis());
        location.setElapsedRealtimeNanos(SystemClock.elapsedRealtimeNanos());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            location.setMock(true);
        }
        return location;
    }

    private void notifyActive() {
        if (listener != null && running) {
            listener.onMockLocationActive();
        }
    }

    private void fail(String message) {
        stop();
        if (listener != null) {
            listener.onMockLocationError(message);
        }
    }

    private static String readableMessage(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return error.getClass().getSimpleName();
        }
        return message.trim();
    }

    @SuppressLint("MissingPermission")
    private static Task<Void> enqueueSetMockMode(
            FusedLocationProviderClient client,
            boolean enabled) {
        return enqueueSetMockMode(client, enabled, null);
    }

    @SuppressLint("MissingPermission")
    private static Task<Void> enqueueSetMockMode(
            FusedLocationProviderClient client,
            boolean enabled,
            Runnable onStarted) {
        return enqueueFusedOperation(() -> client.setMockMode(enabled), onStarted);
    }

    @SuppressLint("MissingPermission")
    private static Task<Void> enqueueSetMockLocation(
            FusedLocationProviderClient client,
            Location location) {
        return enqueueFusedOperation(() -> client.setMockLocation(location), null);
    }

    private static Task<Void> enqueueFusedOperation(
            FusedOperation operation,
            Runnable onStarted) {
        synchronized (FUSED_OPERATION_LOCK) {
            fusedOperationTail = fusedOperationTail.continueWithTask(ignored -> {
                try {
                    if (onStarted != null) {
                        onStarted.run();
                    }
                    return Tasks.withTimeout(
                            operation.run(),
                            FUSED_OPERATION_TIMEOUT_MS,
                            TimeUnit.MILLISECONDS);
                } catch (RuntimeException error) {
                    return Tasks.forException(error);
                }
            });
            return fusedOperationTail;
        }
    }

    private interface FusedOperation {
        Task<Void> run();
    }

    @TargetApi(Build.VERSION_CODES.S)
    private static final class Api31 {
        private Api31() {
        }

        static void addTestProvider(
                LocationManager manager,
                String provider,
                boolean requiresNetwork,
                boolean requiresSatellite,
                boolean requiresCell,
                boolean fineAccuracy) {
            ProviderProperties properties = new ProviderProperties.Builder()
                    .setHasNetworkRequirement(requiresNetwork)
                    .setHasSatelliteRequirement(requiresSatellite)
                    .setHasCellRequirement(requiresCell)
                    .setHasMonetaryCost(false)
                    .setHasAltitudeSupport(true)
                    .setHasSpeedSupport(true)
                    .setHasBearingSupport(true)
                    .setPowerUsage(requiresSatellite
                            ? ProviderProperties.POWER_USAGE_HIGH
                            : ProviderProperties.POWER_USAGE_LOW)
                    .setAccuracy(fineAccuracy
                            ? ProviderProperties.ACCURACY_FINE
                            : ProviderProperties.ACCURACY_COARSE)
                    .build();
            manager.addTestProvider(provider, properties);
        }
    }
}
