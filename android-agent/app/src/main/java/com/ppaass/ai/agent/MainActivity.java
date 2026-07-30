package com.ppaass.ai.agent;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.graphics.*;
import android.graphics.drawable.*;
import android.net.*;
import android.os.*;
import android.text.*;
import android.view.*;
import android.view.inputmethod.*;
import android.widget.*;

import org.json.*;

import java.io.*;
import java.net.*;
import java.security.*;
import java.text.*;
import java.util.*;

public class MainActivity extends MainActivityAccountManagement {
    private SharedPreferences agentSessionPreferences;
    private final SharedPreferences.OnSharedPreferenceChangeListener preferenceChangeListener =
            (sharedPreferences, key) -> {
                if (AgentSessionStore.PREF_PERMISSION_REVISION.equals(key)
                        || AgentAuthSession.PREF_SERVER_AUTHENTICATION_STATUS.equals(key)) {
                    runOnUiThread(this::refreshAgentPermissionUi);
                    return;
                }
                if (AgentAdminRequestStore.PREF_REVISION.equals(key)) {
                    runOnUiThread(this::onAdminRequestStateChanged);
                    return;
                }
                if (PpaassVpnService.PREF_RUNNING.equals(key)
                        || PpaassVpnService.PREF_SYSTEM_MANAGED.equals(key)
                        || PpaassVpnService.PREF_MOCK_GEO_REQUESTED.equals(key)
                        || PpaassVpnService.PREF_MOCK_GEO_ACTIVE.equals(key)
                        || PpaassVpnService.PREF_MOCK_GEO_STOPPING.equals(key)
                        || PpaassVpnService.PREF_MOCK_GEO_ERROR.equals(key)
                        || PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND.equals(key)
                         || PpaassVpnService.PREF_MOCK_GEO_DIRTY.equals(key)
                         || MockGeoConfig.PREF_MODE.equals(key)
                         || PpaassHttpProxyService.PREF_ENABLED.equals(key)
                         || PpaassHttpProxyService.PREF_RUNNING.equals(key)) {
                    runOnUiThread(() -> {
                        updateVpnToggle();
                        updateHttpProxyToggle();
                        refreshMockGeoUi();
                        updateStatusMetrics();
                        if (activityResumed
                                && sharedPreferences.getBoolean(
                                PpaassVpnService.PREF_MOCK_GEO_REQUESTED,
                                false)
                                && sharedPreferences.getBoolean(
                                PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND,
                                false)
                                && !sharedPreferences.getBoolean(
                                PpaassVpnService.PREF_MOCK_GEO_STOPPING,
                                false)
                                && !sharedPreferences.getBoolean(
                                PpaassVpnService.PREF_MOCK_GEO_DIRTY,
                                false)) {
                            // Run after the service callback has released its in-process
                            // cleanup owner; multiple preference notifications collapse
                            // because the first start removes the waiting flag.
                            statusHandler.post(() -> {
                                if (activityResumed
                                        && prefs.getBoolean(
                                        PpaassVpnService.PREF_MOCK_GEO_REQUESTED,
                                        false)
                                        && prefs.getBoolean(
                                        PpaassVpnService
                                                .PREF_MOCK_GEO_WAITING_FOR_FOREGROUND,
                                        false)
                                        && !prefs.getBoolean(
                                        PpaassVpnService.PREF_MOCK_GEO_STOPPING,
                                        false)
                                        && !prefs.getBoolean(
                                        PpaassVpnService.PREF_MOCK_GEO_DIRTY,
                                        false)) {
                                    syncMockGeoAfterResume();
                                }
                            });
                        }
                    });
                }
            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        if (!prefs.contains(PpaassVpnService.PREF_MOCK_GEO_REQUESTED)) {
            prefs.edit()
                    .putBoolean(
                            PpaassVpnService.PREF_MOCK_GEO_REQUESTED,
                            prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false))
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                    .apply();
        }
        restoreMockGeoInstanceState(savedInstanceState);
        cleanupStaleMockGeoState();
        UiPalette.apply(prefs.getString(UiPalette.PREF_COLOR_THEME, UiPalette.DEFAULT_THEME));
        reloadUiPalette();
        configureWindow();
        prefs.registerOnSharedPreferenceChangeListener(preferenceChangeListener);
        agentSessionPreferences = getSharedPreferences(
                ManagedCredentials.PREFERENCES_NAME,
                MODE_PRIVATE);
        agentSessionPreferences.registerOnSharedPreferenceChangeListener(
                preferenceChangeListener);
        showAgentEntry();
    }

    @Override
    protected void onResume() {
        super.onResume();
        activityResumed = true;
        if (!hasAuthenticatedAgentSession()) {
            if (!isAgentAuthenticationInProgress()) {
                onAgentSessionInvalidated();
            }
            return;
        }
        AgentProfileSyncManager.requestImmediateSync(this);
        maybeRequestAdminNotificationPermission();
        cleanupStaleMockGeoState();
        restoreHttpProxyServiceIfEnabled();
        updateVpnToggle();
        updateHttpProxyToggle();
        syncMockGeoAfterResume();
        startStatusRefresh();
    }

    public void refreshAgentPermissionUi() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            runOnUiThread(this::refreshAgentPermissionUi);
            return;
        }
        if (isFinishing()
                || isDestroyed()
                || !hasAuthenticatedAgentSession()
                || isAgentAuthenticationInProgress()) {
            return;
        }
        statusHandler.removeCallbacks(statusRefresh);
        String currentFingerprint = agentPermissionFingerprint();
        if (currentFingerprint.equals(appliedAgentPermissionFingerprint)) {
            if (activityResumed) {
                startStatusRefresh();
            } else {
                updateStatusMetrics();
            }
            return;
        }
        buildUi();
        if (activityResumed) {
            startStatusRefresh();
        }
    }

    @Override
    protected void onPause() {
        activityResumed = false;
        statusHandler.removeCallbacks(statusRefresh);
        super.onPause();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        saveMockGeoInstanceState(outState);
        super.onSaveInstanceState(outState);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (hasAuthenticatedAgentSession()) {
            openAdminApprovalScreenFromIntent();
        }
    }

    @Override
    protected void onDestroy() {
        statusHandler.removeCallbacks(statusRefresh);
        if (appSelectorDialog != null) {
            appSelectorDialog.dismiss();
            appSelectorDialog = null;
        }
        dismissMockGeoDialogs();
        if (prefs != null) {
            prefs.unregisterOnSharedPreferenceChangeListener(preferenceChangeListener);
        }
        if (agentSessionPreferences != null) {
            agentSessionPreferences.unregisterOnSharedPreferenceChangeListener(
                    preferenceChangeListener);
            agentSessionPreferences = null;
        }
        super.onDestroy();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_PERMISSION_REQUEST
                && resultCode == RESULT_OK
                && hasAuthenticatedAgentSession()) {
            startVpnService();
        }
    }

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            String[] permissions,
            int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == ADMIN_NOTIFICATION_PERMISSION_REQUEST) {
            onAdminNotificationPermissionResult(grantResults);
        } else {
            handleMockGeoPermissionResult(requestCode, grantResults);
        }
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent event) {
        handleScreenSwipeEvent(event);
        return super.dispatchTouchEvent(event);
    }

    @SuppressWarnings("deprecation")
    private void configureWindow() {
        getWindow().setStatusBarColor(COLOR_BACKGROUND);
        getWindow().setNavigationBarColor(COLOR_SURFACE);
        getWindow().getDecorView().setSystemUiVisibility(UiPalette.IS_LIGHT
                ? View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
                : 0);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            getWindow().setNavigationBarDividerColor(COLOR_BORDER);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            getWindow().setStatusBarContrastEnforced(false);
            getWindow().setNavigationBarContrastEnforced(false);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowInsetsController controller = getWindow().getInsetsController();
            if (controller != null) {
                int lightBars = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                        | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                controller.setSystemBarsAppearance(
                        UiPalette.IS_LIGHT ? lightBars : 0,
                        WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                                | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
            }
        }
    }
}
