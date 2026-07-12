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

public class MainActivity extends MainActivityScreens {
    private final SharedPreferences.OnSharedPreferenceChangeListener preferenceChangeListener =
            (sharedPreferences, key) -> {
                if (PpaassVpnService.PREF_RUNNING.equals(key)
                        || PpaassVpnService.PREF_SYSTEM_MANAGED.equals(key)
                        || PpaassHttpProxyService.PREF_RUNNING.equals(key)) {
                    runOnUiThread(() -> {
                        updateVpnToggle();
                        updateHttpProxyToggle();
                        updateStatusMetrics();
                    });
                }
            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        configureWindow();
        prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        prefs.registerOnSharedPreferenceChangeListener(preferenceChangeListener);
        buildUi();
    }

    @Override
    protected void onResume() {
        super.onResume();
        restoreHttpProxyServiceIfEnabled();
        updateVpnToggle();
        updateHttpProxyToggle();
        startStatusRefresh();
    }

    @Override
    protected void onPause() {
        statusHandler.removeCallbacks(statusRefresh);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        statusHandler.removeCallbacks(statusRefresh);
        if (appSelectorDialog != null) {
            appSelectorDialog.dismiss();
            appSelectorDialog = null;
        }
        if (prefs != null) {
            prefs.unregisterOnSharedPreferenceChangeListener(preferenceChangeListener);
        }
        super.onDestroy();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_PERMISSION_REQUEST && resultCode == RESULT_OK) {
            startVpnService();
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
        getWindow().getDecorView().setSystemUiVisibility(0);

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
                controller.setSystemBarsAppearance(
                        0,
                        WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                                | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
            }
        }
    }
}
