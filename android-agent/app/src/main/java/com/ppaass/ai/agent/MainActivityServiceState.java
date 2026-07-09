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

// MainActivity 拆分层：保持单个文件短小，便于定位 Android UI 问题。
abstract class MainActivityServiceState extends MainActivityConfig {

protected void toggleVpn() {
        if (isVpnRunning()) {
            stopVpnService();
            return;
        }

        saveConfig();
        Intent permissionIntent = VpnService.prepare(this);
        if (permissionIntent != null) {
            startActivityForResult(permissionIntent, VPN_PERMISSION_REQUEST);
        } else {
            startVpnService();
        }
    }

protected void startVpnService() {
        Intent intent = new Intent(this, PpaassVpnService.class);
        intent.setAction(PpaassVpnService.ACTION_START);
        intent.putExtra(PpaassVpnService.EXTRA_STARTED_BY_APP, true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        updateVpnToggle();
    }

protected void stopVpnService() {
        Intent intent = new Intent(this, PpaassVpnService.class);
        intent.setAction(PpaassVpnService.ACTION_STOP);
        startService(intent);
        updateVpnToggle();
    }

protected void toggleHttpProxy() {
        if (isHttpProxyRunning()) {
            stopHttpProxyService();
            return;
        }

        saveConfig();
        startHttpProxyService();
    }

protected void startHttpProxyService() {
        prefs.edit()
                .putBoolean(PpaassHttpProxyService.PREF_ENABLED, true)
                .apply();
        sendHttpProxyStartIntent();
        updateHttpProxyToggle();
    }

protected void sendHttpProxyStartIntent() {
        Intent intent = new Intent(this, PpaassHttpProxyService.class);
        intent.setAction(PpaassHttpProxyService.ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

protected void stopHttpProxyService() {
        prefs.edit()
                .putBoolean(PpaassHttpProxyService.PREF_ENABLED, false)
                .apply();
        Intent intent = new Intent(this, PpaassHttpProxyService.class);
        intent.setAction(PpaassHttpProxyService.ACTION_STOP);
        startService(intent);
        updateHttpProxyToggle();
    }

protected void showHttpProxyClientsDialog() {
        new HttpProxyClientDialog(this, prefs).show();
    }

protected boolean isVpnRunning() {
        boolean running = prefs.getBoolean(PpaassVpnService.PREF_RUNNING, false);
        if (running && !PpaassVpnService.isRunningInProcess()) {
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_RUNNING, false)
                    .putBoolean(PpaassVpnService.PREF_SYSTEM_MANAGED, false)
                    .apply();
            return false;
        }
        return running;
    }

protected boolean isHttpProxyRunning() {
        boolean enabled = prefs.getBoolean(PpaassHttpProxyService.PREF_ENABLED, false);
        boolean running = prefs.getBoolean(PpaassHttpProxyService.PREF_RUNNING, false);
        if (running && !PpaassHttpProxyService.isRunningInProcess()) {
            if (enabled) {
                restoreHttpProxyServiceIfEnabled();
                return true;
            }
            prefs.edit()
                    .putBoolean(PpaassHttpProxyService.PREF_RUNNING, false)
                    .apply();
            return false;
        }
        if (!running && enabled && !PpaassHttpProxyService.isRunningInProcess()) {
            restoreHttpProxyServiceIfEnabled();
            return true;
        }
        return running;
    }

protected void restoreHttpProxyServiceIfEnabled() {
        if (!prefs.getBoolean(PpaassHttpProxyService.PREF_ENABLED, false)
                || PpaassHttpProxyService.isRunningInProcess()) {
            return;
        }

        long nowMs = SystemClock.elapsedRealtime();
        if (nowMs - lastHttpProxyRestoreAttemptMs < 5_000L) {
            return;
        }
        lastHttpProxyRestoreAttemptMs = nowMs;
        sendHttpProxyStartIntent();
    }

protected void startStatusRefresh() {
        statusHandler.removeCallbacks(statusRefresh);
        updateStatusMetrics();
        statusHandler.postDelayed(statusRefresh, 1000);
    }

protected long currentVpnDownloadBytes() {
        return Math.max(0, NativeAgent.vpnDownloadBytes());
    }

protected long currentVpnUploadBytes() {
        return Math.max(0, NativeAgent.vpnUploadBytes());
    }

}
