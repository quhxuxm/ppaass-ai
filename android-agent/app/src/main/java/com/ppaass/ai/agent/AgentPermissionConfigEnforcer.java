package com.ppaass.ai.agent;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

import java.util.Map;

final class AgentPermissionConfigEnforcer {
    private static final String TAG = "PpaassPermission";

    private AgentPermissionConfigEnforcer() {
    }

    static boolean enforce(Context context, boolean reloadRunningAgents) {
        boolean canCapture = AgentAuthSession.hasPermission(
                context,
                AgentPermissions.PACKET_CAPTURE);
        boolean canEditEgress = AgentAuthSession.hasPermission(
                context,
                AgentPermissions.EGRESS_EDIT);
        boolean canEditRuntime = AgentAuthSession.hasPermission(
                context,
                AgentPermissions.RUNTIME_THREADS_EDIT);

        if (!canCapture) {
            disablePacketCapture(context);
        }

        SharedPreferences preferences = context.getSharedPreferences(
                AgentPermissionConfigPolicy.PREFS_NAME,
                Context.MODE_PRIVATE);
        Map<String, String> requiredDefaults =
                AgentPermissionConfigPolicy.requiredDefaults(
                        canEditEgress,
                        canEditRuntime);
        SharedPreferences.Editor editor = preferences.edit();
        boolean changed = false;
        if (preferences.contains(
                AgentPermissionConfigPolicy.LEGACY_PROXY_ADDRESS_KEY)) {
            editor.remove(AgentPermissionConfigPolicy.LEGACY_PROXY_ADDRESS_KEY);
            changed = true;
        }
        for (Map.Entry<String, String> entry : requiredDefaults.entrySet()) {
            String current;
            try {
                current = preferences.getString(entry.getKey(), null);
            } catch (ClassCastException error) {
                current = null;
            }
            if (!entry.getValue().equals(current)) {
                editor.putString(entry.getKey(), entry.getValue());
                changed = true;
            }
        }
        if (!changed) {
            return false;
        }
        if (!editor.commit()) {
            Log.e(TAG, "Failed to persist permission-controlled config defaults");
            return false;
        }
        Log.i(TAG, "Applied permission-controlled config defaults");
        if (reloadRunningAgents) {
            reloadRunningAgents(context);
        }
        return true;
    }

    private static void disablePacketCapture(Context context) {
        try {
            NativeAgent.setPacketCaptureEnabled(
                    context.getFilesDir().toPath()
                            .resolve("captures")
                            .resolve("ppaass-tun.pcap")
                            .toString(),
                    false);
        } catch (RuntimeException error) {
            Log.w(TAG, "Packet capture could not be disabled immediately", error);
        }
    }

    static void reloadRunningAgents(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(
                AgentPermissionConfigPolicy.PREFS_NAME,
                Context.MODE_PRIVATE);
        if (preferences.getBoolean(PpaassVpnService.PREF_RUNNING, false)
                || PpaassVpnService.isRunningInProcess()) {
            sendReload(context, PpaassVpnService.class, PpaassVpnService.ACTION_RELOAD);
        }
        if (preferences.getBoolean(PpaassHttpProxyService.PREF_RUNNING, false)
                || PpaassHttpProxyService.isRunningInProcess()) {
            sendReload(
                    context,
                    PpaassHttpProxyService.class,
                    PpaassHttpProxyService.ACTION_RELOAD);
        }
    }

    static void stopRunningAgents(Context context) {
        context.getSharedPreferences(
                AgentPermissionConfigPolicy.PREFS_NAME,
                Context.MODE_PRIVATE)
                .edit()
                .putBoolean(PpaassHttpProxyService.PREF_ENABLED, false)
                .apply();
        sendServiceAction(context, PpaassVpnService.class, PpaassVpnService.ACTION_STOP);
        sendServiceAction(
                context,
                PpaassHttpProxyService.class,
                PpaassHttpProxyService.ACTION_STOP);
    }

    private static void sendReload(
            Context context,
            Class<?> serviceClass,
            String action) {
        sendServiceAction(context, serviceClass, action);
    }

    private static void sendServiceAction(
            Context context,
            Class<?> serviceClass,
            String action) {
        Intent intent = new Intent(context, serviceClass);
        intent.setAction(action);
        try {
            context.startService(intent);
        } catch (RuntimeException error) {
            Log.e(TAG, "Failed to apply an Agent service action", error);
            if (PpaassVpnService.ACTION_STOP.equals(action)
                    || PpaassHttpProxyService.ACTION_STOP.equals(action)) {
                context.stopService(intent);
            }
        }
    }
}
