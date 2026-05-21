package com.ppaass.ai.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PpaassVpnService extends VpnService {
    public static final String ACTION_START = "com.ppaass.ai.agent.START";
    public static final String ACTION_STOP = "com.ppaass.ai.agent.STOP";
    public static final String PREF_RUNNING = "vpn_running";

    private static final String CHANNEL_ID = "ppaass_vpn";
    private static final int NOTIFICATION_ID = 7001;

    private long nativeHandle;
    private ParcelFileDescriptor tun;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopAgent();
        } else {
            startAgent();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopAgent();
        super.onDestroy();
    }

    private void startAgent() {
        if (nativeHandle != 0) {
            setRunning(true);
            return;
        }

        startForeground(NOTIFICATION_ID, notification());

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

            int rawFd = tun.detachFd();
            tun = null;
            nativeHandle = NativeAgent.start(rawFd, config.toString());
            setRunning(true);
        } catch (RuntimeException | JSONException error) {
            stopAgent();
            throw new IllegalStateException("Failed to start PPAASS VPN", error);
        }
    }

    private void stopAgent() {
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
        setRunning(false);
        stopSelf();
    }

    private void setRunning(boolean running) {
        getSharedPreferences("ppaass_agent", MODE_PRIVATE)
                .edit()
                .putBoolean(PREF_RUNNING, running)
                .apply();
    }

    private JSONObject buildConfigJson() throws JSONException {
        SharedPreferences prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);

        JSONObject tunJson = new JSONObject()
                .put("ipv4", prefs.getString("tun_ipv4", DefaultConfig.TUN_IPV4))
                .put("ipv6", prefs.getString("tun_ipv6", DefaultConfig.TUN_IPV6))
                .put("mtu", parseInt(prefs.getString("mtu", "1500"), 1500))
                .put("proxy_dns", true)
                .put("block_quic", prefs.getBoolean("block_quic", DefaultConfig.BLOCK_QUIC));
        JSONObject transportJson = new JSONObject()
                .put("tcp_mode", normalizeTcpMode(prefs.getString("tcp_mode", DefaultConfig.TCP_MODE)));
        JSONObject yamuxJson = new JSONObject()
                .put("sessions", parsePositiveInt(
                        prefs.getString("yamux_sessions", String.valueOf(DefaultConfig.YAMUX_SESSIONS)),
                        DefaultConfig.YAMUX_SESSIONS))
                .put("stream_window_size_kb", parseMinInt(
                        prefs.getString(
                                "yamux_stream_window_size_kb",
                                String.valueOf(DefaultConfig.YAMUX_STREAM_WINDOW_SIZE_KB)),
                        DefaultConfig.YAMUX_STREAM_WINDOW_SIZE_KB,
                        DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB));

        return new JSONObject()
                .put("proxy_addrs", new JSONArray(tokens(prefs.getString("proxy_addrs", DefaultConfig.PROXY_ADDR))))
                .put("username", prefs.getString("username", DefaultConfig.USERNAME))
                .put("private_key_pem", DefaultConfig.normalizePrivateKeyPem(
                        prefs.getString("private_key_pem", DefaultConfig.PRIVATE_KEY_PEM)))
                .put("connect_timeout_secs", 30)
                .put("tcp_pool_size", parseNonNegativeInt(
                        prefs.getString("tcp_pool_size", String.valueOf(DefaultConfig.TCP_POOL_SIZE)),
                        DefaultConfig.TCP_POOL_SIZE))
                .put("udp_pool_size", parseNonNegativeInt(
                        prefs.getString("udp_pool_size", String.valueOf(DefaultConfig.UDP_POOL_SIZE)),
                        DefaultConfig.UDP_POOL_SIZE))
                .put("transport", transportJson)
                .put("yamux", yamuxJson)
                .put("tun", tunJson);
    }

    private void applyAppSelection(Builder builder) {
        SharedPreferences prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        Set<String> selected = new HashSet<>(prefs.getStringSet("vpn_apps", Collections.emptySet()));
        selected.remove(getPackageName());

        if (selected.isEmpty()) {
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException ignored) {
            }
            return;
        }

        int allowed = 0;
        for (String packageName : selected) {
            try {
                builder.addAllowedApplication(packageName);
                allowed++;
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }

        if (allowed == 0) {
            throw new IllegalStateException("No selected VPN apps are installed");
        }
    }

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
                .setContentText("Running")
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

    private int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private int parseNonNegativeInt(String value, int fallback) {
        return Math.max(0, parseInt(value, fallback));
    }

    private int parsePositiveInt(String value, int fallback) {
        return Math.max(1, parseInt(value, fallback));
    }

    private int parseMinInt(String value, int fallback, int min) {
        return Math.max(min, parseInt(value, fallback));
    }

    private String normalizeTcpMode(String value) {
        if (value == null) {
            return DefaultConfig.TCP_MODE;
        }
        String normalized = value.trim().toLowerCase();
        if ("auto".equals(normalized) || "yamux".equals(normalized) || "legacy".equals(normalized)) {
            return normalized;
        }
        return DefaultConfig.TCP_MODE;
    }

    private List<String> tokens(String value) {
        List<String> result = new ArrayList<>();
        if (value == null) {
            return result;
        }
        for (String item : value.split("[,\\n]")) {
            String trimmed = item.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
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
