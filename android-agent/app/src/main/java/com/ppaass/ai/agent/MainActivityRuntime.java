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
abstract class MainActivityRuntime extends MainActivityDnsPanel {

protected void updateVpnToggle() {
        if (vpnToggle == null) {
            return;
        }

        boolean running = isVpnRunning();
        boolean systemManaged = prefs.getBoolean(PpaassVpnService.PREF_SYSTEM_MANAGED, false);
        String label = running ? "停止" : "启动";
        int actionColor = running ? COLOR_ACTION_STOP : COLOR_ACTION_START;
        updateFlipButton(label, actionColor, true);
        if (vpnStatus != null) {
            vpnStatus.setText(systemManaged ? "始终开启 VPN" : running ? "已连接" : "未连接");
            int statusColor = running ? COLOR_STATUS_RUNNING : COLOR_STATUS_STOPPED;
            vpnStatus.setTextColor(chipText(statusColor));
            vpnStatus.setBackground(rounded(chipFill(statusColor), chipFill(statusColor)));
        }
        updateConfigEditability(!running && !isHttpProxyRunning());
        updateConnectivityButton();
    }

protected void updateHttpProxyToggle() {
        if (httpProxyToggle == null) {
            return;
        }

        boolean running = isHttpProxyRunning();
        int actionColor = running ? COLOR_ACTION_STOP : COLOR_ACTION_START;
        httpProxyToggle.setText(running ? "停止" : "启动");
        applyActionButtonStyle(httpProxyToggle, actionColor);
        httpProxyToggle.setEnabled(true);
        updateHttpProxyEndpoint();
        updateConfigEditability(!isVpnRunning() && !running);
    }

protected void updateFlipButton(String label, int color, boolean enabled) {
        boolean shouldFlip = lastVpnToggleLabel != null && !label.equals(lastVpnToggleLabel);
        lastVpnToggleLabel = label;
        if (!shouldFlip) {
            vpnToggle.animate().cancel();
            vpnToggle.setRotationY(0f);
            applyToggleButtonState(label, color, enabled);
            return;
        }

        vpnToggle.animate()
                .rotationY(90f)
                .setDuration(110)
                .withEndAction(() -> {
                    applyToggleButtonState(label, color, enabled);
                    vpnToggle.setRotationY(-90f);
                    vpnToggle.animate().rotationY(0f).setDuration(110).start();
                })
                .start();
    }

protected void applyToggleButtonState(String label, int color, boolean enabled) {
        vpnToggle.setText(label);
        applyActionButtonStyle(vpnToggle, color);
        vpnToggle.setEnabled(enabled);
    }

protected void updateStatusMetrics() {
        long rxBytes = currentVpnDownloadBytes();
        long txBytes = currentVpnUploadBytes();
        long nowMs = SystemClock.elapsedRealtime();
        boolean resetDay = ensureTrafficDay(rxBytes, txBytes);

        long rxRate = 0;
        long txRate = 0;
        long deltaRx = 0;
        long deltaTx = 0;
        if (lastTrafficSampleMs > 0 && !resetDay) {
            long elapsedMs = Math.max(1, nowMs - lastTrafficSampleMs);
            deltaRx = Math.max(0, rxBytes - lastRxBytes);
            deltaTx = Math.max(0, txBytes - lastTxBytes);
            rxRate = deltaRx * 1000 / elapsedMs;
            txRate = deltaTx * 1000 / elapsedMs;
        }

        lastRxBytes = rxBytes;
        lastTxBytes = txBytes;
        lastTrafficSampleMs = nowMs;

        if (deltaRx > 0 || deltaTx > 0) {
            recordHourlyTraffic(deltaRx, deltaTx);
        }

        long downloadBytes = Math.max(0, rxBytes - prefs.getLong(PREF_TRAFFIC_RX_BASE, rxBytes));
        long uploadBytes = Math.max(0, txBytes - prefs.getLong(PREF_TRAFFIC_TX_BASE, txBytes));
        boolean running = isVpnRunning();
        if (!running) {
            rxRate = 0;
            txRate = 0;
        }

        if (downloadSpeed != null) {
            downloadSpeed.setText(formatSpeed(rxRate));
        }
        if (uploadSpeed != null) {
            uploadSpeed.setText(formatSpeed(txRate));
        }
        if (trafficDownload != null) {
            trafficDownload.setText(formatBytes(downloadBytes));
        }
        if (trafficUpload != null) {
            trafficUpload.setText(formatBytes(uploadBytes));
        }
        if (speedGauge != null) {
            speedGauge.setSpeeds(rxRate, txRate, running);
        }
        if (trafficChart != null) {
            trafficChart.setHourlyData(
                    hourlyDownloadBytes,
                    hourlyUploadBytes,
                    Calendar.getInstance().get(Calendar.HOUR_OF_DAY));
        }
        updateHttpProxyEndpoint();
        updateDnsRecords();
    }

protected void updateHttpProxyEndpoint() {
        if (httpProxyEndpointList == null) {
            return;
        }
        httpProxyEndpointList.removeAllViews();
        String port = String.valueOf(httpProxyListenPort());
        WifiAddresses wifiAddresses = currentWifiIpv4Addresses();
        if (!wifiAddresses.connected) {
            addHttpProxyEndpointLine("当前不在 Wi-Fi 下", true);
            return;
        }
        if (wifiAddresses.addresses.isEmpty()) {
            addHttpProxyEndpointLine("当前 Wi-Fi 未获取到可访问 IPv4 地址", true);
            return;
        }

        for (String address : wifiAddresses.addresses) {
            addHttpProxyEndpointLine(address + ":" + port, false);
        }
    }

protected void addHttpProxyEndpointLine(String text, boolean message) {
        if (httpProxyEndpointList.getChildCount() > 0) {
            addHttpProxyEndpointDivider();
        }
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(message ? COLOR_TEXT : Color.rgb(30, 41, 59));
        view.setTextSize(message ? 13.5f : 14.5f);
        view.setTypeface(message ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
        view.setSingleLine(true);
        view.setEllipsize(TextUtils.TruncateAt.END);
        view.setIncludeFontPadding(false);
        view.setPadding(0, dp(2), 0, dp(2));
        httpProxyEndpointList.addView(view, matchWrap());
    }

protected void addHttpProxyEndpointDivider() {
        View divider = new View(this);
        divider.setBackgroundColor(COLOR_BORDER);
        LinearLayout.LayoutParams params = matchWrap();
        params.height = 1;
        params.setMargins(0, dp(7), 0, dp(7));
        httpProxyEndpointList.addView(divider, params);
    }

@SuppressWarnings("deprecation")
    protected WifiAddresses currentWifiIpv4Addresses() {
        List<String> addresses = new ArrayList<>();
        boolean connected = false;
        ConnectivityManager connectivityManager =
                (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            return new WifiAddresses(false, addresses);
        }

        Network[] networks = connectivityManager.getAllNetworks();
        for (Network network : networks) {
            NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
            if (capabilities == null
                    || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                continue;
            }

            LinkProperties properties = connectivityManager.getLinkProperties(network);
            if (properties == null) {
                continue;
            }
            connected = true;
            if (isInternalNetworkInterface(properties.getInterfaceName())) {
                continue;
            }

            for (LinkAddress linkAddress : properties.getLinkAddresses()) {
                InetAddress address = linkAddress.getAddress();
                if (address instanceof Inet4Address
                        && isDisplayableWifiAddress((Inet4Address) address)) {
                    String hostAddress = address.getHostAddress();
                    if (!addresses.contains(hostAddress)) {
                        addresses.add(hostAddress);
                    }
                }
            }
        }
        Collections.sort(addresses);
        return new WifiAddresses(connected, addresses);
    }

protected boolean isDisplayableWifiAddress(Inet4Address address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }
        String hostAddress = address.getHostAddress();
        return !isAgentTunAddress(hostAddress) && !isAndroidEmulatorNatAddress(hostAddress);
    }

protected boolean isAgentTunAddress(String hostAddress) {
        String tunAddress = DefaultConfig.TUN_IPV4;
        int slash = tunAddress.indexOf('/');
        if (slash >= 0) {
            tunAddress = tunAddress.substring(0, slash);
        }
        if (hostAddress.equals(tunAddress)) {
            return true;
        }
        int lastDot = tunAddress.lastIndexOf('.');
        return lastDot > 0 && hostAddress.startsWith(tunAddress.substring(0, lastDot + 1));
    }

protected boolean isAndroidEmulatorNatAddress(String hostAddress) {
        if (!hostAddress.startsWith("10.0.2.")) {
            return false;
        }
        String fingerprint = Build.FINGERPRINT == null ? "" : Build.FINGERPRINT;
        String model = Build.MODEL == null ? "" : Build.MODEL;
        String hardware = Build.HARDWARE == null ? "" : Build.HARDWARE;
        return fingerprint.contains("generic") || model.contains("sdk") || hardware.contains("ranchu");
    }

protected boolean isInternalNetworkInterface(String interfaceName) {
        if (interfaceName == null) {
            return false;
        }
        String name = interfaceName.toLowerCase(Locale.US);
        return name.startsWith("lo")
                || name.startsWith("tun")
                || name.startsWith("utun")
                || name.startsWith("ppp")
                || name.startsWith("wg")
                || name.startsWith("ipsec")
                || name.startsWith("dummy")
                || name.startsWith("clat");
    }

protected static final class WifiAddresses {
        final boolean connected;
        final List<String> addresses;

        WifiAddresses(boolean connected, List<String> addresses) {
            this.connected = connected;
            this.addresses = addresses;
        }
    }

protected boolean ensureTrafficDay(long rxBytes, long txBytes) {
        String today = new SimpleDateFormat("yyyyMMdd", Locale.US).format(new Date());
        String storedDay = prefs.getString(PREF_TRAFFIC_DAY, "");
        long storedBase = prefs.getLong(PREF_TRAFFIC_RX_BASE, rxBytes);
        long storedTxBase = prefs.getLong(PREF_TRAFFIC_TX_BASE, txBytes);
        if (today.equals(storedDay) && storedBase <= rxBytes && storedTxBase <= txBytes) {
            return false;
        }

        for (int i = 0; i < hourlyDownloadBytes.length; i++) {
            hourlyDownloadBytes[i] = 0;
            hourlyUploadBytes[i] = 0;
        }
        prefs.edit()
                .putString(PREF_TRAFFIC_DAY, today)
                .putLong(PREF_TRAFFIC_RX_BASE, rxBytes)
                .putLong(PREF_TRAFFIC_TX_BASE, txBytes)
                .putString(PREF_TRAFFIC_HOURLY, serializeHourlyTraffic(hourlyDownloadBytes))
                .putString(PREF_TRAFFIC_TX_HOURLY, serializeHourlyTraffic(hourlyUploadBytes))
                .apply();
        return true;
    }

protected void recordHourlyTraffic(long deltaRx, long deltaTx) {
        int hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
        hourlyDownloadBytes[hour] = Math.max(0, hourlyDownloadBytes[hour] + deltaRx);
        hourlyUploadBytes[hour] = Math.max(0, hourlyUploadBytes[hour] + deltaTx);
        prefs.edit()
                .putString(PREF_TRAFFIC_HOURLY, serializeHourlyTraffic(hourlyDownloadBytes))
                .putString(PREF_TRAFFIC_TX_HOURLY, serializeHourlyTraffic(hourlyUploadBytes))
                .apply();
    }

protected void loadHourlyTrafficState() {
        for (int i = 0; i < hourlyDownloadBytes.length; i++) {
            hourlyDownloadBytes[i] = 0;
            hourlyUploadBytes[i] = 0;
        }
        loadHourlyTraffic(PREF_TRAFFIC_HOURLY, hourlyDownloadBytes);
        loadHourlyTraffic(PREF_TRAFFIC_TX_HOURLY, hourlyUploadBytes);
    }

protected void loadHourlyTraffic(String key, long[] target) {
        String serialized = prefs == null ? "" : prefs.getString(key, "");
        if (serialized == null || serialized.isEmpty()) {
            return;
        }
        String[] parts = serialized.split(",");
        for (int i = 0; i < parts.length && i < target.length; i++) {
            try {
                target[i] = Math.max(0, Long.parseLong(parts[i]));
            } catch (NumberFormatException ignored) {
                target[i] = 0;
            }
        }
    }

protected String serializeHourlyTraffic(long[] values) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                builder.append(',');
            }
            builder.append(values[i]);
        }
        return builder.toString();
    }

}
