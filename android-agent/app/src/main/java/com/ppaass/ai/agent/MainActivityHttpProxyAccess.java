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

// HTTP Proxy 入口地址集中在这里，避免状态页和运行时逻辑互相拖长。
abstract class MainActivityHttpProxyAccess extends MainActivityHttpProxyAddressDiscovery {

    protected void updateHttpProxyEndpoint() {
        updateHttpProxyUsbAccess();
        updateHttpProxyBluetoothAccess();
        if (httpProxyEndpointList == null) {
            return;
        }
        httpProxyEndpointList.removeAllViews();
        String port = String.valueOf(httpProxyListenPort());
        WifiAddresses wifiAddresses = currentWifiIpv4Addresses();
        List<String> addresses = new ArrayList<>(wifiAddresses.addresses);
        for (String hotspotAddress : currentWifiHotspotIpv4Addresses()) {
            if (!addresses.contains(hotspotAddress)) {
                addresses.add(hotspotAddress);
            }
        }
        Collections.sort(addresses);

        if (addresses.isEmpty() && wifiAddresses.connected) {
            addHttpProxyEndpointLine(httpProxyEndpointList, "当前 Wi-Fi 未获取到可访问 IPv4 地址", true);
            return;
        }
        if (addresses.isEmpty()) {
            addHttpProxyEndpointLine(httpProxyEndpointList, "当前不在 Wi-Fi 下，且未检测到热点地址", true);
            return;
        }

        for (String address : addresses) {
            addHttpProxyEndpointLine(httpProxyEndpointList, address + ":" + port, false);
        }
    }

    protected void updateHttpProxyUsbAccess() {
        if (httpProxyUsbEndpointList == null) {
            return;
        }
        httpProxyUsbEndpointList.removeAllViews();
        String port = String.valueOf(httpProxyListenPort());
        List<String> addresses = currentUsbTetherIpv4Addresses();
        if (addresses.isEmpty()) {
            boolean configured = hasConfiguredUsbTetherAddress();
            addHttpProxyEndpointLine(
                    httpProxyUsbEndpointList,
                    configured ? "电脑未识别 USB 网络共享" : "未检测到 USB 网络共享地址",
                    true);
            updateHttpProxyUsbAction("打开设置");
            updateHttpProxyUsbHint(configured
                    ? "系统已开启共享，但电脑侧未建立 USB 网络"
                    : isUsbCableConnected()
                    ? "在系统里开启 USB 网络共享后会显示地址"
                    : "用 USB 连接电脑，并开启系统 USB 网络共享");
            return;
        }

        for (String address : addresses) {
            addHttpProxyEndpointLine(httpProxyUsbEndpointList, address + ":" + port, false);
        }
        updateHttpProxyUsbAction("复制地址");
        updateHttpProxyUsbHint("电脑浏览器代理填上方地址，无需额外工具");
    }

    protected void updateHttpProxyBluetoothAccess() {
        if (httpProxyBluetoothEndpointList == null) {
            return;
        }
        httpProxyBluetoothEndpointList.removeAllViews();
        String port = String.valueOf(httpProxyListenPort());
        List<String> addresses = currentBluetoothTetherIpv4Addresses();
        if (addresses.isEmpty()) {
            boolean configured = hasConfiguredBluetoothTetherAddress();
            addHttpProxyEndpointLine(
                    httpProxyBluetoothEndpointList,
                    configured ? "电脑未识别蓝牙网络共享" : "未检测到蓝牙网络共享地址",
                    true);
            updateHttpProxyBluetoothAction("打开设置");
            updateHttpProxyBluetoothHint(configured
                    ? "系统已开启共享，但电脑侧未建立蓝牙网络"
                    : "配对电脑，并在系统里开启蓝牙网络共享");
            return;
        }

        for (String address : addresses) {
            addHttpProxyEndpointLine(httpProxyBluetoothEndpointList, address + ":" + port, false);
        }
        updateHttpProxyBluetoothAction("复制地址");
        updateHttpProxyBluetoothHint("电脑浏览器代理填上方地址，无需同一 Wi-Fi");
    }

    protected void handleHttpProxyUsbAction() {
        List<String> addresses = currentUsbTetherIpv4Addresses();
        if (addresses.isEmpty()) {
            openUsbTetherSettings();
            return;
        }
        copyHttpProxyUsbEndpoint(addresses.get(0) + ":" + httpProxyListenPort());
    }

    protected void handleHttpProxyBluetoothAction() {
        List<String> addresses = currentBluetoothTetherIpv4Addresses();
        if (addresses.isEmpty()) {
            openTetherSettings();
            return;
        }
        copyHttpProxyBluetoothEndpoint(addresses.get(0) + ":" + httpProxyListenPort());
    }

    protected void copyHttpProxyUsbEndpoint(String endpoint) {
        copyHttpProxyEndpoint(endpoint, "USB");
    }

    protected void copyHttpProxyBluetoothEndpoint(String endpoint) {
        copyHttpProxyEndpoint(endpoint, "蓝牙");
    }

    protected void copyHttpProxyEndpoint(String endpoint, String channelLabel) {
        android.content.ClipboardManager clipboard =
                (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "无法访问剪贴板", Toast.LENGTH_SHORT).show();
            return;
        }
        clipboard.setPrimaryClip(ClipData.newPlainText(
                "PPAASS HTTP Proxy " + channelLabel + " Endpoint",
                endpoint));
        Toast.makeText(this, "已复制" + channelLabel + "代理地址", Toast.LENGTH_SHORT).show();
    }

    protected void openUsbTetherSettings() {
        openTetherSettings();
    }

    protected void openTetherSettings() {
        Intent intent = new Intent("android.settings.TETHER_SETTINGS");
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException ignored) {
            startActivity(new Intent(android.provider.Settings.ACTION_SETTINGS));
        }
    }

    protected void updateHttpProxyBluetoothHint(String text) {
        if (httpProxyBluetoothHint != null) {
            httpProxyBluetoothHint.setText(text);
        }
    }

    protected void updateHttpProxyUsbHint(String text) {
        if (httpProxyUsbHint != null) {
            httpProxyUsbHint.setText(text);
        }
    }

    protected void updateHttpProxyUsbAction(String text) {
        if (httpProxyUsbActionButton != null) {
            httpProxyUsbActionButton.setText(text);
            httpProxyUsbActionButton.setEnabled(true);
        }
    }

    protected void updateHttpProxyBluetoothAction(String text) {
        if (httpProxyBluetoothActionButton != null) {
            httpProxyBluetoothActionButton.setText(text);
            httpProxyBluetoothActionButton.setEnabled(true);
        }
    }

    protected boolean isUsbCableConnected() {
        Intent status = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (status == null) {
            return false;
        }
        int plugged = status.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);
        return (plugged & BatteryManager.BATTERY_PLUGGED_USB) != 0;
    }

    protected void addHttpProxyEndpointLine(LinearLayout target, String text, boolean message) {
        if (target == null) {
            return;
        }
        if (target.getChildCount() > 0) {
            addHttpProxyEndpointDivider(target);
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
        target.addView(view, matchWrap());
    }

    protected void addHttpProxyEndpointDivider(LinearLayout target) {
        View divider = new View(this);
        divider.setBackgroundColor(COLOR_BORDER);
        LinearLayout.LayoutParams params = matchWrap();
        params.height = 1;
        params.setMargins(0, dp(7), 0, dp(7));
        target.addView(divider, params);
    }

}
