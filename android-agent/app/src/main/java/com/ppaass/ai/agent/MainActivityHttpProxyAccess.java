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

// HTTP / SOCKS5 代理入口地址集中在这里，避免状态页和运行时逻辑互相拖长。
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
            addHttpProxyEndpointLine(httpProxyEndpointList, explicitProxyEndpoint(address, port), false);
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
                    configured ? "USB 网络共享地址暂未被电脑识别" : "等待 USB 网络共享地址",
                    true);
            addHttpProxyEndpointLine(
                    httpProxyUsbEndpointList,
                    "备用 ADB 转发  127.0.0.1:" + port,
                    false);
            updateHttpProxyUsbAction("复制命令");
            updateHttpProxyUsbHint(configured
                    ? "优先使用系统 USB 网络共享；电脑侧未识别时，可备用复制 adb forward 命令"
                    : "主要方式是打开系统 USB 网络共享；ADB forward 仅作为备用调试方式");
            return;
        }

        for (String address : addresses) {
            addHttpProxyEndpointLine(httpProxyUsbEndpointList, explicitProxyEndpoint(address, port), false);
        }
        addHttpProxyEndpointLine(
                httpProxyUsbEndpointList,
                "备用 ADB 转发  127.0.0.1:" + port,
                false);
        updateHttpProxyUsbAction("复制地址");
        updateHttpProxyUsbHint("优先使用上方 USB 网络共享地址；ADB forward 可作为备用方式");
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
            addHttpProxyEndpointLine(httpProxyBluetoothEndpointList, explicitProxyEndpoint(address, port), false);
        }
        updateHttpProxyBluetoothAction("复制地址");
        updateHttpProxyBluetoothHint("电脑 HTTP 与 SOCKS5 代理都填上方同一个地址");
    }

    protected void handleHttpProxyUsbAction() {
        List<String> addresses = currentUsbTetherIpv4Addresses();
        if (addresses.isEmpty()) {
            copyUsbDebugForwardCommand();
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

    protected void copyUsbDebugForwardCommand() {
        android.content.ClipboardManager clipboard =
                (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "无法访问剪贴板", Toast.LENGTH_SHORT).show();
            return;
        }
        clipboard.setPrimaryClip(ClipData.newPlainText(
                "PPAASS USB 调试转发命令",
                adbForwardCommand()));
        Toast.makeText(this, "已复制 USB 调试转发命令", Toast.LENGTH_SHORT).show();
    }

    protected void copyHttpProxyEndpoint(String endpoint, String channelLabel) {
        android.content.ClipboardManager clipboard =
                (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "无法访问剪贴板", Toast.LENGTH_SHORT).show();
            return;
        }
        clipboard.setPrimaryClip(ClipData.newPlainText(
                "PPAASS HTTP / SOCKS5 代理 " + channelLabel + "入口",
                endpoint));
        Toast.makeText(this, "已复制" + channelLabel + "显式代理地址", Toast.LENGTH_SHORT).show();
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
        view.setTextColor(message ? COLOR_TEXT : COLOR_ACCENT_DARK);
        view.setTextSize(message ? 13.5f : 14.5f);
        view.setTypeface(message ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
        view.setSingleLine(true);
        view.setEllipsize(TextUtils.TruncateAt.END);
        view.setIncludeFontPadding(false);
        view.setPadding(0, dp(2), 0, dp(2));
        target.addView(view, matchWrap());
    }

    protected String explicitProxyEndpoint(String address, String port) {
        return address + ":" + port;
    }

    protected String adbForwardCommand() {
        int port = httpProxyListenPort();
        return "adb forward tcp:" + port + " tcp:" + port;
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
