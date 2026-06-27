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
abstract class MainActivityHttpProxyAccess extends MainActivityDnsPanel {

    protected void updateHttpProxyEndpoint() {
        updateHttpProxyUsbAccess();
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

    protected void handleHttpProxyUsbAction() {
        List<String> addresses = currentUsbTetherIpv4Addresses();
        if (addresses.isEmpty()) {
            openUsbTetherSettings();
            return;
        }
        copyHttpProxyUsbEndpoint(addresses.get(0) + ":" + httpProxyListenPort());
    }

    protected void copyHttpProxyUsbEndpoint(String endpoint) {
        android.content.ClipboardManager clipboard =
                (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "无法访问剪贴板", Toast.LENGTH_SHORT).show();
            return;
        }
        clipboard.setPrimaryClip(ClipData.newPlainText(
                "PPAASS HTTP Proxy USB Endpoint",
                endpoint));
        Toast.makeText(this, "已复制 USB 代理地址", Toast.LENGTH_SHORT).show();
    }

    protected void openUsbTetherSettings() {
        Intent intent = new Intent("android.settings.TETHER_SETTINGS");
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException ignored) {
            startActivity(new Intent(android.provider.Settings.ACTION_SETTINGS));
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

    protected boolean isUsbCableConnected() {
        Intent status = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (status == null) {
            return false;
        }
        int plugged = status.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);
        return (plugged & BatteryManager.BATTERY_PLUGGED_USB) != 0;
    }

    protected List<String> currentUsbTetherIpv4Addresses() {
        List<String> addresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!isUsbTetherInterface(networkInterface.getName()) || !networkInterface.isUp()) {
                    continue;
                }
                collectUsbTetherAddresses(networkInterface, addresses);
            }
        } catch (SocketException ignored) {
            addresses.clear();
        }
        Collections.sort(addresses);
        return addresses;
    }

    protected boolean hasConfiguredUsbTetherAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!isUsbTetherInterface(networkInterface.getName())) {
                    continue;
                }
                Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress address = inetAddresses.nextElement();
                    if (address instanceof Inet4Address
                            && isDisplayableUsbTetherAddress((Inet4Address) address)) {
                        return true;
                    }
                }
            }
        } catch (SocketException ignored) {
            return false;
        }
        return false;
    }

    protected void collectUsbTetherAddresses(NetworkInterface networkInterface, List<String> addresses) {
        Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
        while (inetAddresses.hasMoreElements()) {
            InetAddress address = inetAddresses.nextElement();
            if (address instanceof Inet4Address
                    && isDisplayableUsbTetherAddress((Inet4Address) address)) {
                String hostAddress = address.getHostAddress();
                if (!addresses.contains(hostAddress)) {
                    addresses.add(hostAddress);
                }
            }
        }
    }

    protected boolean isUsbTetherInterface(String interfaceName) {
        if (interfaceName == null) {
            return false;
        }
        String name = interfaceName.toLowerCase(Locale.US);
        return name.startsWith("rndis")
                || name.startsWith("usb")
                || name.startsWith("ncm")
                || name.startsWith("ecm");
    }

    protected boolean isDisplayableUsbTetherAddress(Inet4Address address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }
        String hostAddress = address.getHostAddress();
        return !isAgentTunAddress(hostAddress) && !isAndroidEmulatorNatAddress(hostAddress);
    }

    protected List<String> currentWifiHotspotIpv4Addresses() {
        List<String> addresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!networkInterface.isUp()
                        || !isWifiHotspotInterface(networkInterface.getName())) {
                    continue;
                }
                collectWifiHotspotAddresses(networkInterface, addresses);
            }
        } catch (SocketException ignored) {
            addresses.clear();
        }
        return addresses;
    }

    protected void collectWifiHotspotAddresses(NetworkInterface networkInterface, List<String> addresses) {
        Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
        while (inetAddresses.hasMoreElements()) {
            InetAddress address = inetAddresses.nextElement();
            if (address instanceof Inet4Address
                    && isDisplayableWifiAddress((Inet4Address) address)) {
                String hostAddress = address.getHostAddress();
                if (!addresses.contains(hostAddress)) {
                    addresses.add(hostAddress);
                }
            }
        }
    }

    protected boolean isWifiHotspotInterface(String interfaceName) {
        if (interfaceName == null) {
            return false;
        }
        String name = interfaceName.toLowerCase(Locale.US);
        return name.startsWith("ap")
                || name.startsWith("br")
                || name.startsWith("swlan")
                || name.startsWith("softap")
                || name.startsWith("wifi")
                || name.startsWith("wlan");
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

}
