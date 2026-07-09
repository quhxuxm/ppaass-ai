package com.ppaass.ai.agent;

import android.net.*;
import android.os.*;

import java.net.*;
import java.util.*;

// HTTP Proxy 可访问地址发现集中在这里，避免 UI 刷新逻辑掺入接口细节。
abstract class MainActivityHttpProxyAddressDiscovery extends MainActivityDnsPanel {

    protected List<String> currentUsbTetherIpv4Addresses() {
        return currentTetherIpv4Addresses(this::isUsbTetherInterface, this::isDisplayableUsbTetherAddress);
    }

    protected boolean hasConfiguredUsbTetherAddress() {
        return hasConfiguredTetherAddress(this::isUsbTetherInterface, this::isDisplayableUsbTetherAddress);
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
        return isDisplayableLanAddress(address);
    }

    protected List<String> currentBluetoothTetherIpv4Addresses() {
        return currentTetherIpv4Addresses(
                this::isBluetoothTetherInterface,
                this::isDisplayableBluetoothTetherAddress);
    }

    protected boolean hasConfiguredBluetoothTetherAddress() {
        return hasConfiguredTetherAddress(
                this::isBluetoothTetherInterface,
                this::isDisplayableBluetoothTetherAddress);
    }

    protected boolean isBluetoothTetherInterface(String interfaceName) {
        if (interfaceName == null) {
            return false;
        }
        String name = interfaceName.toLowerCase(Locale.US);
        return name.startsWith("bnep")
                || name.startsWith("bt-pan")
                || name.startsWith("bt_pan")
                || name.startsWith("bt")
                || name.startsWith("pan");
    }

    protected boolean isDisplayableBluetoothTetherAddress(Inet4Address address) {
        return isDisplayableLanAddress(address);
    }

    protected List<String> currentWifiHotspotIpv4Addresses() {
        return currentTetherIpv4Addresses(
                this::isWifiHotspotInterface,
                this::isDisplayableWifiAddress);
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

    @SuppressWarnings("deprecation")
    protected WifiAddresses currentWifiIpv4Addresses() {
        List<String> addresses = new ArrayList<>();
        boolean connected = false;
        ConnectivityManager connectivityManager =
                (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
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
            collectWifiLinkAddresses(properties, addresses);
        }
        Collections.sort(addresses);
        return new WifiAddresses(connected, addresses);
    }

    protected void collectWifiLinkAddresses(LinkProperties properties, List<String> addresses) {
        if (isInternalNetworkInterface(properties.getInterfaceName())) {
            return;
        }
        for (LinkAddress linkAddress : properties.getLinkAddresses()) {
            InetAddress address = linkAddress.getAddress();
            if (address instanceof Inet4Address
                    && isDisplayableWifiAddress((Inet4Address) address)) {
                addUniqueAddress(addresses, address.getHostAddress());
            }
        }
    }

    protected boolean isDisplayableWifiAddress(Inet4Address address) {
        return isDisplayableLanAddress(address);
    }

    protected List<String> currentTetherIpv4Addresses(
            InterfaceMatcher matcher,
            AddressFilter filter) {
        List<String> addresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!networkInterface.isUp() || !matcher.matches(networkInterface.getName())) {
                    continue;
                }
                collectInterfaceAddresses(networkInterface, filter, addresses);
            }
        } catch (SocketException ignored) {
            addresses.clear();
        }
        Collections.sort(addresses);
        return addresses;
    }

    protected boolean hasConfiguredTetherAddress(InterfaceMatcher matcher, AddressFilter filter) {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (matcher.matches(networkInterface.getName())
                        && hasInterfaceAddress(networkInterface, filter)) {
                    return true;
                }
            }
        } catch (SocketException ignored) {
            return false;
        }
        return false;
    }

    protected void collectInterfaceAddresses(
            NetworkInterface networkInterface,
            AddressFilter filter,
            List<String> addresses) {
        Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
        while (inetAddresses.hasMoreElements()) {
            InetAddress address = inetAddresses.nextElement();
            if (address instanceof Inet4Address && filter.allows((Inet4Address) address)) {
                addUniqueAddress(addresses, address.getHostAddress());
            }
        }
    }

    protected boolean hasInterfaceAddress(NetworkInterface networkInterface, AddressFilter filter) {
        Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
        while (inetAddresses.hasMoreElements()) {
            InetAddress address = inetAddresses.nextElement();
            if (address instanceof Inet4Address && filter.allows((Inet4Address) address)) {
                return true;
            }
        }
        return false;
    }

    protected void addUniqueAddress(List<String> addresses, String hostAddress) {
        if (!addresses.contains(hostAddress)) {
            addresses.add(hostAddress);
        }
    }

    protected boolean isDisplayableLanAddress(Inet4Address address) {
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

    protected interface InterfaceMatcher {
        boolean matches(String interfaceName);
    }

    protected interface AddressFilter {
        boolean allows(Inet4Address address);
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
