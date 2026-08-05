package com.ppaass.ai.agent;

final class NativeAgent {
    static final int AUTHENTICATION_UNCONFIRMED = 0;
    static final int AUTHENTICATION_USER_EXPIRED = 1;
    static final int AUTHENTICATION_USER_DISABLED = 2;
    static final int AUTHENTICATION_VERIFIED_ACTIVE = 3;

    static {
        System.loadLibrary("android_agent");
    }

    private NativeAgent() {
    }

    static native long start(int tunFd, String configJson, PpaassVpnService vpnService);

    static native long startHttpProxy(String configJson, int listenPort);

    static native boolean validateKeyPair(String privateKeyPem, String publicKeyPem);

    static native boolean isRunning(long handle);

    static native int authenticationStatus(long handle);

    static native void stop(long handle);

    static native long vpnDownloadBytes();

    static native long vpnUploadBytes();

    static native boolean packetCaptureEnabled();

    static native boolean setPacketCaptureEnabled(String file, boolean enabled);

    static native boolean clearPacketCapture(String file);

    static native String packetCaptureReportJson(String file, int limit, int proxyListenPort);

    static native String dnsResolutionRecordsJson();

    static native String httpProxyClientsJson();

    static native boolean blockHttpProxyClient(String ip);

    static native boolean unblockHttpProxyClient(String ip);
}
