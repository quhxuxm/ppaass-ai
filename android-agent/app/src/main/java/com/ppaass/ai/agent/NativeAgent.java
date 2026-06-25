package com.ppaass.ai.agent;

final class NativeAgent {
    static {
        System.loadLibrary("android_agent");
    }

    private NativeAgent() {
    }

    static native long start(int tunFd, String configJson, PpaassVpnService vpnService);

    static native long startHttpProxy(String configJson, int listenPort);

    static native boolean isRunning(long handle);

    static native void stop(long handle);

    static native long vpnDownloadBytes();

    static native long vpnUploadBytes();

    static native String dnsResolutionRecordsJson();
}
