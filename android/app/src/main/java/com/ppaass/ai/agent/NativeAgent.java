package com.ppaass.ai.agent;

final class NativeAgent {
    static {
        System.loadLibrary("ppaass_android_agent");
    }

    private NativeAgent() {
    }

    static native long start(int tunFd, String configJson);

    static native void stop(long handle);
}
