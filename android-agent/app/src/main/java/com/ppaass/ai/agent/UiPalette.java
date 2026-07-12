package com.ppaass.ai.agent;

import android.graphics.Color;

// Android 端共享的深色调色板，与 Desktop 的 midnight 风格保持一致。
final class UiPalette {
    static final int BACKGROUND = Color.rgb(2, 4, 6);
    static final int SURFACE = Color.rgb(10, 16, 22);
    static final int CONTROL = Color.rgb(16, 25, 34);
    static final int TEXT = Color.rgb(247, 252, 255);
    static final int MUTED = Color.rgb(154, 174, 188);
    static final int BORDER = Color.rgb(38, 58, 72);

    static final int ACCENT = Color.rgb(143, 156, 255);
    static final int ACCENT_STRONG = Color.rgb(217, 221, 255);
    static final int ACCENT_SOFT = Color.rgb(27, 33, 69);

    static final int ACTION_START = Color.rgb(255, 229, 92);
    static final int ACTION_START_SOFT = Color.rgb(52, 47, 19);
    static final int ACTION_INFO = Color.rgb(72, 232, 255);
    static final int ACTION_INFO_SOFT = Color.rgb(10, 41, 50);
    static final int ACTION_WARN = Color.rgb(255, 126, 170);
    static final int ACTION_WARN_SOFT = Color.rgb(53, 19, 31);
    static final int ACTION_STOP = Color.rgb(255, 107, 145);
    static final int ACTION_STOP_SOFT = Color.rgb(54, 17, 29);

    static final int STATUS_RUNNING = Color.rgb(98, 245, 166);
    static final int STATUS_RUNNING_SOFT = Color.rgb(16, 43, 29);
    static final int STATUS_STOPPED = Color.rgb(154, 174, 188);
    static final int STATUS_STOPPED_SOFT = Color.rgb(21, 29, 37);

    static final int ON_BRIGHT = Color.rgb(16, 19, 0);
    static final int CHART_TRACK = Color.rgb(27, 39, 49);
    static final int CHART_IDLE = Color.rgb(17, 25, 34);

    private UiPalette() {
    }
}
