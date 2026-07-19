package com.ppaass.ai.agent;

import android.graphics.Color;

// Android 端动态调色板，配色 key 与 Desktop 保持一致。
final class UiPalette {
    static final String PREF_COLOR_THEME = "ui_color_theme";
    static final String DEFAULT_THEME = "midnight";
    static final String[] THEME_KEYS = {
            "midnight", "ocean", "forest", "sunset", "violet",
            "porcelain", "sky", "mint", "rose"
    };
    static final String[] THEME_LABELS = {
            "午夜霓虹", "深海蓝", "森林绿", "日落橙", "星云紫",
            "暖瓷白", "晴空白", "薄荷白", "樱花白"
    };

    static boolean IS_LIGHT;
    static int BACKGROUND;
    static int SURFACE;
    static int CONTROL;
    static int TEXT;
    static int MUTED;
    static int BORDER;
    static int ACCENT;
    static int ACCENT_STRONG;
    static int ACCENT_SOFT;
    static int ACTION_START;
    static int ACTION_START_SOFT;
    static int ACTION_INFO;
    static int ACTION_INFO_SOFT;
    static int ACTION_WARN;
    static int ACTION_WARN_SOFT;
    static int ACTION_STOP;
    static int ACTION_STOP_SOFT;
    static int STATUS_RUNNING;
    static int STATUS_RUNNING_SOFT;
    static int STATUS_STOPPED;
    static int STATUS_STOPPED_SOFT;
    static int ON_BRIGHT;
    static int CHART_TRACK;
    static int CHART_IDLE;

    static {
        apply(DEFAULT_THEME);
    }

    static void apply(String theme) {
        switch (normalizeTheme(theme)) {
            case "ocean":
                setPalette(false, 2, 8, 18, 7, 22, 34, 12, 33, 48,
                        56, 189, 248, 186, 230, 253,
                        45, 212, 191, 125, 211, 252, 251, 191, 36, 248, 113, 113,
                        74, 222, 128);
                break;
            case "forest":
                setPalette(false, 2, 11, 7, 8, 25, 16, 14, 37, 24,
                        74, 222, 128, 187, 247, 208,
                        190, 242, 100, 52, 211, 153, 250, 204, 21, 251, 113, 133,
                        110, 231, 183);
                break;
            case "sunset":
                setPalette(false, 16, 6, 5, 34, 15, 12, 50, 24, 18,
                        251, 146, 60, 254, 215, 170,
                        251, 191, 36, 56, 189, 248, 244, 114, 182, 251, 113, 133,
                        74, 222, 128);
                break;
            case "violet":
                setPalette(false, 9, 3, 17, 25, 14, 38, 39, 22, 58,
                        192, 132, 252, 233, 213, 255,
                        244, 114, 182, 96, 165, 250, 250, 204, 21, 251, 113, 133,
                        74, 222, 128);
                break;
            case "porcelain":
                setPalette(true, 255, 251, 244, 255, 255, 255, 248, 242, 233,
                        194, 106, 50, 112, 51, 24,
                        217, 164, 65, 21, 119, 210, 214, 66, 120, 209, 64, 78,
                        5, 133, 96);
                break;
            case "sky":
                setPalette(true, 246, 251, 255, 255, 255, 255, 237, 247, 255,
                        22, 119, 210, 12, 79, 150,
                        14, 165, 233, 37, 99, 235, 217, 119, 6, 220, 38, 38,
                        5, 150, 105);
                break;
            case "mint":
                setPalette(true, 247, 255, 251, 255, 255, 255, 234, 248, 242,
                        7, 138, 104, 5, 97, 73,
                        132, 204, 22, 14, 116, 144, 217, 119, 6, 220, 38, 38,
                        5, 150, 105);
                break;
            case "rose":
                setPalette(true, 255, 249, 251, 255, 255, 255, 255, 240, 244,
                        214, 66, 120, 159, 40, 84,
                        234, 179, 8, 37, 99, 235, 225, 80, 130, 220, 38, 38,
                        5, 150, 105);
                break;
            default:
                setPalette(false, 2, 4, 6, 10, 16, 22, 16, 25, 34,
                        143, 156, 255, 217, 221, 255,
                        255, 229, 92, 72, 232, 255, 255, 126, 170, 255, 107, 145,
                        98, 245, 166);
                break;
        }
    }

    static String normalizeTheme(String value) {
        if (value != null) {
            for (String key : THEME_KEYS) {
                if (key.equalsIgnoreCase(value.trim())) {
                    return key;
                }
            }
        }
        return DEFAULT_THEME;
    }

    static int themeIndex(String value) {
        String normalized = normalizeTheme(value);
        for (int i = 0; i < THEME_KEYS.length; i++) {
            if (THEME_KEYS[i].equals(normalized)) {
                return i;
            }
        }
        return 0;
    }

    private static void setPalette(
            boolean light,
            int bgR, int bgG, int bgB,
            int surfaceR, int surfaceG, int surfaceB,
            int controlR, int controlG, int controlB,
            int accentR, int accentG, int accentB,
            int strongR, int strongG, int strongB,
            int startR, int startG, int startB,
            int infoR, int infoG, int infoB,
            int warnR, int warnG, int warnB,
            int stopR, int stopG, int stopB,
            int runningR, int runningG, int runningB) {
        IS_LIGHT = light;
        BACKGROUND = Color.rgb(bgR, bgG, bgB);
        SURFACE = Color.rgb(surfaceR, surfaceG, surfaceB);
        CONTROL = Color.rgb(controlR, controlG, controlB);
        TEXT = light ? Color.rgb(36, 43, 48) : Color.rgb(247, 252, 255);
        MUTED = blend(TEXT, SURFACE, light ? 0.62f : 0.60f);
        BORDER = blend(Color.rgb(accentR, accentG, accentB), SURFACE, 0.25f);
        ACCENT = Color.rgb(accentR, accentG, accentB);
        ACCENT_STRONG = Color.rgb(strongR, strongG, strongB);
        ACCENT_SOFT = blend(ACCENT, SURFACE, 0.18f);
        ACTION_START = Color.rgb(startR, startG, startB);
        ACTION_START_SOFT = blend(ACTION_START, SURFACE, 0.18f);
        ACTION_INFO = Color.rgb(infoR, infoG, infoB);
        ACTION_INFO_SOFT = blend(ACTION_INFO, SURFACE, 0.18f);
        ACTION_WARN = Color.rgb(warnR, warnG, warnB);
        ACTION_WARN_SOFT = blend(ACTION_WARN, SURFACE, 0.18f);
        ACTION_STOP = Color.rgb(stopR, stopG, stopB);
        ACTION_STOP_SOFT = blend(ACTION_STOP, SURFACE, 0.18f);
        STATUS_RUNNING = Color.rgb(runningR, runningG, runningB);
        STATUS_RUNNING_SOFT = blend(STATUS_RUNNING, SURFACE, 0.16f);
        STATUS_STOPPED = MUTED;
        STATUS_STOPPED_SOFT = blend(MUTED, SURFACE, 0.12f);
        ON_BRIGHT = Color.rgb(16, 19, 8);
        CHART_TRACK = blend(ACCENT, BACKGROUND, 0.13f);
        CHART_IDLE = blend(MUTED, BACKGROUND, 0.12f);
    }

    private static int blend(int foreground, int background, float amount) {
        float inverse = 1f - amount;
        return Color.rgb(
                Math.round(Color.red(foreground) * amount + Color.red(background) * inverse),
                Math.round(Color.green(foreground) * amount + Color.green(background) * inverse),
                Math.round(Color.blue(foreground) * amount + Color.blue(background) * inverse));
    }

    private UiPalette() {
    }
}
