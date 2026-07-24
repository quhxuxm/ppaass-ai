package com.ppaass.ai.agent;

import android.content.SharedPreferences;

import java.util.Locale;

/**
 * Persisted configuration for Android system-location simulation.
 *
 * <p>The stable mode values are intentionally separate from the translated labels shown in the
 * UI. This keeps existing selections valid if labels change later.</p>
 */
final class MockGeoConfig {
    static final String PREF_MODE = "mock_geo_mode";
    static final String PREF_CUSTOM_LATITUDE = "mock_geo_custom_latitude";
    static final String PREF_CUSTOM_LONGITUDE = "mock_geo_custom_longitude";
    static final String PREF_ACCURACY_METERS = "mock_geo_accuracy_meters";

    static final String MODE_OFF = "off";
    static final String MODE_CUSTOM = "custom";
    static final float DEFAULT_ACCURACY_METERS = 8.0f;
    static final double DEFAULT_CUSTOM_LATITUDE = 39.9042;
    static final double DEFAULT_CUSTOM_LONGITUDE = 116.4074;

    private static final Preset[] PRESETS = {
            new Preset("beijing", "北京", 39.9042, 116.4074),
            new Preset("shanghai", "上海", 31.2304, 121.4737),
            new Preset("hong_kong", "香港", 22.3193, 114.1694),
            new Preset("singapore", "新加坡", 1.3521, 103.8198),
            new Preset("tokyo", "东京", 35.6762, 139.6503),
            new Preset("sydney", "悉尼", -33.8688, 151.2093),
            new Preset("london", "伦敦", 51.5074, -0.1278),
            new Preset("frankfurt", "法兰克福", 50.1109, 8.6821),
            new Preset("new_york", "纽约", 40.7128, -74.0060),
            new Preset("los_angeles", "洛杉矶", 34.0522, -118.2437),
            new Preset("florida", "佛罗里达", 27.994402, -81.760254)
    };

    private MockGeoConfig() {
    }

    static Selection load(SharedPreferences prefs) {
        String mode = normalizeMode(readString(prefs, PREF_MODE, MODE_OFF));
        float accuracy;
        try {
            accuracy = parseAccuracy(readString(
                    prefs,
                    PREF_ACCURACY_METERS,
                    formatAccuracy(DEFAULT_ACCURACY_METERS)));
        } catch (IllegalArgumentException ignored) {
            accuracy = DEFAULT_ACCURACY_METERS;
        }
        Preset preset = findPreset(mode);
        if (preset != null) {
            return new Selection(preset.id, preset.label, preset.latitude, preset.longitude, accuracy);
        }
        if (MODE_CUSTOM.equals(mode)) {
            try {
                double latitude = parseLatitude(readString(
                        prefs,
                        PREF_CUSTOM_LATITUDE,
                        formatCoordinate(DEFAULT_CUSTOM_LATITUDE)));
                double longitude = parseLongitude(readString(
                        prefs,
                        PREF_CUSTOM_LONGITUDE,
                        formatCoordinate(DEFAULT_CUSTOM_LONGITUDE)));
                return new Selection(
                        MODE_CUSTOM,
                        "自定义",
                        latitude,
                        longitude,
                        accuracy);
            } catch (IllegalArgumentException ignored) {
                return disabled();
            }
        }
        return disabled();
    }

    static String readString(SharedPreferences prefs, String key, String fallback) {
        try {
            return prefs.getString(key, fallback);
        } catch (ClassCastException ignored) {
            return fallback;
        }
    }

    static Selection selectionForInput(
            String mode,
            String latitudeText,
            String longitudeText,
            String accuracyText) {
        String normalized = normalizeMode(mode);
        if (MODE_OFF.equals(normalized)) {
            return disabled();
        }
        float accuracy = parseAccuracy(accuracyText);
        Preset preset = findPreset(normalized);
        if (preset != null) {
            return new Selection(
                    preset.id,
                    preset.label,
                    preset.latitude,
                    preset.longitude,
                    accuracy);
        }
        if (!MODE_CUSTOM.equals(normalized)) {
            throw new IllegalArgumentException("未知的模拟 GEO");
        }
        return new Selection(
                MODE_CUSTOM,
                "自定义",
                parseLatitude(latitudeText),
                parseLongitude(longitudeText),
                accuracy);
    }

    static void save(SharedPreferences prefs, Selection selection) {
        SharedPreferences.Editor editor = prefs.edit()
                .putString(PREF_MODE, selection.mode)
                .putString(PREF_ACCURACY_METERS, formatAccuracy(selection.accuracyMeters));
        if (MODE_CUSTOM.equals(selection.mode)) {
            editor.putString(PREF_CUSTOM_LATITUDE, formatCoordinate(selection.latitude))
                    .putString(PREF_CUSTOM_LONGITUDE, formatCoordinate(selection.longitude));
        }
        editor.apply();
    }

    static void reset(SharedPreferences prefs) {
        prefs.edit()
                .remove(PREF_MODE)
                .remove(PREF_CUSTOM_LATITUDE)
                .remove(PREF_CUSTOM_LONGITUDE)
                .remove(PREF_ACCURACY_METERS)
                .apply();
    }

    static Selection disabled() {
        return new Selection(MODE_OFF, "关闭", 0.0, 0.0, DEFAULT_ACCURACY_METERS);
    }

    static String[] optionLabels() {
        String[] labels = new String[PRESETS.length + 2];
        labels[0] = "关闭（使用真实定位）";
        for (int i = 0; i < PRESETS.length; i++) {
            labels[i + 1] = PRESETS[i].label;
        }
        labels[labels.length - 1] = "自定义经纬度";
        return labels;
    }

    static String modeForOptionIndex(int index) {
        if (index <= 0) {
            return MODE_OFF;
        }
        if (index <= PRESETS.length) {
            return PRESETS[index - 1].id;
        }
        return MODE_CUSTOM;
    }

    static int optionIndexForMode(String mode) {
        String normalized = normalizeMode(mode);
        if (MODE_OFF.equals(normalized)) {
            return 0;
        }
        for (int i = 0; i < PRESETS.length; i++) {
            if (PRESETS[i].id.equals(normalized)) {
                return i + 1;
            }
        }
        return PRESETS.length + 1;
    }

    static Preset presetForMode(String mode) {
        return findPreset(normalizeMode(mode));
    }

    static String normalizeMode(String value) {
        if (value == null) {
            return MODE_OFF;
        }
        String normalized = value.trim().toLowerCase(Locale.US);
        if (MODE_OFF.equals(normalized) || MODE_CUSTOM.equals(normalized)) {
            return normalized;
        }
        return findPreset(normalized) == null ? MODE_OFF : normalized;
    }

    static double parseLatitude(String value) {
        return parseCoordinate(value, -90.0, 90.0, "纬度");
    }

    static double parseLongitude(String value) {
        return parseCoordinate(value, -180.0, 180.0, "经度");
    }

    static float parseAccuracy(String value) {
        final float parsed;
        try {
            parsed = Float.parseFloat(value == null ? "" : value.trim());
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("定位精度必须是数字");
        }
        if (!Float.isFinite(parsed) || parsed <= 0.0f || parsed > 10_000.0f) {
            throw new IllegalArgumentException("定位精度必须在 0–10000 米之间");
        }
        return parsed;
    }

    static String formatCoordinate(double value) {
        return String.format(Locale.US, "%.6f", value);
    }

    static String formatAccuracy(float value) {
        if (value == Math.rint(value)) {
            return String.format(Locale.US, "%.0f", value);
        }
        return String.format(Locale.US, "%.1f", value);
    }

    private static double parseCoordinate(String value, double min, double max, String label) {
        final double parsed;
        try {
            parsed = Double.parseDouble(value == null ? "" : value.trim());
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException(label + "必须是数字");
        }
        if (!Double.isFinite(parsed) || parsed < min || parsed > max) {
            throw new IllegalArgumentException(
                    label + "必须在 " + formatRangeValue(min) + "–" + formatRangeValue(max) + " 之间");
        }
        return parsed;
    }

    private static String formatRangeValue(double value) {
        return String.format(Locale.US, "%.0f", value);
    }

    private static Preset findPreset(String mode) {
        if (mode == null) {
            return null;
        }
        for (Preset preset : PRESETS) {
            if (preset.id.equals(mode)) {
                return preset;
            }
        }
        return null;
    }

    static final class Preset {
        final String id;
        final String label;
        final double latitude;
        final double longitude;

        Preset(String id, String label, double latitude, double longitude) {
            this.id = id;
            this.label = label;
            this.latitude = latitude;
            this.longitude = longitude;
        }
    }

    static final class Selection {
        final String mode;
        final String label;
        final double latitude;
        final double longitude;
        final float accuracyMeters;

        Selection(
                String mode,
                String label,
                double latitude,
                double longitude,
                float accuracyMeters) {
            this.mode = mode;
            this.label = label;
            this.latitude = latitude;
            this.longitude = longitude;
            this.accuracyMeters = accuracyMeters;
        }

        boolean enabled() {
            return !MODE_OFF.equals(mode);
        }

        String summary() {
            if (!enabled()) {
                return "关闭";
            }
            return label;
        }
    }
}
