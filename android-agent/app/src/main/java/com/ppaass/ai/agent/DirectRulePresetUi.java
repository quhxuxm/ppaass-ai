package com.ppaass.ai.agent;

import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;

final class DirectRulePresetUi {
    private DirectRulePresetUi() {
    }

    static void addTo(MainActivityDirectAccessUi activity, LinearLayout root) {
        LinearLayout.LayoutParams headingParams = activity.matchWrap();
        headingParams.setMargins(0, activity.dp(16), 0, activity.dp(6));
        root.addView(activity.controlLabel("快捷预设"), headingParams);

        addRow(activity, root, 0,
                new Preset("本机", new String[]{"localhost", "127.0.0.0/8", "::1"}),
                new Preset("私网", new String[]{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}));
        addRow(activity, root, activity.dp(8),
                new Preset("中国", new String[]{"*.cn"}),
                new Preset("Microsoft", new String[]{"*.microsoft.com", "*.bing.com"}));
        addRow(activity, root, activity.dp(8),
                new Preset("Teams", new String[]{"teams.microsoft.com", "*.teams.microsoft.com", "*.lync.com"}),
                new Preset("Skype", new String[]{"skype.com", "*.skype.com"}));
        addRow(activity, root, activity.dp(8), new Preset("YouTube", new String[]{
                "youtube.com", "*.youtube.com", "youtu.be", "*.youtu.be",
                "youtubei.googleapis.com", "youtube.googleapis.com", "suggestqueries.google.com",
                "googlevideo.com", "*.googlevideo.com", "ytimg.com", "*.ytimg.com",
                "ggpht.com", "*.ggpht.com", "*.gstatic.com"
        }));
    }

    private static void addRow(
            MainActivityDirectAccessUi activity,
            LinearLayout root,
            int topMargin,
            Preset... presets
    ) {
        LinearLayout row = activity.horizontalRow();
        for (Preset preset : presets) {
            addButton(activity, row, preset);
        }
        LinearLayout.LayoutParams params = activity.matchWrap();
        params.setMargins(0, topMargin, 0, 0);
        root.addView(row, params);
    }

    private static void addButton(
            MainActivityDirectAccessUi activity,
            LinearLayout row,
            Preset preset
    ) {
        Button button = activity.secondaryButton(preset.label);
        button.setOnClickListener(view -> activity.addDirectRules(preset.rules));
        activity.trackEditable(button);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, activity.dp(44), 1f);
        if (row.getChildCount() > 0) {
            params.setMargins(activity.dp(8), 0, 0, 0);
        }
        row.addView(button, params);
    }

    private record Preset(String label, String[] rules) {
    }
}
