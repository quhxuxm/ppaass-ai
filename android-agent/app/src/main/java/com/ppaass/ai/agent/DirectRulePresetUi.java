package com.ppaass.ai.agent;

import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;

final class DirectRulePresetUi {
    private static final String[] TEAMS_RULES = {
            "teams.microsoft.com", "*.teams.microsoft.com",
            "teams.cloud.microsoft", "*.teams.cloud.microsoft",
            "*.lync.com", "*.skype.com",
            "cloud.microsoft", "*.cloud.microsoft",
            "static.microsoft", "*.static.microsoft",
            "usercontent.microsoft", "*.usercontent.microsoft",
            "*.auth.microsoft.com", "*.msftidentity.com", "*.msidentity.com",
            "account.activedirectory.windowsazure.com", "accounts.accesscontrol.windows.net",
            "adminwebservice.microsoftonline.com", "api.passwordreset.microsoftonline.com",
            "autologon.microsoftazuread-sso.com", "becws.microsoftonline.com",
            "ccs.login.microsoftonline.com", "clientconfig.microsoftonline-p.net",
            "companymanager.microsoftonline.com", "device.login.microsoftonline.com",
            "graph.microsoft.com", "graph.windows.net", "login-us.microsoftonline.com",
            "login.microsoft.com", "login.microsoftonline-p.com", "login.microsoftonline.com",
            "login.windows.net", "logincert.microsoftonline.com", "loginex.microsoftonline.com",
            "nexus.microsoftonline-p.com", "passwordreset.microsoftonline.com",
            "provisioningapi.microsoftonline.com", "*.hip.live.com",
            "*.microsoftonline-p.com", "*.microsoftonline.com", "*.msauth.net",
            "*.msauthimages.net", "*.msecnd.net", "*.msftauth.net", "*.msftauthimages.net",
            "*.phonefactor.net", "enterpriseregistration.windows.net",
            "account.live.com", "login.live.com", "aka.ms",
            "*.keydelivery.mediaservices.windows.net",
            "*.streaming.mediaservices.windows.net",
            "join.secure.skypeassets.com", "mlccdnprod.azureedge.net",
            "52.112.0.0/14", "52.122.0.0/15",
            "20.20.32.0/19", "20.190.128.0/18", "20.231.128.0/19", "40.126.0.0/18",
            "2603:1006:2000::/48", "2603:1007:200::/48", "2603:1016:1400::/48",
            "2603:1017::/48", "2603:1026:3000::/48", "2603:1027::/48",
            "2603:1027:1::/48", "2603:1036:3000::/48", "2603:1037::/48",
            "2603:1037:1::/48", "2603:1046:2000::/48", "2603:1047::/48",
            "2603:1047:1::/48", "2603:1056:2000::/48", "2603:1057:2::/48",
            "2603:1057::/48", "2603:1063::/38", "2620:1ec:6::/48", "2620:1ec:40::/42"
    };

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
                new Preset("Teams", teamsRules()),
                new Preset("Skype", new String[]{"skype.com", "*.skype.com"}));
        addRow(activity, root, activity.dp(8), new Preset("YouTube", new String[]{
                "youtube.com", "*.youtube.com", "youtu.be", "*.youtu.be",
                "youtubei.googleapis.com", "youtube.googleapis.com", "suggestqueries.google.com",
                "googlevideo.com", "*.googlevideo.com", "ytimg.com", "*.ytimg.com",
                "ggpht.com", "*.ggpht.com", "*.gstatic.com"
        }));
        addRow(activity, root, activity.dp(8),
                new Preset("Outlook", new String[]{
                        "outlook.com", "*.outlook.com", "outlook.office.com", "*.outlook.office.com"
                }),
                new Preset("Office", new String[]{
                        "office.com", "*.office.com", "office365.com", "*.office365.com"
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

    static String[] teamsRules() {
        return TEAMS_RULES.clone();
    }

    private record Preset(String label, String[] rules) {
    }
}
