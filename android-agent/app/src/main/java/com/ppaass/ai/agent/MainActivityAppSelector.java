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

// MainActivity 拆分层：保持单个文件短小，便于定位 Android UI 问题。
abstract class MainActivityAppSelector extends MainActivityUiKit {

protected void showAppSelector() {
        if (appSelectorDialog != null && appSelectorDialog.isShowing()) {
            return;
        }

        List<AppEntry> apps = loadVpnCapableApps();
        Set<String> selected = selectedPackages();
        boolean[] checked = new boolean[apps.size()];
        for (int i = 0; i < apps.size(); i++) {
            AppEntry app = apps.get(i);
            checked[i] = selected.contains(app.packageName);
        }

        AppListAdapter adapter = new AppListAdapter(this, apps, checked);
        ListView list = new ListView(this);
        list.setAdapter(adapter);
        list.setFastScrollEnabled(true);
        list.setDivider(null);
        list.setDividerHeight(0);
        list.setCacheColorHint(Color.TRANSPARENT);
        list.setSelector(interactiveRounded(
                COLOR_ACCENT_SOFT,
                alphaColor(COLOR_ACCENT, 118),
                COLOR_ACCENT));

        TextView selectionSummary = chip(appSelectionSummary(checked), COLOR_STATUS_STOPPED);
        list.setOnItemClickListener((parent, view, position, id) -> {
            checked[position] = !checked[position];
            selectionSummary.setText(appSelectionSummary(checked));
            adapter.notifyDataSetChanged();
        });

        LinearLayout dialogContent = new LinearLayout(this);
        dialogContent.setOrientation(LinearLayout.VERTICAL);
        dialogContent.setPadding(dp(18), dp(16), dp(18), 0);
        dialogContent.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));

        LinearLayout titleRow = horizontalRow();
        TextView dialogTitle = titleText("VPN 应用", 20f);
        titleRow.addView(dialogTitle, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        titleRow.addView(selectionSummary, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        dialogContent.addView(titleRow, matchWrap());

        TextView dialogSubtitle = mutedText("只有选中的应用会使用 VPN 路径", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(4), 0, dp(12));
        dialogContent.addView(dialogSubtitle, subtitleParams);

        LinearLayout listShell = new LinearLayout(this);
        listShell.setOrientation(LinearLayout.VERTICAL);
        listShell.setPadding(dp(4), dp(4), dp(4), dp(4));
        listShell.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        listShell.addView(list, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(460)));
        dialogContent.addView(listShell, matchWrap());

        appSelectorDialog = new AlertDialog.Builder(this)
                .setView(dialogContent)
                .setPositiveButton("确定", (dialog, which) -> {
                    Set<String> next = new HashSet<>();
                    for (int i = 0; i < apps.size(); i++) {
                        if (checked[i]) {
                            next.add(apps.get(i).packageName);
                        }
                    }
                    prefs.edit().putStringSet("vpn_apps", next).apply();
                    updateSelectedAppsSummary();
                })
                .setNegativeButton("取消", null)
                .setNeutralButton("清空", null)
                .create();
        appSelectorDialog.setOnDismissListener(dialog -> appSelectorDialog = null);
        appSelectorDialog.setOnShowListener(dialog -> {
            Window window = appSelectorDialog.getWindow();
            if (window != null) {
                window.setBackgroundDrawable(rounded(COLOR_SURFACE, COLOR_BORDER));
            }
            appSelectorDialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(COLOR_ACCENT_DARK);
            appSelectorDialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(COLOR_MUTED);
            Button clearButton = appSelectorDialog.getButton(AlertDialog.BUTTON_NEUTRAL);
            clearButton.setTextColor(COLOR_ACTION_STOP);
            clearButton.setOnClickListener(view -> {
                for (int i = 0; i < checked.length; i++) {
                    checked[i] = false;
                }
                selectionSummary.setText(appSelectionSummary(checked));
                adapter.notifyDataSetChanged();
            });
        });
        appSelectorDialog.show();
    }

protected String appSelectionSummary(boolean[] checked) {
        int count = 0;
        for (boolean item : checked) {
            if (item) {
                count++;
            }
        }
        return count == 0 ? "所有应用" : "已选择 " + count + " 个";
    }

protected List<AppEntry> loadVpnCapableApps() {
        PackageManager pm = getPackageManager();
        List<PackageInfo> installed = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        List<AppEntry> apps = new ArrayList<>();
        for (PackageInfo info : installed) {
            if (info.packageName == null) {
                continue;
            }
            String packageName = info.packageName;
            if (getPackageName().equals(packageName) || !requestsInternet(info)) {
                continue;
            }
            ApplicationInfo appInfo = info.applicationInfo;
            CharSequence label = appInfo == null ? null : appInfo.loadLabel(pm);
            boolean systemApp = appInfo != null && (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            Drawable icon = loadIcon(pm, appInfo);
            apps.add(new AppEntry(label == null ? packageName : label.toString(), packageName, systemApp, icon));
        }
        Collections.sort(apps, (left, right) -> {
            if (left.systemApp != right.systemApp) {
                return left.systemApp ? 1 : -1;
            }
            int labelCompare = left.label.compareToIgnoreCase(right.label);
            if (labelCompare != 0) {
                return labelCompare;
            }
            return left.packageName.compareTo(right.packageName);
        });
        return apps;
    }

protected boolean requestsInternet(PackageInfo info) {
        if (info.requestedPermissions == null) {
            return false;
        }
        for (String permission : info.requestedPermissions) {
            if (Manifest.permission.INTERNET.equals(permission)) {
                return true;
            }
        }
        return false;
    }

protected Drawable loadIcon(PackageManager pm, ApplicationInfo appInfo) {
        if (appInfo == null) {
            return pm.getDefaultActivityIcon();
        }
        try {
            return appInfo.loadIcon(pm);
        } catch (RuntimeException ignored) {
            return pm.getDefaultActivityIcon();
        }
    }

protected Set<String> selectedPackages() {
        return new HashSet<>(prefs.getStringSet("vpn_apps", Collections.emptySet()));
    }

protected void updateSelectedAppsSummary() {
        if (selectedAppsSummary == null) {
            return;
        }

        Set<String> selected = selectedPackages();
        if (selected.isEmpty()) {
            selectedAppsSummary.setText("所有应用");
            return;
        }

        selectedAppsSummary.setText("已选择 " + selected.size() + " 个");
    }

}
