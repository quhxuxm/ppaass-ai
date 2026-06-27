package com.ppaass.ai.agent;

import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class HttpProxyClientDialog {
    private static final int COLOR_CONTROL = Color.rgb(241, 245, 249);
    private static final int COLOR_TEXT = Color.rgb(17, 24, 39);
    private static final int COLOR_MUTED = Color.rgb(100, 116, 139);
    private static final int COLOR_BORDER = Color.rgb(226, 232, 240);
    private static final int COLOR_ACCENT = Color.rgb(37, 99, 235);
    private static final int COLOR_ACTION_STOP = Color.rgb(220, 38, 38);

    private final Context context;
    private final SharedPreferences prefs;
    private LinearLayout content;

    HttpProxyClientDialog(Context context, SharedPreferences prefs) {
        this.context = context;
        this.prefs = prefs;
    }

    void show() {
        content = new LinearLayout(context);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(4), dp(4), dp(4), dp(4));

        ScrollView scroll = new ScrollView(context);
        scroll.setClipToPadding(false);
        scroll.addView(content, matchWrap());

        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle("HTTP Proxy 客户端")
                .setView(scroll)
                .setPositiveButton("关闭", null)
                .create();
        dialog.setOnShowListener(view -> render());
        dialog.show();
    }

    private void render() {
        content.removeAllViews();

        LinearLayout header = horizontalRow();
        TextView summary = mutedText("当前活动连接和禁止列表", 13f);
        header.addView(summary, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        Button refresh = secondaryButton("刷新");
        refresh.setOnClickListener(view -> render());
        header.addView(refresh, new LinearLayout.LayoutParams(dp(76), dp(40)));
        content.addView(header, matchWrap());

        try {
            JSONObject state = new JSONObject(NativeAgent.httpProxyClientsJson());
            addActiveClients(state.optJSONArray("active"));
            addBlockedClients(state.optJSONArray("blocked"));
        } catch (JSONException error) {
            addEmptyRow("客户端列表读取失败");
        }
    }

    private void addActiveClients(JSONArray active) throws JSONException {
        addSectionTitle("活动连接");
        if (active == null || active.length() == 0) {
            addEmptyRow("暂无活动客户端");
            return;
        }

        for (int i = 0; i < active.length(); i++) {
            JSONObject client = active.getJSONObject(i);
            String ip = client.optString("ip", "");
            int connections = client.optInt("connections", 0);
            JSONArray peers = client.optJSONArray("peers");
            String detail = connections + " 个连接";
            if (peers != null && peers.length() > 0) {
                detail += "\n" + joinJsonArray(peers);
            }
            addClientRow(ip, detail, "断开并禁止", COLOR_ACTION_STOP, view -> {
                blockClient(ip);
                render();
            });
        }
    }

    private void addBlockedClients(JSONArray nativeBlocked) {
        addSectionTitle("已禁止");
        Set<String> blocked = new HashSet<>(prefs.getStringSet(
                PpaassHttpProxyService.PREF_BLOCKED_CLIENTS,
                Collections.emptySet()));
        if (nativeBlocked != null) {
            for (int i = 0; i < nativeBlocked.length(); i++) {
                String ip = nativeBlocked.optString(i, "");
                if (!ip.isEmpty()) {
                    blocked.add(ip);
                }
            }
        }

        if (blocked.isEmpty()) {
            addEmptyRow("暂无禁止客户端");
            return;
        }

        List<String> sorted = new ArrayList<>(blocked);
        Collections.sort(sorted);
        for (String ip : sorted) {
            addClientRow(ip, "新连接会被拒绝", "恢复", COLOR_ACCENT, view -> {
                unblockClient(ip);
                render();
            });
        }
    }

    private void blockClient(String ip) {
        String normalized = normalizeIp(ip);
        if (normalized.isEmpty()) {
            return;
        }
        Set<String> blocked = blockedClients();
        blocked.add(normalized);
        saveBlockedClients(blocked);
        NativeAgent.blockHttpProxyClient(normalized);
        Toast.makeText(context, "已断开并禁止 " + normalized, Toast.LENGTH_SHORT).show();
    }

    private void unblockClient(String ip) {
        String normalized = normalizeIp(ip);
        if (normalized.isEmpty()) {
            return;
        }
        Set<String> blocked = blockedClients();
        blocked.remove(normalized);
        saveBlockedClients(blocked);
        NativeAgent.unblockHttpProxyClient(normalized);
        Toast.makeText(context, "已恢复 " + normalized, Toast.LENGTH_SHORT).show();
    }

    private Set<String> blockedClients() {
        return new HashSet<>(prefs.getStringSet(
                PpaassHttpProxyService.PREF_BLOCKED_CLIENTS,
                Collections.emptySet()));
    }

    private void saveBlockedClients(Set<String> blocked) {
        prefs.edit()
                .putStringSet(PpaassHttpProxyService.PREF_BLOCKED_CLIENTS, blocked)
                .apply();
    }

    private String normalizeIp(String ip) {
        return ip == null ? "" : ip.trim();
    }

    private void addSectionTitle(String title) {
        TextView view = controlLabel(title);
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(14), 0, dp(6));
        content.addView(view, params);
    }

    private void addEmptyRow(String text) {
        TextView empty = mutedText(text, 13f);
        empty.setGravity(Gravity.CENTER);
        empty.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        LinearLayout.LayoutParams params = matchWrap();
        params.height = dp(48);
        content.addView(empty, params);
    }

    private void addClientRow(
            String ip,
            String detail,
            String actionLabel,
            int actionColor,
            View.OnClickListener action) {
        LinearLayout row = horizontalRow();
        row.setPadding(dp(12), dp(10), dp(12), dp(10));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        LinearLayout textColumn = new LinearLayout(context);
        textColumn.setOrientation(LinearLayout.VERTICAL);
        textColumn.addView(titleText(ip, 14f), matchWrap());
        TextView detailView = mutedText(detail, 12f);
        detailView.setSingleLine(false);
        detailView.setMaxLines(4);
        detailView.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams detailParams = matchWrap();
        detailParams.setMargins(0, dp(3), 0, 0);
        textColumn.addView(detailView, detailParams);
        row.addView(textColumn, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        Button button = actionButton(actionLabel, actionColor);
        button.setTextSize(13f);
        button.setOnClickListener(action);
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(dp(104), dp(40));
        buttonParams.setMargins(dp(8), 0, 0, 0);
        row.addView(button, buttonParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        rowParams.setMargins(0, dp(6), 0, 0);
        content.addView(row, rowParams);
    }

    private String joinJsonArray(JSONArray values) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < values.length(); i++) {
            String value = values.optString(i, "");
            if (value.isEmpty()) {
                continue;
            }
            if (builder.length() > 0) {
                builder.append('\n');
            }
            builder.append(value);
        }
        return builder.toString();
    }

    private LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        return row;
    }

    private Button secondaryButton(String text) {
        Button button = new Button(context);
        button.setText(text);
        button.setTextSize(13f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setEllipsize(TextUtils.TruncateAt.END);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setTextColor(COLOR_ACCENT);
        button.setBackground(rounded(Color.rgb(219, 234, 254), Color.rgb(219, 234, 254)));
        return button;
    }

    private Button actionButton(String text, int color) {
        Button button = new Button(context);
        button.setText(text);
        button.setTextSize(15f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setTextColor(Color.WHITE);
        button.setSingleLine(true);
        button.setEllipsize(TextUtils.TruncateAt.END);
        button.setIncludeFontPadding(false);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setBackground(rounded(color, color));
        return button;
    }

    private TextView titleText(String text, float size) {
        TextView view = new TextView(context);
        view.setText(text);
        view.setTextColor(COLOR_TEXT);
        view.setTextSize(size);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        return view;
    }

    private TextView mutedText(String text, float size) {
        TextView view = new TextView(context);
        view.setText(text);
        view.setTextColor(COLOR_MUTED);
        view.setTextSize(size);
        return view;
    }

    private TextView controlLabel(String text) {
        TextView view = titleText(text, 13f);
        view.setSingleLine(true);
        view.setEllipsize(TextUtils.TruncateAt.END);
        return view;
    }

    private GradientDrawable rounded(int fill, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(12));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }
}
