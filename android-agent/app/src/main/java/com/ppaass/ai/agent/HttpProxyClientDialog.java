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
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
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
    private static final int COLOR_SURFACE = Color.WHITE;
    private static final int COLOR_CONTROL = Color.rgb(241, 245, 249);
    private static final int COLOR_TEXT = Color.rgb(17, 24, 39);
    private static final int COLOR_MUTED = Color.rgb(100, 116, 139);
    private static final int COLOR_BORDER = Color.rgb(226, 232, 240);
    private static final int COLOR_ACCENT = Color.rgb(45, 170, 158);
    private static final int COLOR_ACCENT_DARK = Color.rgb(18, 128, 119);
    private static final int COLOR_ACCENT_SOFT = Color.rgb(207, 244, 237);
    private static final int COLOR_ACTION_STOP = Color.rgb(214, 104, 86);
    private static final int COLOR_ACTION_STOP_SOFT = Color.rgb(255, 225, 218);

    private final Context context;
    private final SharedPreferences prefs;
    private LinearLayout list;
    private TextView summary;
    private Button activeTab;
    private Button blockedTab;
    private boolean showingBlocked;

    HttpProxyClientDialog(Context context, SharedPreferences prefs) {
        this.context = context;
        this.prefs = prefs;
    }

    void show() {
        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(14), dp(16), dp(12));

        LinearLayout header = horizontalRow();
        LinearLayout titleColumn = new LinearLayout(context);
        titleColumn.setOrientation(LinearLayout.VERTICAL);
        titleColumn.addView(titleText("HTTP Proxy 客户端", 20f), matchWrap());
        summary = mutedText("正在读取客户端", 12f);
        titleColumn.addView(summary, matchWrap());
        header.addView(titleColumn, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        ImageButton refresh = iconButton(R.drawable.ic_refresh_24, COLOR_ACCENT, "刷新");
        refresh.setOnClickListener(view -> render());
        header.addView(refresh, new LinearLayout.LayoutParams(dp(40), dp(40)));
        ImageButton close = iconButton(R.drawable.ic_close_24, COLOR_MUTED, "关闭");
        LinearLayout.LayoutParams closeParams = new LinearLayout.LayoutParams(dp(40), dp(40));
        closeParams.setMargins(dp(6), 0, 0, 0);
        header.addView(close, closeParams);
        root.addView(header, matchWrap());

        LinearLayout tabs = horizontalRow();
        tabs.setPadding(dp(3), dp(3), dp(3), dp(3));
        tabs.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        LinearLayout.LayoutParams tabsParams = matchWrap();
        tabsParams.setMargins(0, dp(12), 0, dp(8));
        activeTab = tabButton("活动");
        activeTab.setOnClickListener(view -> {
            showingBlocked = false;
            render();
        });
        blockedTab = tabButton("已禁止");
        blockedTab.setOnClickListener(view -> {
            showingBlocked = true;
            render();
        });
        tabs.addView(activeTab, new LinearLayout.LayoutParams(0, dp(38), 1f));
        LinearLayout.LayoutParams blockedParams = new LinearLayout.LayoutParams(0, dp(38), 1f);
        blockedParams.setMargins(dp(4), 0, 0, 0);
        tabs.addView(blockedTab, blockedParams);
        root.addView(tabs, tabsParams);

        list = new LinearLayout(context);
        list.setOrientation(LinearLayout.VERTICAL);
        LinearLayout listShell = new LinearLayout(context);
        listShell.setOrientation(LinearLayout.VERTICAL);
        listShell.setPadding(dp(4), dp(4), dp(4), dp(4));
        listShell.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        MaxHeightScrollView scroll = new MaxHeightScrollView(context, dp(420));
        scroll.setClipToPadding(false);
        scroll.setScrollbarFadingEnabled(true);
        scroll.setVerticalScrollBarEnabled(false);
        scroll.addView(list, matchWrap());
        listShell.addView(scroll, matchWrap());
        root.addView(listShell, matchWrap());

        AlertDialog dialog = new AlertDialog.Builder(context).setView(root).create();
        close.setOnClickListener(view -> dialog.dismiss());
        dialog.setOnShowListener(view -> render());
        dialog.show();
    }

    private void render() {
        if (list == null) {
            return;
        }
        list.removeAllViews();
        try {
            JSONObject state = new JSONObject(NativeAgent.httpProxyClientsJson());
            JSONArray active = state.optJSONArray("active");
            Set<String> blocked = blockedClientsFromState(state.optJSONArray("blocked"));
            updateHeader(active == null ? 0 : active.length(), blocked.size());
            if (showingBlocked) {
                addBlockedRows(blocked);
            } else {
                addActiveRows(active);
            }
        } catch (JSONException error) {
            addEmptyRow("客户端列表读取失败");
        }
    }

    private void updateHeader(int activeCount, int blockedCount) {
        if (summary != null) {
            summary.setText(activeCount + " 个活动 · " + blockedCount + " 个已禁止");
        }
        activeTab.setText("活动 " + activeCount);
        blockedTab.setText("已禁止 " + blockedCount);
        styleTab(activeTab, !showingBlocked);
        styleTab(blockedTab, showingBlocked);
    }

    private void addActiveRows(JSONArray active) throws JSONException {
        if (active == null || active.length() == 0) {
            addEmptyRow("暂无活动客户端");
            return;
        }
        for (int i = 0; i < active.length(); i++) {
            JSONObject client = active.optJSONObject(i);
            if (client == null) {
                continue;
            }
            String ip = client.optString("ip", "");
            String detail = client.optInt("connections", 0) + " 个连接";
            String peers = compactPeers(client.optJSONArray("peers"));
            if (!peers.isEmpty()) {
                detail += " · " + peers;
            }
            addClientRow(ip, detail, false, R.drawable.ic_block_24, COLOR_ACTION_STOP, view -> {
                blockClient(ip);
                render();
            });
        }
    }

    private void addBlockedRows(Set<String> blocked) {
        if (blocked.isEmpty()) {
            addEmptyRow("暂无禁止客户端");
            return;
        }
        List<String> sorted = new ArrayList<>(blocked);
        Collections.sort(sorted);
        for (String ip : sorted) {
            addClientRow(ip, "新连接会被拒绝", true, R.drawable.ic_restore_24, COLOR_ACCENT, view -> {
                unblockClient(ip);
                render();
            });
        }
    }

    private void addClientRow(
            String ip,
            String detail,
            boolean blocked,
            int actionIcon,
            int actionColor,
            View.OnClickListener action) {
        LinearLayout row = horizontalRow();
        row.setMinimumHeight(dp(52));
        row.setPadding(dp(10), dp(6), dp(6), dp(6));
        row.setBackground(rounded(COLOR_SURFACE, COLOR_SURFACE));

        LinearLayout textColumn = new LinearLayout(context);
        textColumn.setOrientation(LinearLayout.VERTICAL);
        TextView title = titleText(ip, 15f);
        title.setSingleLine(true);
        title.setEllipsize(TextUtils.TruncateAt.END);
        title.setTextColor(blocked ? COLOR_ACTION_STOP : COLOR_TEXT);
        textColumn.addView(title, matchWrap());
        TextView detailView = mutedText(detail, 12f);
        detailView.setSingleLine(true);
        detailView.setEllipsize(TextUtils.TruncateAt.END);
        textColumn.addView(detailView, matchWrap());
        row.addView(textColumn, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        ImageButton button = iconButton(actionIcon, actionColor, blocked ? "恢复" : "禁止");
        button.setOnClickListener(action);
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(dp(36), dp(36));
        buttonParams.setMargins(dp(6), 0, 0, 0);
        row.addView(button, buttonParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        if (list.getChildCount() > 0) {
            rowParams.setMargins(0, dp(4), 0, 0);
        }
        list.addView(row, rowParams);
    }

    private void addEmptyRow(String text) {
        TextView empty = mutedText(text, 13f);
        empty.setGravity(Gravity.CENTER);
        empty.setTypeface(Typeface.DEFAULT_BOLD);
        empty.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        list.addView(empty, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(56)));
    }

    private Set<String> blockedClientsFromState(JSONArray nativeBlocked) {
        Set<String> blocked = blockedClients();
        if (nativeBlocked == null) {
            return blocked;
        }
        for (int i = 0; i < nativeBlocked.length(); i++) {
            String ip = nativeBlocked.optString(i, "");
            if (!ip.isEmpty()) {
                blocked.add(ip);
            }
        }
        return blocked;
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

    private String compactPeers(JSONArray values) {
        if (values == null || values.length() == 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        int visible = Math.min(2, values.length());
        for (int i = 0; i < visible; i++) {
            String value = values.optString(i, "");
            if (value.isEmpty()) {
                continue;
            }
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append(value);
        }
        if (values.length() > visible) {
            builder.append(" 等 ").append(values.length()).append(" 个端口");
        }
        return builder.toString();
    }

    private Button tabButton(String text) {
        Button button = new Button(context);
        button.setText(text);
        button.setTextSize(13f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setMinHeight(0);
        button.setMinWidth(0);
        flattenButton(button);
        return button;
    }

    private void styleTab(Button button, boolean selected) {
        button.setTextColor(selected ? COLOR_ACCENT_DARK : COLOR_MUTED);
        int fill = selected ? COLOR_ACCENT_SOFT : COLOR_CONTROL;
        button.setBackground(rounded(fill, fill));
    }

    private ImageButton iconButton(int icon, int color, String description) {
        ImageButton button = new ImageButton(context);
        boolean stopAction = color == COLOR_ACTION_STOP;
        button.setImageResource(icon);
        int tint = color == COLOR_MUTED ? COLOR_MUTED : (stopAction ? COLOR_ACTION_STOP : COLOR_ACCENT_DARK);
        button.setColorFilter(tint);
        button.setContentDescription(description);
        button.setScaleType(ImageView.ScaleType.CENTER);
        button.setPadding(dp(8), dp(8), dp(8), dp(8));
        button.setMinimumHeight(0);
        button.setMinimumWidth(0);
        int fill = color == COLOR_MUTED ? COLOR_CONTROL : (stopAction ? COLOR_ACTION_STOP_SOFT : COLOR_ACCENT_SOFT);
        button.setBackground(rounded(fill, fill));
        flattenButton(button);
        return button;
    }

    private void flattenButton(View view) {
        view.setStateListAnimator(null);
        view.setElevation(0f);
        view.setTranslationZ(0f);
    }

    private LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        return row;
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

    private GradientDrawable rounded(int fill, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(10));
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
