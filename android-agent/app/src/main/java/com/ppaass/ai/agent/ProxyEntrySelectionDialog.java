package com.ppaass.ai.agent;

import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

final class ProxyEntrySelectionDialog {
    private ProxyEntrySelectionDialog() {
    }

    static void show(MainActivityConfigScreen host, TextView summary, TextView action) {
        ManagedProxyEntries.Selection selection = ManagedProxyEntries.load(host);
        if (selection.entries.isEmpty()) {
            Toast.makeText(host, host.tr("暂无可用 Proxy Entry"), Toast.LENGTH_SHORT).show();
            return;
        }
        List<ManagedProxyEntries.Entry> entries = selectedFirst(
                selection.entries,
                selection.selectedId);
        ProxyEntryAdapter adapter = new ProxyEntryAdapter(host, entries, selection.selectedId);
        ListView list = buildList(host, entries.size(), adapter);
        AlertDialog dialog = new AlertDialog.Builder(host)
                .setView(buildContent(host, list, entries.size()))
                .setNegativeButton("取消", null)
                .setPositiveButton("确认切换", null)
                .create();

        list.setOnItemClickListener((parent, view, position, id) -> {
            ManagedProxyEntries.Entry entry = adapter.getItem(position);
            if (entry == null) {
                return;
            }
            adapter.setPendingId(entry.id);
            Button confirm = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            if (confirm != null) {
                confirm.setEnabled(!entry.id.equals(selection.selectedId));
            }
        });
        dialog.setOnShowListener(ignored -> configureDialog(
                host,
                dialog,
                list,
                adapter,
                selection.selectedId,
                summary,
                action));
        dialog.show();
    }

    private static ListView buildList(
            MainActivityConfigScreen host,
            int count,
            ProxyEntryAdapter adapter) {
        ListView list = new ListView(host);
        list.setAdapter(adapter);
        list.setDivider(new ColorDrawable(Color.TRANSPARENT));
        list.setDividerHeight(host.dp(ProxyEntryAdapter.ROW_DIVIDER_DP));
        list.setSelector(android.R.color.transparent);
        list.setPadding(0, host.dp(4), 0, host.dp(4));
        list.setClipToPadding(false);
        boolean scrollable = count > 4;
        list.setVerticalScrollBarEnabled(scrollable);
        list.setScrollbarFadingEnabled(!scrollable);
        list.setScrollBarStyle(View.SCROLLBARS_INSIDE_OVERLAY);
        list.setOverScrollMode(scrollable
                ? View.OVER_SCROLL_IF_CONTENT_SCROLLS
                : View.OVER_SCROLL_NEVER);
        return list;
    }

    private static LinearLayout buildContent(
            MainActivityConfigScreen host,
            ListView list,
            int count) {
        LinearLayout content = new LinearLayout(host);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(host.dp(20), host.dp(22), host.dp(20), host.dp(10));
        content.addView(dialogHeading(host), host.matchWrap());
        TextView subtitle = host.mutedText(
                "选择后点击确认切换；测速不会改变当前节点",
                13f);
        LinearLayout.LayoutParams subtitleParams = host.matchWrap();
        subtitleParams.setMargins(0, host.dp(6), 0, host.dp(16));
        content.addView(subtitle, subtitleParams);
        int visibleRows = Math.min(count, 4);
        int rowExtent = ProxyEntryAdapter.ROW_HEIGHT_DP
                + ProxyEntryAdapter.ROW_DIVIDER_DP;
        int listHeight = Math.min(
                host.dp(500),
                host.dp(rowExtent) * visibleRows + host.dp(8));
        content.addView(list, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                listHeight));
        if (count > 4) {
            TextView hint = host.mutedText("上下滑动查看更多节点 · 共 " + count + " 个", 12f);
            hint.setGravity(Gravity.CENTER);
            LinearLayout.LayoutParams hintParams = host.matchWrap();
            hintParams.setMargins(0, host.dp(8), 0, 0);
            content.addView(hint, hintParams);
        }
        return content;
    }

    private static View dialogHeading(MainActivityConfigScreen host) {
        LinearLayout row = new LinearLayout(host);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        ImageView icon = new ImageView(host);
        icon.setImageResource(R.drawable.ic_proxy_24);
        icon.setColorFilter(host.COLOR_ACCENT);
        icon.setPadding(host.dp(8), host.dp(8), host.dp(8), host.dp(8));
        icon.setBackground(host.iconPlateBackground(host.COLOR_ACCENT));
        row.addView(icon, new LinearLayout.LayoutParams(host.dp(40), host.dp(40)));
        TextView title = host.titleText("选择 Proxy Entry", 20f);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f);
        titleParams.setMargins(host.dp(12), 0, 0, 0);
        row.addView(title, titleParams);
        return row;
    }

    private static void configureDialog(
            MainActivityConfigScreen host,
            AlertDialog dialog,
            ListView list,
            ProxyEntryAdapter adapter,
            String selectedId,
            TextView summary,
            TextView action) {
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(host.rounded(host.COLOR_SURFACE, host.COLOR_BORDER));
            int screenWidth = host.getResources().getDisplayMetrics().widthPixels;
            window.setLayout(
                    Math.min(screenWidth - host.dp(24), host.dp(620)),
                    WindowManager.LayoutParams.WRAP_CONTENT);
        }
        Button cancel = dialog.getButton(AlertDialog.BUTTON_NEGATIVE);
        Button confirm = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
        cancel.setTextColor(host.COLOR_MUTED);
        confirm.setTextColor(host.COLOR_ACCENT_DARK);
        confirm.setEnabled(false);
        host.flattenButton(cancel);
        host.flattenButton(confirm);
        confirm.setOnClickListener(view -> confirmSelection(
                host,
                dialog,
                list,
                adapter,
                selectedId,
                summary,
                action,
                confirm,
                cancel));
        list.setSelection(0);
    }

    private static void confirmSelection(
            MainActivityConfigScreen host,
            AlertDialog dialog,
            ListView list,
            ProxyEntryAdapter adapter,
            String selectedId,
            TextView summary,
            TextView action,
            Button confirm,
            Button cancel) {
        ManagedProxyEntries.Entry entry = adapter.pendingEntry();
        if (entry == null || entry.id.equals(selectedId)) {
            return;
        }
        confirm.setEnabled(false);
        confirm.setText("正在切换…");
        cancel.setEnabled(false);
        list.setEnabled(false);
        ProxyEntrySelectionUi.select(host, entry, summary, action, success -> {
            if (success) {
                dialog.dismiss();
                return;
            }
            confirm.setText("确认切换");
            confirm.setEnabled(true);
            cancel.setEnabled(true);
            list.setEnabled(true);
        });
    }

    private static List<ManagedProxyEntries.Entry> selectedFirst(
            List<ManagedProxyEntries.Entry> entries,
            String selectedId) {
        List<ManagedProxyEntries.Entry> ordered = new ArrayList<>(entries.size());
        for (ManagedProxyEntries.Entry entry : entries) {
            if (entry.id.equals(selectedId)) {
                ordered.add(entry);
                break;
            }
        }
        for (ManagedProxyEntries.Entry entry : entries) {
            if (!entry.id.equals(selectedId)) {
                ordered.add(entry);
            }
        }
        return ordered;
    }
}
