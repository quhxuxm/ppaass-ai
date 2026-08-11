package com.ppaass.ai.agent;

import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;

final class ProxyEntrySelectionUi {
    interface SelectionCallback {
        void onFinished(boolean success);
    }

    private ProxyEntrySelectionUi() {
    }

    static void attach(MainActivityConfigScreen host, LinearLayout root) {
        LinearLayout section = host.configSection(root, "Proxy Entry");
        TextView summary = host.mutedText(summary(host), 13f);
        LinearLayout.LayoutParams summaryParams = host.matchWrap();
        summaryParams.setMargins(0, 0, 0, host.dp(10));
        section.addView(summary, summaryParams);
        TextView action = host.actionButton("选择 Proxy Entry", host.COLOR_ACTION_INFO);
        action.setOnClickListener(view -> ProxyEntrySelectionDialog.show(
                host,
                summary,
                action));
        section.addView(action, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                host.dp(48)));
        host.addFieldHelp(section, "选择器仅展示 Entry 图标、名称、描述与状态，不展示服务器地址。");
    }

    private static String summary(MainActivityConfigScreen host) {
        ManagedProxyEntries.Selection selection = ManagedProxyEntries.load(host);
        for (ManagedProxyEntries.Entry entry : selection.entries) {
            if (entry.id.equals(selection.selectedId)) {
                return "当前：" + entry.name;
            }
        }
        return "当前使用管理员分配的 Proxy Entry";
    }

    static void select(
            MainActivityConfigScreen host,
            ManagedProxyEntries.Entry entry,
            TextView summary,
            TextView action,
            SelectionCallback callback) {
        action.setEnabled(false);
        action.setText("正在切换…");
        new Thread(() -> {
            try {
                AgentSessionStore.StoredSession session = AgentSessionStore.load(host);
                AgentAuthClient.ProfileSyncResult result = new AgentProxyEntryClient(
                        host,
                        AgentAuthConfig.proxyRegistryUrl(host)).select(
                        session.accessToken,
                        AgentAuthSession.username(),
                        entry.id);
                if (!AgentAuthSession.applySynchronizedProfile(host, result)) {
                    throw new IOException("无法保存 Proxy Entry 选择");
                }
                host.runOnUiThread(() -> {
                    summary.setText("当前：" + entry.name);
                    action.setEnabled(true);
                    action.setText("选择 Proxy Entry");
                    Toast.makeText(host, "已切换到 " + entry.name, Toast.LENGTH_SHORT).show();
                    callback.onFinished(true);
                });
            } catch (Exception error) {
                host.runOnUiThread(() -> {
                    action.setEnabled(true);
                    action.setText("选择 Proxy Entry");
                    Toast.makeText(
                            host,
                            error.getMessage() == null ? "切换 Proxy Entry 失败" : error.getMessage(),
                            Toast.LENGTH_LONG).show();
                    callback.onFinished(false);
                });
            }
        }, "proxy-entry-selection").start();
    }
}
