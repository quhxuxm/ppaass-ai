package com.ppaass.ai.agent;

import android.app.AlertDialog;
import android.app.DatePickerDialog;
import android.app.TimePickerDialog;
import android.graphics.Typeface;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class AgentAdminApprovalDialog {
    private AgentAdminApprovalDialog() {
    }

    static void show(
            MainActivityAdminApprovals host,
            AgentAdminModels.KeyRequest request,
            List<AgentAdminModels.ProxyAddress> addresses,
            Listener listener) {
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.YEAR, 1);
        expiry.set(Calendar.SECOND, 0);
        expiry.set(Calendar.MILLISECOND, 0);

        ScrollView scroll = new ScrollView(host);
        scroll.setFillViewport(true);
        LinearLayout root = new LinearLayout(host);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(host.dp(20), host.dp(4), host.dp(20), host.dp(12));
        scroll.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView user = host.titleText(request.title(), 18f);
        root.addView(user, host.matchWrap());
        TextView username = host.mutedText(request.username, 13f);
        root.addView(username, host.matchWrap());

        if (!request.message.isEmpty()) {
            TextView messageLabel = host.controlLabel("用户留言");
            root.addView(messageLabel, host.labelParams());
            TextView message = host.mutedText(request.message, 14f);
            message.setTextIsSelectable(true);
            message.setPadding(
                    host.dp(12), host.dp(10), host.dp(12), host.dp(10));
            message.setBackground(host.rounded(
                    host.COLOR_CONTROL,
                    host.COLOR_BORDER));
            root.addView(message, host.matchWrap());
        }

        TextView expiryLabel = host.controlLabel("新密钥过期时间");
        root.addView(expiryLabel, host.labelParams());
        Button expiryButton = host.secondaryButton("");
        updateExpiryButton(expiryButton, expiry);
        expiryButton.setOnClickListener(view -> chooseDate(host, expiry, expiryButton));
        LinearLayout.LayoutParams expiryParams = host.matchWrap();
        expiryParams.height = host.dp(48);
        root.addView(expiryButton, expiryParams);

        TextView proxyLabel = host.controlLabel("分配 Proxy 地址");
        root.addView(proxyLabel, host.labelParams());
        LinearLayout proxyList = new LinearLayout(host);
        proxyList.setOrientation(LinearLayout.VERTICAL);
        proxyList.setPadding(
                host.dp(10), host.dp(6), host.dp(10), host.dp(6));
        proxyList.setBackground(host.rounded(
                host.COLOR_CONTROL,
                host.COLOR_BORDER));
        root.addView(proxyList, host.matchWrap());

        Set<String> preselected = new HashSet<>(request.proxyAddressIds);
        List<ProxyChoice> choices = new ArrayList<>();
        for (AgentAdminModels.ProxyAddress address : addresses) {
            if (!address.enabled) {
                continue;
            }
            CheckBox checkBox = new CheckBox(host);
            String label = address.title();
            if (!address.label.isEmpty()) {
                label += "\n" + address.address;
            }
            checkBox.setText(label);
            checkBox.setTextColor(host.COLOR_TEXT);
            checkBox.setTextSize(14f);
            checkBox.setTypeface(Typeface.DEFAULT, Typeface.NORMAL);
            checkBox.setPadding(host.dp(4), host.dp(5), host.dp(4), host.dp(5));
            checkBox.setChecked(preselected.contains(address.id));
            proxyList.addView(checkBox, host.matchWrap());
            choices.add(new ProxyChoice(address.id, checkBox));
        }
        if (choices.isEmpty()) {
            TextView empty = host.mutedText(
                    "没有启用的 Proxy 地址，请先在 Proxy Web 中配置。",
                    13f);
            empty.setPadding(host.dp(6), host.dp(10), host.dp(6), host.dp(10));
            proxyList.addView(empty, host.matchWrap());
        }

        TextView error = host.mutedText("", 13f);
        error.setTextColor(host.COLOR_ACTION_STOP);
        error.setVisibility(TextView.GONE);
        LinearLayout.LayoutParams errorParams = host.matchWrap();
        errorParams.setMargins(0, host.dp(10), 0, 0);
        root.addView(error, errorParams);

        AlertDialog dialog = new AlertDialog.Builder(host)
                .setTitle("批准密钥申请")
                .setView(scroll)
                .setNegativeButton("取消", null)
                .setPositiveButton("批准并生成密钥", null)
                .create();
        dialog.setOnShowListener(ignored -> {
            Button approve = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            approve.setEnabled(!choices.isEmpty());
            approve.setOnClickListener(view -> {
                List<String> selected = selectedIds(choices);
                long expiresAt = expiry.getTimeInMillis() / 1000L;
                String validation = validationMessage(
                        System.currentTimeMillis() / 1000L,
                        expiresAt,
                        selected.size());
                if (validation != null) {
                    error.setText(validation);
                    error.setVisibility(TextView.VISIBLE);
                    return;
                }
                dialog.dismiss();
                listener.onApprove(request, expiresAt, selected);
            });
        });
        dialog.show();
    }

    static String validationMessage(
            long nowEpochSeconds,
            long expiresAt,
            int selectedProxyCount) {
        if (expiresAt <= nowEpochSeconds) {
            return "密钥过期时间必须晚于当前时间";
        }
        if (selectedProxyCount < 1) {
            return "请至少选择一个启用的 Proxy 地址";
        }
        return null;
    }

    private static void chooseDate(
            MainActivityAdminApprovals host,
            Calendar value,
            Button button) {
        DatePickerDialog date = new DatePickerDialog(
                host,
                (picker, year, month, day) -> {
                    value.set(Calendar.YEAR, year);
                    value.set(Calendar.MONTH, month);
                    value.set(Calendar.DAY_OF_MONTH, day);
                    chooseTime(host, value, button);
                },
                value.get(Calendar.YEAR),
                value.get(Calendar.MONTH),
                value.get(Calendar.DAY_OF_MONTH));
        date.getDatePicker().setMinDate(System.currentTimeMillis());
        date.show();
    }

    private static void chooseTime(
            MainActivityAdminApprovals host,
            Calendar value,
            Button button) {
        new TimePickerDialog(
                host,
                (picker, hour, minute) -> {
                    value.set(Calendar.HOUR_OF_DAY, hour);
                    value.set(Calendar.MINUTE, minute);
                    value.set(Calendar.SECOND, 0);
                    value.set(Calendar.MILLISECOND, 0);
                    updateExpiryButton(button, value);
                },
                value.get(Calendar.HOUR_OF_DAY),
                value.get(Calendar.MINUTE),
                true).show();
    }

    private static void updateExpiryButton(Button button, Calendar value) {
        button.setText(new SimpleDateFormat(
                "yyyy-MM-dd HH:mm",
                Locale.getDefault()).format(value.getTime()));
    }

    private static List<String> selectedIds(List<ProxyChoice> choices) {
        List<String> selected = new ArrayList<>();
        for (ProxyChoice choice : choices) {
            if (choice.checkBox.isChecked()) {
                selected.add(choice.id);
            }
        }
        return selected;
    }

    interface Listener {
        void onApprove(
                AgentAdminModels.KeyRequest request,
                long expiresAt,
                List<String> proxyAddressIds);
    }

    private static final class ProxyChoice {
        final String id;
        final CheckBox checkBox;

        ProxyChoice(String id, CheckBox checkBox) {
            this.id = id;
            this.checkBox = checkBox;
        }
    }
}
