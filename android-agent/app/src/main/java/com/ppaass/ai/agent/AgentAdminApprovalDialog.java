package com.ppaass.ai.agent;

import android.app.AlertDialog;
import android.app.DatePickerDialog;
import android.app.TimePickerDialog;
import android.graphics.Typeface;
import android.text.InputFilter;
import android.view.Window;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
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
    private static final int MAX_REASON_CHARACTERS = 500;

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
        scroll.setBackgroundColor(host.COLOR_SURFACE);
        LinearLayout root = new LinearLayout(host);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(host.dp(20), host.dp(20), host.dp(20), host.dp(14));
        root.setBackgroundColor(host.COLOR_SURFACE);
        scroll.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView dialogTitle = host.titleText("批准密钥申请", 22f);
        root.addView(dialogTitle, host.matchWrap());

        LinearLayout identity = new LinearLayout(host);
        identity.setOrientation(LinearLayout.HORIZONTAL);
        identity.setGravity(android.view.Gravity.CENTER_VERTICAL);
        identity.setPadding(
                host.dp(14), host.dp(12), host.dp(14), host.dp(12));
        identity.setBackground(host.rounded(
                host.COLOR_CONTROL,
                host.COLOR_BORDER));
        LinearLayout.LayoutParams avatarParams =
                new LinearLayout.LayoutParams(host.dp(48), host.dp(48));
        avatarParams.setMargins(0, 0, host.dp(12), 0);
        identity.addView(
                AgentAdminRequestViews.avatarView(host, request, 48),
                avatarParams);
        LinearLayout identityText = new LinearLayout(host);
        identityText.setOrientation(LinearLayout.VERTICAL);
        TextView user = host.titleText(request.title(), 18f);
        identityText.addView(user, host.matchWrap());
        TextView username = host.mutedText(request.username, 13f);
        LinearLayout.LayoutParams usernameParams = host.matchWrap();
        usernameParams.setMargins(0, host.dp(3), 0, 0);
        identityText.addView(username, usernameParams);
        identity.addView(identityText, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        LinearLayout.LayoutParams identityParams = host.matchWrap();
        identityParams.setMargins(0, host.dp(14), 0, 0);
        root.addView(identity, identityParams);

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
                    "没有启用的 Proxy 地址，请先在 Proxy Registry 中配置。",
                    13f);
            empty.setPadding(host.dp(6), host.dp(10), host.dp(6), host.dp(10));
            proxyList.addView(empty, host.matchWrap());
        }

        TextView reasonLabel = host.controlLabel("操作原因");
        root.addView(reasonLabel, host.labelParams());
        EditText reason = new EditText(host);
        reason.setTextColor(host.COLOR_TEXT);
        reason.setHintTextColor(host.COLOR_MUTED);
        reason.setTextSize(14f);
        reason.setTypeface(Typeface.DEFAULT);
        reason.setHint("例如：已核实用户用途和密钥有效期");
        reason.setGravity(android.view.Gravity.TOP | android.view.Gravity.START);
        reason.setMinLines(3);
        reason.setMaxLines(5);
        reason.setPadding(host.dp(12), host.dp(10), host.dp(12), host.dp(10));
        reason.setBackground(host.rounded(host.COLOR_CONTROL, host.COLOR_BORDER));
        reason.setFilters(new InputFilter[]{
                new InputFilter.LengthFilter(MAX_REASON_CHARACTERS)
        });
        LinearLayout.LayoutParams reasonParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                host.dp(112));
        root.addView(reason, reasonParams);

        TextView reasonLimit = host.mutedText("必填，最多 500 个字符", 12f);
        LinearLayout.LayoutParams reasonLimitParams = host.matchWrap();
        reasonLimitParams.setMargins(0, host.dp(6), 0, 0);
        root.addView(reasonLimit, reasonLimitParams);

        TextView error = host.mutedText("", 13f);
        error.setTextColor(host.COLOR_ACTION_STOP);
        error.setVisibility(TextView.GONE);
        LinearLayout.LayoutParams errorParams = host.matchWrap();
        errorParams.setMargins(0, host.dp(10), 0, 0);
        root.addView(error, errorParams);

        AlertDialog dialog = new AlertDialog.Builder(host)
                .setView(scroll)
                .setNegativeButton("取消", null)
                .setPositiveButton("批准并生成密钥", null)
                .create();
        dialog.setOnShowListener(ignored -> {
            styleDialogSurface(host, dialog);
            Button approve = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            approve.setTextColor(host.COLOR_ACCENT_DARK);
            approve.setEnabled(!choices.isEmpty());
            approve.setOnClickListener(view -> {
                List<String> selected = selectedIds(choices);
                long expiresAt = expiry.getTimeInMillis() / 1000L;
                String validation = validationMessage(
                        System.currentTimeMillis() / 1000L,
                        expiresAt,
                        selected.size(),
                        reason.getText().toString());
                if (validation != null) {
                    error.setText(validation);
                    error.setVisibility(TextView.VISIBLE);
                    return;
                }
                dialog.dismiss();
                listener.onApprove(
                        request,
                        expiresAt,
                        selected,
                        reason.getText().toString().trim());
            });
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE)
                    .setTextColor(host.COLOR_MUTED);
        });
        dialog.show();
    }

    private static void styleDialogSurface(
            MainActivityAdminApprovals host,
            AlertDialog dialog) {
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(host.rounded(
                    host.COLOR_SURFACE,
                    host.COLOR_BORDER));
        }
    }

    static String validationMessage(
            long nowEpochSeconds,
            long expiresAt,
            int selectedProxyCount,
            String reason) {
        if (expiresAt <= nowEpochSeconds) {
            return "密钥过期时间必须晚于当前时间";
        }
        if (selectedProxyCount < 1) {
            return "请至少选择一个启用的 Proxy 地址";
        }
        if (reason == null || reason.trim().isEmpty()) {
            return "请填写本次审批的操作原因";
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
                List<String> proxyAddressIds,
                String reason);
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
