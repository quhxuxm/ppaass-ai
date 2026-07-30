package com.ppaass.ai.agent;

import android.app.AlertDialog;
import android.graphics.Typeface;
import android.text.InputFilter;
import android.view.Window;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

final class AgentAdminRejectionDialog {
    private static final int MAX_REASON_CHARACTERS = 500;

    private AgentAdminRejectionDialog() {
    }

    static void show(
            MainActivityAdminApprovals host,
            AgentAdminModels.KeyRequest request,
            Listener listener) {
        LinearLayout root = new LinearLayout(host);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(host.dp(20), host.dp(20), host.dp(20), host.dp(14));
        root.setBackgroundColor(host.COLOR_SURFACE);

        root.addView(host.titleText("拒绝密钥申请", 22f), host.matchWrap());

        LinearLayout identity = new LinearLayout(host);
        identity.setOrientation(LinearLayout.HORIZONTAL);
        identity.setGravity(android.view.Gravity.CENTER_VERTICAL);
        identity.setPadding(
                host.dp(12), host.dp(10), host.dp(12), host.dp(10));
        identity.setBackground(host.rounded(
                host.COLOR_CONTROL,
                host.COLOR_BORDER));
        LinearLayout.LayoutParams avatarParams =
                new LinearLayout.LayoutParams(host.dp(44), host.dp(44));
        avatarParams.setMargins(0, 0, host.dp(11), 0);
        identity.addView(
                AgentAdminRequestViews.avatarView(host, request, 44),
                avatarParams);
        LinearLayout identityText = new LinearLayout(host);
        identityText.setOrientation(LinearLayout.VERTICAL);
        identityText.addView(
                host.titleText(request.title(), 17f),
                host.matchWrap());
        if (!request.title().equals(request.username)) {
            identityText.addView(
                    host.mutedText(request.username, 12.5f),
                    host.matchWrap());
        }
        identity.addView(identityText, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        LinearLayout.LayoutParams identityParams = host.matchWrap();
        identityParams.setMargins(0, host.dp(12), 0, 0);
        root.addView(identity, identityParams);

        TextView description = host.mutedText(
                "可填写拒绝原因，用户会在账户页面看到。",
                14f);
        LinearLayout.LayoutParams descriptionParams = host.matchWrap();
        descriptionParams.setMargins(0, host.dp(10), 0, 0);
        root.addView(description, descriptionParams);

        TextView label = host.controlLabel("拒绝理由（可选）");
        root.addView(label, host.labelParams());
        EditText reason = new EditText(host);
        reason.setTextColor(host.COLOR_TEXT);
        reason.setHintTextColor(host.COLOR_MUTED);
        reason.setTextSize(14f);
        reason.setTypeface(Typeface.DEFAULT);
        reason.setHint("例如：请补充用途说明后重新申请");
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

        TextView limit = host.mutedText("最多 500 个字符", 12f);
        LinearLayout.LayoutParams limitParams = host.matchWrap();
        limitParams.setMargins(0, host.dp(6), 0, 0);
        root.addView(limit, limitParams);

        AlertDialog dialog = new AlertDialog.Builder(host)
                .setView(root)
                .setNegativeButton("取消", null)
                .setPositiveButton("拒绝申请", null)
                .create();
        dialog.setOnShowListener(ignored -> {
            Window window = dialog.getWindow();
            if (window != null) {
                window.setBackgroundDrawable(host.rounded(
                        host.COLOR_SURFACE,
                        host.COLOR_BORDER));
            }
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE)
                    .setTextColor(host.COLOR_MUTED);
            Button reject = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            reject.setTextColor(host.COLOR_ACTION_STOP);
            reject.setOnClickListener(view -> {
                String value = reason.getText().toString().trim();
                dialog.dismiss();
                listener.onReject(request, value);
            });
        });
        dialog.show();
    }

    interface Listener {
        void onReject(AgentAdminModels.KeyRequest request, String reason);
    }
}
