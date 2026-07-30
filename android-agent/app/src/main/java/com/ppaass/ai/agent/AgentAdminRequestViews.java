package com.ppaass.ai.agent;

import android.graphics.Bitmap;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

final class AgentAdminRequestViews {
    private AgentAdminRequestViews() {
    }

    static void addCard(
            MainActivityAdminApprovals host,
            LinearLayout root,
            AgentAdminModels.KeyRequest request,
            String activeRequestId,
            List<AgentAdminModels.ProxyAddress> proxyAddresses,
            Callbacks callbacks) {
        LinearLayout card = host.panel(root);
        LinearLayout titleRow = host.horizontalRow();
        View avatar = avatarView(host, request, 42);
        LinearLayout.LayoutParams avatarParams =
                new LinearLayout.LayoutParams(host.dp(42), host.dp(42));
        avatarParams.setMargins(0, 0, host.dp(10), 0);
        titleRow.addView(avatar, avatarParams);
        LinearLayout identity = new LinearLayout(host);
        identity.setOrientation(LinearLayout.VERTICAL);
        TextView name = host.titleText(request.title(), 17f);
        name.setSingleLine(true);
        name.setEllipsize(TextUtils.TruncateAt.END);
        identity.addView(name, host.matchWrap());
        String identityDetail = request.username
                + (request.email.isEmpty() ? "" : " · " + request.email);
        identity.addView(host.mutedText(identityDetail, 12.5f), host.matchWrap());
        titleRow.addView(identity, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        titleRow.addView(
                host.chip(
                        "rotate".equals(request.kind) ? "过期重生成" : "首次申请",
                        "rotate".equals(request.kind)
                                ? host.COLOR_ACTION_WARN
                                : host.COLOR_ACTION_INFO),
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
        card.addView(titleRow, host.matchWrap());

        TextView time = host.mutedText(
                "申请时间："
                        + new SimpleDateFormat(
                        "yyyy-MM-dd HH:mm",
                        Locale.getDefault())
                        .format(new Date(request.requestedAt * 1000L)),
                12.5f);
        LinearLayout.LayoutParams timeParams = host.matchWrap();
        timeParams.setMargins(0, host.dp(9), 0, 0);
        card.addView(time, timeParams);

        TextView message = host.mutedText(
                request.message.isEmpty()
                        ? "用户未填写申请留言"
                        : "申请留言：" + request.message,
                13.5f);
        message.setTextIsSelectable(true);
        message.setPadding(
                host.dp(11), host.dp(9), host.dp(11), host.dp(9));
        message.setBackground(host.rounded(host.COLOR_CONTROL, host.COLOR_BORDER));
        LinearLayout.LayoutParams messageParams = host.matchWrap();
        messageParams.setMargins(0, host.dp(10), 0, 0);
        card.addView(message, messageParams);

        boolean busy = !activeRequestId.isEmpty();
        LinearLayout actions = host.horizontalRow();
        Button reject = host.secondaryButton(
                request.id.equals(activeRequestId) ? "处理中…" : "拒绝");
        reject.setEnabled(!busy);
        reject.setOnClickListener(view -> callbacks.onReject(request));
        actions.addView(reject, new LinearLayout.LayoutParams(
                0, host.dp(42), 1f));
        Button approve = host.actionButton(
                request.id.equals(activeRequestId) ? "处理中…" : "批准",
                host.COLOR_ACTION_START);
        approve.setEnabled(!busy && hasEnabledAddress(proxyAddresses));
        approve.setOnClickListener(view -> AgentAdminApprovalDialog.show(
                host,
                request,
                proxyAddresses,
                callbacks::onApprove));
        LinearLayout.LayoutParams approveParams =
                new LinearLayout.LayoutParams(0, host.dp(42), 1f);
        approveParams.setMargins(host.dp(10), 0, 0, 0);
        actions.addView(approve, approveParams);
        LinearLayout.LayoutParams actionParams = host.matchWrap();
        actionParams.setMargins(0, host.dp(12), 0, 0);
        card.addView(actions, actionParams);
    }

    static View avatarView(
            MainActivityAdminApprovals host,
            AgentAdminModels.KeyRequest request,
            int sizeDp) {
        Bitmap bitmap = AgentProfileAvatar.decode(request.avatarUrl);
        if (bitmap != null) {
            ImageView avatar = new ImageView(host);
            avatar.setImageBitmap(bitmap);
            avatar.setScaleType(ImageView.ScaleType.CENTER_CROP);
            avatar.setBackground(host.rounded(
                    host.COLOR_CONTROL,
                    host.COLOR_BORDER));
            avatar.setClipToOutline(true);
            avatar.setContentDescription(request.title() + "的头像");
            return avatar;
        }
        TextView fallback = host.titleText(
                request.title().substring(0, 1).toUpperCase(Locale.getDefault()),
                sizeDp > 42 ? 18f : 16f);
        fallback.setGravity(Gravity.CENTER);
        fallback.setBackground(host.rounded(
                host.COLOR_CONTROL,
                host.COLOR_BORDER));
        return fallback;
    }

    private static boolean hasEnabledAddress(
            List<AgentAdminModels.ProxyAddress> addresses) {
        for (AgentAdminModels.ProxyAddress address : addresses) {
            if (address.enabled) {
                return true;
            }
        }
        return false;
    }

    interface Callbacks {
        void onReject(AgentAdminModels.KeyRequest request);

        void onApprove(
                AgentAdminModels.KeyRequest request,
                long expiresAt,
                List<String> proxyAddressIds);
    }
}
