package com.ppaass.ai.agent;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;

final class AgentAdminRequestNotifier {
    static final String EXTRA_OPEN_ADMIN_APPROVALS =
            "com.ppaass.ai.agent.OPEN_ADMIN_APPROVALS";
    private static final String CHANNEL_ID = "ppaass_admin_key_requests";
    private static final int NOTIFICATION_ID = 0x504b5251;

    private AgentAdminRequestNotifier() {
    }

    static void update(Context context, int pendingCount, boolean alert) {
        NotificationManager manager =
                (NotificationManager) context.getSystemService(
                        Context.NOTIFICATION_SERVICE);
        if (manager == null) {
            return;
        }
        if (pendingCount <= 0) {
            manager.cancel(NOTIFICATION_ID);
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        createChannel(manager);
        Intent openApp = new Intent(context, MainActivity.class)
                .putExtra(EXTRA_OPEN_ADMIN_APPROVALS, true)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent contentIntent = PendingIntent.getActivity(
                context,
                17,
                openApp,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        String text = "有 " + pendingCount + " 项密钥申请待处理";
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(context, CHANNEL_ID)
                : new Notification.Builder(context);
        Notification notification = builder
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentTitle("PPAASS 管理员")
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(contentIntent)
                .setAutoCancel(true)
                .setOnlyAlertOnce(!alert)
                .setNumber(pendingCount)
                .setCategory(Notification.CATEGORY_STATUS)
                .build();
        manager.notify(NOTIFICATION_ID, notification);
    }

    static void cancel(Context context) {
        NotificationManager manager =
                (NotificationManager) context.getSystemService(
                        Context.NOTIFICATION_SERVICE);
        if (manager != null) {
            manager.cancel(NOTIFICATION_ID);
        }
    }

    private static void createChannel(NotificationManager manager) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "密钥申请审批",
                NotificationManager.IMPORTANCE_DEFAULT);
        channel.setDescription("管理员收到新的用户密钥申请时提醒");
        manager.createNotificationChannel(channel);
    }
}
