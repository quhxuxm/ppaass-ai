package com.ppaass.ai.agent;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.view.View;

// 状态页的速度仪表盘，只负责绘制，不参与业务状态计算。
final class SpeedGaugeView extends View {
    private static final int COLOR_CONTROL = Color.rgb(241, 245, 249);
    private static final int COLOR_TEXT = Color.rgb(17, 24, 39);
    private static final int COLOR_MUTED = Color.rgb(100, 116, 139);
    private static final int COLOR_ACCENT = Color.rgb(45, 170, 158);

    private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint progressPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF arcBounds = new RectF();
    private long rxBytesPerSecond;
    private long txBytesPerSecond;
    private boolean active;

    SpeedGaugeView(Context context) {
        super(context);
        trackPaint.setStyle(Paint.Style.STROKE);
        trackPaint.setStrokeCap(Paint.Cap.ROUND);
        trackPaint.setColor(COLOR_CONTROL);
        progressPaint.setStyle(Paint.Style.STROKE);
        progressPaint.setStrokeCap(Paint.Cap.ROUND);
        progressPaint.setColor(COLOR_ACCENT);
        textPaint.setTextAlign(Paint.Align.CENTER);
    }

    void setSpeeds(long rxBytesPerSecond, long txBytesPerSecond, boolean active) {
        this.rxBytesPerSecond = Math.max(0, rxBytesPerSecond);
        this.txBytesPerSecond = Math.max(0, txBytesPerSecond);
        this.active = active;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int width = getWidth();
        int height = getHeight();
        float stroke = dp(16);
        float radius = Math.min(width * 0.38f, height * 0.50f);
        float centerX = width / 2f;
        float centerY = dp(28) + radius;
        arcBounds.set(centerX - radius, centerY - radius, centerX + radius, centerY + radius);

        trackPaint.setStrokeWidth(stroke);
        progressPaint.setStrokeWidth(stroke);
        canvas.drawArc(arcBounds, 150f, 240f, false, trackPaint);

        long totalSpeed = rxBytesPerSecond + txBytesPerSecond;
        long scale = gaugeScale(totalSpeed);
        float sweep = active ? Math.min(240f, totalSpeed * 240f / scale) : 0f;
        canvas.drawArc(arcBounds, 150f, sweep, false, progressPaint);

        textPaint.setTypeface(Typeface.DEFAULT_BOLD);
        textPaint.setColor(COLOR_TEXT);
        textPaint.setTextSize(dp(28));
        canvas.drawText(formatSpeed(totalSpeed), centerX, centerY + dp(4), textPaint);

        textPaint.setTypeface(Typeface.DEFAULT);
        textPaint.setColor(COLOR_MUTED);
        textPaint.setTextSize(dp(12));
        canvas.drawText(active ? "实时速度" : "VPN 空闲", centerX, centerY + dp(30), textPaint);
        canvas.drawText("刻度 " + formatSpeed(scale), centerX, Math.min(height - dp(10), centerY + dp(54)), textPaint);
    }

    private long gaugeScale(long speed) {
        long scale = 64L * 1024L;
        while (speed > scale && scale < 1024L * 1024L * 1024L) {
            scale *= 2L;
        }
        return scale;
    }

    private String formatSpeed(long bytesPerSecond) {
        return formatBytes(bytesPerSecond) + "/s";
    }

    private String formatBytes(long bytes) {
        double value = bytes;
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        int unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? String.format("%.0f %s", value, units[unit]) : String.format("%.1f %s", value, units[unit]);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
