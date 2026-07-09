package com.ppaass.ai.agent;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.view.View;

// 状态页的速度仪表盘，只负责绘制，不参与业务状态计算。
final class SpeedGaugeView extends View {
    private static final int COLOR_TRACK = Color.rgb(225, 229, 239);
    private static final int COLOR_TEXT = Color.rgb(35, 41, 53);
    private static final int COLOR_MUTED = Color.rgb(105, 113, 130);
    private static final int COLOR_DOWNLOAD_A = Color.rgb(242, 193, 0);
    private static final int COLOR_DOWNLOAD_B = Color.rgb(229, 22, 112);
    private static final int COLOR_UPLOAD_A = Color.rgb(21, 94, 232);
    private static final int COLOR_UPLOAD_B = Color.rgb(217, 91, 135);

    private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint progressPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint chipPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF arcBounds = new RectF();
    private final RectF chipBounds = new RectF();
    private long rxBytesPerSecond;
    private long txBytesPerSecond;
    private boolean active;

    SpeedGaugeView(Context context) {
        super(context);
        trackPaint.setStyle(Paint.Style.STROKE);
        trackPaint.setStrokeCap(Paint.Cap.ROUND);
        trackPaint.setColor(COLOR_TRACK);
        progressPaint.setStyle(Paint.Style.STROKE);
        progressPaint.setStrokeCap(Paint.Cap.ROUND);
        textPaint.setTextAlign(Paint.Align.CENTER);
        chipPaint.setStyle(Paint.Style.FILL);
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
        long scale = gaugeScale(Math.max(rxBytesPerSecond, txBytesPerSecond));
        float outerPadding = dp(18);
        float centerGap = dp(22);
        float availableWidth = Math.max(0f, width - outerPadding * 2f - centerGap);
        if (availableWidth <= dp(96)) {
            return;
        }
        float gaugeSlotWidth = availableWidth / 2f;
        float centerY = height * 0.42f;
        float radius = Math.min(gaugeSlotWidth * 0.38f, height * 0.30f);
        float leftCenterX = outerPadding + gaugeSlotWidth / 2f;
        float rightCenterX = outerPadding + gaugeSlotWidth + centerGap + gaugeSlotWidth / 2f;

        drawGauge(
                canvas,
                leftCenterX,
                centerY,
                radius,
                rxBytesPerSecond,
                scale,
                "下载",
                COLOR_DOWNLOAD_A,
                COLOR_DOWNLOAD_B);
        drawGauge(
                canvas,
                rightCenterX,
                centerY,
                radius,
                txBytesPerSecond,
                scale,
                "上传",
                COLOR_UPLOAD_A,
                COLOR_UPLOAD_B);

        textPaint.setTypeface(Typeface.DEFAULT);
        textPaint.setColor(COLOR_MUTED);
        textPaint.setTextSize(dp(11));
        canvas.drawText(
                active ? "双通道实时速率 · 刻度 " + formatSpeed(scale) : "VPN 空闲 · 等待流量",
                width / 2f,
                height - dp(12),
                textPaint);
    }

    private void drawGauge(
            Canvas canvas,
            float centerX,
            float centerY,
            float radius,
            long speed,
            long scale,
            String label,
            int startColor,
            int endColor) {
        float stroke = Math.min(dp(14), Math.max(dp(9), radius * 0.22f));
        arcBounds.set(centerX - radius, centerY - radius, centerX + radius, centerY + radius);
        trackPaint.setStrokeWidth(stroke);
        progressPaint.setStrokeWidth(stroke);
        progressPaint.setShader(new LinearGradient(
                centerX - radius,
                centerY,
                centerX + radius,
                centerY,
                startColor,
                endColor,
                Shader.TileMode.CLAMP));

        canvas.drawArc(arcBounds, 145f, 250f, false, trackPaint);
        float sweep = active ? Math.min(250f, speed * 250f / Math.max(1, scale)) : 0f;
        canvas.drawArc(arcBounds, 145f, sweep, false, progressPaint);
        progressPaint.setShader(null);

        textPaint.setTypeface(Typeface.DEFAULT_BOLD);
        textPaint.setColor(startColor);
        textPaint.setTextSize(dp(24));
        canvas.drawText(formatNumber(speed), centerX, centerY + dp(3), textPaint);

        textPaint.setTypeface(Typeface.DEFAULT);
        textPaint.setColor(COLOR_TEXT);
        textPaint.setTextSize(dp(12));
        canvas.drawText(unitLabel(speed), centerX, centerY + dp(22), textPaint);

        float chipWidth = Math.min(dp(78), Math.max(dp(56), radius * 1.55f));
        chipBounds.set(
                centerX - chipWidth / 2f,
                centerY + radius * 0.52f,
                centerX + chipWidth / 2f,
                centerY + radius * 0.52f + dp(24));
        chipPaint.setShader(new LinearGradient(
                chipBounds.left,
                chipBounds.top,
                chipBounds.right,
                chipBounds.bottom,
                Color.argb(64, startColor >> 16 & 0xff, startColor >> 8 & 0xff, startColor & 0xff),
                Color.argb(78, endColor >> 16 & 0xff, endColor >> 8 & 0xff, endColor & 0xff),
                Shader.TileMode.CLAMP));
        canvas.drawRoundRect(chipBounds, dp(12), dp(12), chipPaint);
        chipPaint.setShader(null);

        textPaint.setTypeface(Typeface.DEFAULT_BOLD);
        textPaint.setColor(COLOR_TEXT);
        textPaint.setTextSize(dp(11));
        canvas.drawText(label, centerX, chipBounds.top + dp(16), textPaint);
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

    private String formatNumber(long bytesPerSecond) {
        double value = bytesPerSecond;
        int unit = 0;
        while (value >= 1024 && unit < 4) {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? String.format("%.0f", value) : String.format("%.1f", value);
    }

    private String unitLabel(long bytesPerSecond) {
        double value = bytesPerSecond;
        String[] units = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s"};
        int unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return units[unit];
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
