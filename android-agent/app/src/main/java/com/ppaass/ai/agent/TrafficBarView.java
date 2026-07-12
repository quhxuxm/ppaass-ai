package com.ppaass.ai.agent;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;

// 状态页的 24 小时流量柱状图，外部只需要喂入聚合后的小时数据。
final class TrafficBarView extends View {
    private static final int COLOR_CONTROL_A = UiPalette.CHART_IDLE;
    private static final int COLOR_MUTED = UiPalette.MUTED;
    private static final int COLOR_BORDER = UiPalette.BORDER;
    private static final int COLOR_DOWNLOAD_A = UiPalette.ACTION_START;
    private static final int COLOR_DOWNLOAD_B = UiPalette.ACTION_WARN;
    private static final int COLOR_UPLOAD_A = UiPalette.STATUS_RUNNING;
    private static final int COLOR_UPLOAD_B = UiPalette.ACTION_INFO;
    private static final int[] COLOR_BAR_PALETTE = {
            COLOR_DOWNLOAD_B,
            COLOR_DOWNLOAD_A,
            COLOR_UPLOAD_A,
            COLOR_UPLOAD_B
    };

    private final Paint barPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF barBounds = new RectF();
    private final long[] downloadValues = new long[24];
    private final long[] uploadValues = new long[24];
    private int currentHour;

    TrafficBarView(Context context) {
        super(context);
        gridPaint.setColor(COLOR_BORDER);
        gridPaint.setStrokeWidth(dp(1));
        textPaint.setColor(COLOR_MUTED);
        textPaint.setTextSize(dp(10));
        textPaint.setTextAlign(Paint.Align.CENTER);
    }

    void setHourlyData(long[] hourlyDownloadValues, long[] hourlyUploadValues, int currentHour) {
        for (int i = 0; i < downloadValues.length; i++) {
            downloadValues[i] = i < hourlyDownloadValues.length ? Math.max(0, hourlyDownloadValues[i]) : 0;
            uploadValues[i] = i < hourlyUploadValues.length ? Math.max(0, hourlyUploadValues[i]) : 0;
        }
        this.currentHour = currentHour;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int width = getWidth();
        int height = getHeight();
        float left = dp(8);
        float right = width - dp(8);
        float top = dp(30);
        float bottom = height - dp(25);
        float chartHeight = Math.max(dp(48), bottom - top);

        drawLegend(canvas, left, dp(9), COLOR_UPLOAD_B, "合计");
        drawLegend(canvas, left + dp(72), dp(9), COLOR_CONTROL_A, "空闲");

        for (int i = 0; i < 3; i++) {
            float y = top + chartHeight * i / 2f;
            canvas.drawLine(left, y, right, y, gridPaint);
        }

        long max = maxTraffic();
        float gap = dp(3);
        float groupWidth = Math.max(dp(6), (right - left - gap * 23) / 24f);
        for (int i = 0; i < downloadValues.length; i++) {
            boolean highlighted = i == currentHour;
            float x = left + i * (groupWidth + gap);
            long total = downloadValues[i] + uploadValues[i];
            float totalRatio = max == 0 ? 0f : total / (float) max;
            float totalHeight = total > 0 ? Math.max(dp(7), chartHeight * totalRatio) : dp(4);
            float y = bottom - totalHeight;
            drawTotalBar(canvas, x, y, groupWidth, totalHeight, total, barColor(i), highlighted);
        }

        textPaint.setColor(COLOR_MUTED);
        textPaint.setTextAlign(Paint.Align.CENTER);
        canvas.drawText("00", left + groupWidth / 2f, height - dp(6), textPaint);
        canvas.drawText("12", left + 12 * (groupWidth + gap) + groupWidth / 2f, height - dp(6), textPaint);
        canvas.drawText("23", right - groupWidth / 2f, height - dp(6), textPaint);
    }

    private long maxTraffic() {
        long max = 0;
        for (int i = 0; i < downloadValues.length; i++) {
            max = Math.max(max, downloadValues[i] + uploadValues[i]);
        }
        return max;
    }

    private void drawTotalBar(
            Canvas canvas,
            float x,
            float y,
            float width,
            float totalHeight,
            long total,
            int color,
            boolean highlighted) {
        if (total <= 0) {
            barPaint.setShader(null);
            barPaint.setColor(COLOR_CONTROL_A);
            barBounds.set(x, y, x + width, y + totalHeight);
            canvas.drawRoundRect(barBounds, dp(4), dp(4), barPaint);
            return;
        }

        int alpha = highlighted ? 255 : 188;
        barPaint.setShader(null);
        barPaint.setColor(withAlpha(color, alpha));
        barBounds.set(x, y, x + width, y + totalHeight);
        canvas.drawRoundRect(barBounds, dp(4), dp(4), barPaint);
    }

    private int barColor(int index) {
        return COLOR_BAR_PALETTE[index % COLOR_BAR_PALETTE.length];
    }

    private void drawLegend(Canvas canvas, float x, float y, int color, String label) {
        barBounds.set(x, y, x + dp(14), y + dp(10));
        barPaint.setShader(null);
        barPaint.setColor(color);
        canvas.drawRoundRect(barBounds, dp(5), dp(5), barPaint);
        textPaint.setColor(COLOR_MUTED);
        textPaint.setTextAlign(Paint.Align.LEFT);
        canvas.drawText(label, x + dp(18), y + dp(10), textPaint);
        textPaint.setTextAlign(Paint.Align.CENTER);
    }

    private int withAlpha(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
