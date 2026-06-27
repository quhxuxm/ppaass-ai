package com.ppaass.ai.agent;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;

// 状态页的 24 小时流量柱状图，外部只需要喂入聚合后的小时数据。
final class TrafficBarView extends View {
    private static final int COLOR_CONTROL = Color.rgb(241, 245, 249);
    private static final int COLOR_MUTED = Color.rgb(100, 116, 139);
    private static final int COLOR_BORDER = Color.rgb(226, 232, 240);
    private static final int COLOR_ACCENT = Color.rgb(37, 99, 235);
    private static final int COLOR_ACTION_START = Color.rgb(15, 118, 110);

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
        float left = dp(6);
        float right = width - dp(6);
        float top = dp(28);
        float bottom = height - dp(24);
        float chartHeight = Math.max(dp(48), bottom - top);

        drawLegend(canvas, right - dp(146), dp(10), COLOR_ACCENT, "下载");
        drawLegend(canvas, right - dp(76), dp(10), COLOR_ACTION_START, "上传");

        for (int i = 0; i < 3; i++) {
            float y = top + chartHeight * i / 2f;
            canvas.drawLine(left, y, right, y, gridPaint);
        }

        long max = maxTraffic();
        float gap = dp(3);
        float groupWidth = Math.max(dp(5), (right - left - gap * 23) / 24f);
        float barGap = dp(1);
        float barWidth = Math.max(dp(2), (groupWidth - barGap) / 2f);
        for (int i = 0; i < downloadValues.length; i++) {
            boolean highlighted = i == currentHour;
            float x = left + i * (groupWidth + gap);
            drawTrafficBar(canvas, downloadValues[i], max, x, bottom, chartHeight,
                    barWidth,
                    highlighted ? COLOR_ACCENT : Color.rgb(147, 197, 253));
            drawTrafficBar(canvas, uploadValues[i], max, x + barWidth + barGap, bottom, chartHeight,
                    barWidth,
                    highlighted ? COLOR_ACTION_START : Color.rgb(94, 234, 212));
        }

        canvas.drawText("00", left + barWidth / 2f, height - dp(6), textPaint);
        canvas.drawText("12", left + 12 * (groupWidth + gap) + groupWidth / 2f, height - dp(6), textPaint);
        canvas.drawText("23", right - groupWidth / 2f, height - dp(6), textPaint);
    }

    private long maxTraffic() {
        long max = 0;
        for (int i = 0; i < downloadValues.length; i++) {
            max = Math.max(max, downloadValues[i]);
            max = Math.max(max, uploadValues[i]);
        }
        return max;
    }

    private void drawTrafficBar(Canvas canvas, long value, long max, float x, float bottom, float chartHeight, float barWidth, int color) {
        boolean hasValue = value > 0;
        float ratio = max == 0 ? 0f : value / (float) max;
        float barHeight = hasValue ? Math.max(dp(4), chartHeight * ratio) : dp(3);
        float y = bottom - barHeight;
        barPaint.setColor(hasValue ? color : COLOR_CONTROL);
        barBounds.set(x, y, x + barWidth, bottom);
        canvas.drawRoundRect(barBounds, dp(3), dp(3), barPaint);
    }

    private void drawLegend(Canvas canvas, float x, float y, int color, String label) {
        barPaint.setColor(color);
        barBounds.set(x, y, x + dp(10), y + dp(10));
        canvas.drawRoundRect(barBounds, dp(3), dp(3), barPaint);
        textPaint.setTextAlign(Paint.Align.LEFT);
        canvas.drawText(label, x + dp(14), y + dp(10), textPaint);
        textPaint.setTextAlign(Paint.Align.CENTER);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
