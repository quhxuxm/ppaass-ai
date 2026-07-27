package com.ppaass.ai.agent;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.view.View;

// 状态页的 24 小时上传/下载趋势图，外部只需要喂入聚合后的小时数据。
final class TrafficBarView extends View {
    private final int COLOR_MUTED = UiPalette.MUTED;
    private final int COLOR_BORDER = UiPalette.BORDER;
    private final int COLOR_DOWNLOAD = UiPalette.ACTION_INFO;
    private final int COLOR_UPLOAD = UiPalette.STATUS_RUNNING;

    private final Paint chartPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF legendBounds = new RectF();
    private final Path chartPath = new Path();
    private final Path areaPath = new Path();
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

        drawLegend(canvas, left, dp(9), COLOR_DOWNLOAD, UiLanguage.tr(getContext(), "每小时下载"));
        drawLegend(canvas, left + dp(108), dp(9), COLOR_UPLOAD, UiLanguage.tr(getContext(), "每小时上传"));

        for (int i = 0; i < 3; i++) {
            float y = top + chartHeight * i / 2f;
            canvas.drawLine(left, y, right, y, gridPaint);
        }

        long max = maxTraffic();
        drawSeries(canvas, downloadValues, max, left, right, top, bottom, COLOR_DOWNLOAD);
        drawSeries(canvas, uploadValues, max, left, right, top, bottom, COLOR_UPLOAD);

        textPaint.setColor(COLOR_MUTED);
        textPaint.setTextAlign(Paint.Align.CENTER);
        drawHourLabel(canvas, left, right, 0, height);
        drawHourLabel(canvas, left, right, 6, height);
        drawHourLabel(canvas, left, right, 12, height);
        drawHourLabel(canvas, left, right, 18, height);
        drawHourLabel(canvas, left, right, 23, height);
    }

    private long maxTraffic() {
        long max = 0;
        for (int i = 0; i < downloadValues.length; i++) {
            max = Math.max(max, Math.max(downloadValues[i], uploadValues[i]));
        }
        return Math.max(1, max);
    }

    private void drawSeries(
            Canvas canvas,
            long[] values,
            long max,
            float left,
            float right,
            float top,
            float bottom,
            int color) {
        chartPath.reset();
        areaPath.reset();
        float chartWidth = right - left;
        for (int index = 0; index < values.length; index++) {
            float x = left + chartWidth * index / 23f;
            float y = bottom - (bottom - top) * values[index] / (float) max;
            if (index == 0) {
                chartPath.moveTo(x, y);
                areaPath.moveTo(x, bottom);
                areaPath.lineTo(x, y);
            } else {
                chartPath.lineTo(x, y);
                areaPath.lineTo(x, y);
            }
        }
        areaPath.lineTo(right, bottom);
        areaPath.close();
        chartPaint.setStyle(Paint.Style.FILL);
        chartPaint.setColor(withAlpha(color, 32));
        canvas.drawPath(areaPath, chartPaint);
        chartPaint.setStyle(Paint.Style.STROKE);
        chartPaint.setStrokeWidth(dp(2));
        chartPaint.setStrokeCap(Paint.Cap.ROUND);
        chartPaint.setStrokeJoin(Paint.Join.ROUND);
        chartPaint.setColor(color);
        canvas.drawPath(chartPath, chartPaint);

        float currentX = left + chartWidth * Math.max(0, Math.min(23, currentHour)) / 23f;
        float currentY = bottom - (bottom - top)
                * values[Math.max(0, Math.min(23, currentHour))] / (float) max;
        chartPaint.setStyle(Paint.Style.FILL);
        chartPaint.setColor(color);
        canvas.drawCircle(currentX, currentY, dp(3), chartPaint);
    }

    private void drawLegend(Canvas canvas, float x, float y, int color, String label) {
        legendBounds.set(x, y, x + dp(14), y + dp(4));
        chartPaint.setStyle(Paint.Style.FILL);
        chartPaint.setColor(color);
        canvas.drawRoundRect(legendBounds, dp(2), dp(2), chartPaint);
        textPaint.setColor(COLOR_MUTED);
        textPaint.setTextAlign(Paint.Align.LEFT);
        canvas.drawText(label, x + dp(18), y + dp(10), textPaint);
        textPaint.setTextAlign(Paint.Align.CENTER);
    }

    private void drawHourLabel(Canvas canvas, float left, float right, int hour, int height) {
        float x = left + (right - left) * hour / 23f;
        canvas.drawText(String.format(java.util.Locale.ROOT, "%02d", hour), x, height - dp(6), textPaint);
    }

    private int withAlpha(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
