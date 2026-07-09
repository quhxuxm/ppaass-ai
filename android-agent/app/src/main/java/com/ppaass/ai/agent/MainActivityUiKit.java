package com.ppaass.ai.agent;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.graphics.*;
import android.graphics.drawable.*;
import android.net.*;
import android.os.*;
import android.text.*;
import android.view.*;
import android.view.inputmethod.*;
import android.widget.*;

import org.json.*;

import java.io.*;
import java.net.*;
import java.security.*;
import java.text.*;
import java.util.*;

// MainActivity 拆分层：保持单个文件短小，便于定位 Android UI 问题。
abstract class MainActivityUiKit extends MainActivityState {

private static final int[] CARD_ACCENTS = {
        COLOR_ACCENT,
        COLOR_ACTION_START,
        COLOR_ACTION_INFO,
        COLOR_ACCENT
};

protected Button secondaryButton(String text) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(13f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setEllipsize(TextUtils.TruncateAt.END);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(dp(8), 0, dp(8), 0);
        button.setTextColor(COLOR_ACCENT_DARK);
        button.setBackground(rounded(COLOR_ACCENT_SOFT, COLOR_ACCENT_SOFT));
        flattenButton(button);
        return button;
    }

protected GradientDrawable gradient(int start, int end) {
        GradientDrawable drawable = new GradientDrawable(
                GradientDrawable.Orientation.TL_BR,
                new int[]{start, end});
        drawable.setCornerRadius(dp(16));
        drawable.setStroke(dp(1), Color.argb(150, 255, 255, 255));
        return drawable;
    }

protected GradientDrawable softGradient(int start, int end, int stroke) {
        GradientDrawable drawable = new GradientDrawable(
                GradientDrawable.Orientation.TL_BR,
                new int[]{start, end});
        drawable.setCornerRadius(dp(16));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

protected int alphaColor(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

protected Drawable appBackground() {
        return new Drawable() {
            private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

            @Override
            public void draw(Canvas canvas) {
                Rect bounds = getBounds();
                int width = Math.max(1, bounds.width());
                int height = Math.max(1, bounds.height());

                paint.setShader(new LinearGradient(
                        0,
                        0,
                        width,
                        height,
                        Color.rgb(248, 244, 250),
                        COLOR_BACKGROUND,
                        Shader.TileMode.CLAMP));
                canvas.drawRect(bounds, paint);

                drawWash(canvas, width * 0.14f, height * 0.03f, width * 0.42f, COLOR_ACCENT, 30);
                drawWash(canvas, width * 0.74f, 0f, width * 0.38f, COLOR_ACTION_START, 34);
                drawWash(canvas, width * 0.90f, height * 0.82f, width * 0.34f, COLOR_ACTION_INFO, 18);
                paint.setShader(null);
            }

            private void drawWash(Canvas canvas, float cx, float cy, float radius, int color, int alpha) {
                paint.setShader(new RadialGradient(
                        cx,
                        cy,
                        radius,
                        alphaColor(color, alpha),
                        Color.TRANSPARENT,
                        Shader.TileMode.CLAMP));
                canvas.drawCircle(cx, cy, radius, paint);
            }

            @Override
            public void setAlpha(int alpha) {
                paint.setAlpha(alpha);
            }

            @Override
            public void setColorFilter(android.graphics.ColorFilter colorFilter) {
                paint.setColorFilter(colorFilter);
            }

            @Override
            public int getOpacity() {
                return PixelFormat.TRANSLUCENT;
            }
        };
    }

protected int cardAccent(int index) {
        return CARD_ACCENTS[Math.floorMod(index, CARD_ACCENTS.length)];
    }

protected GradientDrawable iconPlateBackground(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(Color.WHITE);
        drawable.setCornerRadius(dp(10));
        drawable.setStroke(dp(1), alphaColor(color, 72));
        return drawable;
    }

protected ImageView iconPlate(int icon, int color) {
        ImageView view = new ImageView(this);
        view.setImageResource(icon);
        view.setColorFilter(color);
        view.setBackground(iconPlateBackground(color));
        view.setPadding(dp(6), dp(6), dp(6), dp(6));
        return view;
    }

protected int sectionIconColor(String text) {
        if (text.contains("流量") || text.contains("代理")) {
            return COLOR_ACTION_WARN;
        }
        if (text.contains("DNS") || text.contains("应用")) {
            return COLOR_ACCENT;
        }
        if (text.contains("连通")) {
            return COLOR_ACTION_START;
        }
        return COLOR_ACTION_INFO;
    }

protected void applySystemBarPadding(
            View view,
            int baseLeft,
            int baseTop,
            int baseRight,
            int baseBottom) {
        int topFallback = systemBarInsetFallback("status_bar_height");
        int bottomFallback = systemBarInsetFallback("navigation_bar_height");
        view.setOnApplyWindowInsetsListener((target, insets) -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Insets systemBars = insets.getInsets(WindowInsets.Type.systemBars());
                target.setPadding(
                        baseLeft + systemBars.left,
                        baseTop + Math.max(systemBars.top, topFallback),
                        baseRight + systemBars.right,
                        baseBottom + Math.max(systemBars.bottom, bottomFallback));
            } else {
                applyLegacySystemBarPadding(
                        target,
                        insets,
                        baseLeft,
                        baseTop,
                        baseRight,
                        baseBottom,
                        topFallback,
                        bottomFallback);
            }
            return insets;
        });
    }

protected int systemBarInsetFallback(String resourceName) {
        if (Build.VERSION.SDK_INT < 35) {
            return 0;
        }
        int resourceId = getResources().getIdentifier(resourceName, "dimen", "android");
        if (resourceId == 0) {
            return 0;
        }
        return getResources().getDimensionPixelSize(resourceId);
    }

@SuppressWarnings("deprecation")
    protected void applyLegacySystemBarPadding(
            View target,
            WindowInsets insets,
            int baseLeft,
            int baseTop,
            int baseRight,
            int baseBottom,
            int topFallback,
            int bottomFallback) {
        target.setPadding(
                baseLeft + insets.getSystemWindowInsetLeft(),
                baseTop + Math.max(insets.getSystemWindowInsetTop(), topFallback),
                baseRight + insets.getSystemWindowInsetRight(),
                baseBottom + Math.max(insets.getSystemWindowInsetBottom(), bottomFallback));
    }

protected Button actionButton(String text, int color) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(15f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setEllipsize(TextUtils.TruncateAt.END);
        button.setIncludeFontPadding(false);
        button.setMinHeight(0);
        button.setMinWidth(0);
        applyActionButtonStyle(button, color);
        flattenButton(button);
        return button;
    }

protected void applyActionButtonStyle(Button button, int color) {
        int fill = actionButtonFill(color);
        button.setTextColor(actionButtonText(color));
        if (color == COLOR_ACTION_START) {
            button.setTextColor(COLOR_TEXT);
            button.setBackground(rounded(COLOR_ACTION_START_SOFT, COLOR_ACTION_START));
            return;
        }
        if (color == COLOR_ACCENT) {
            button.setTextColor(COLOR_ACCENT);
            button.setBackground(rounded(COLOR_ACTION_WARN_SOFT, COLOR_ACTION_WARN));
            return;
        }
        if (color == COLOR_ACTION_INFO) {
            button.setTextColor(COLOR_ACTION_INFO);
            button.setBackground(rounded(COLOR_ACTION_INFO_SOFT, COLOR_ACTION_INFO));
            return;
        }
        if (color == COLOR_ACTION_STOP) {
            button.setTextColor(COLOR_ACTION_STOP);
            button.setBackground(rounded(COLOR_ACTION_STOP_SOFT, COLOR_ACTION_STOP));
            return;
        }
        button.setBackground(rounded(fill, fill));
    }

protected int actionButtonFill(int color) {
        if (color == COLOR_ACTION_STOP) {
            return COLOR_ACTION_STOP_SOFT;
        }
        if (color == COLOR_ACTION_INFO) {
            return COLOR_ACTION_INFO_SOFT;
        }
        if (color == COLOR_ACTION_WARN) {
            return COLOR_ACTION_WARN_SOFT;
        }
        if (color == COLOR_ACTION_START) {
            return COLOR_ACTION_START_SOFT;
        }
        if (color == COLOR_STATUS_STOPPED) {
            return COLOR_STATUS_STOPPED_SOFT;
        }
        return COLOR_ACTION_START_SOFT;
    }

protected int actionButtonText(int color) {
        if (color == COLOR_ACTION_STOP) {
            return COLOR_ACTION_STOP;
        }
        if (color == COLOR_ACTION_INFO) {
            return COLOR_ACTION_INFO;
        }
        if (color == COLOR_ACTION_WARN) {
            return COLOR_ACTION_WARN;
        }
        if (color == COLOR_ACTION_START) {
            return COLOR_TEXT;
        }
        if (color == COLOR_STATUS_STOPPED) {
            return COLOR_MUTED;
        }
        return COLOR_ACCENT_DARK;
    }

protected LinearLayout panel(LinearLayout root) {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(18), dp(16), dp(18), dp(18));
        panel.setBackground(rounded(COLOR_SURFACE, alphaColor(cardAccent(root.getChildCount()), 86)));
        panel.setStateListAnimator(null);
        panel.setElevation(dp(4));
        panel.setTranslationZ(dp(2));
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, root.getChildCount() == 0 ? 0 : dp(16), 0, 0);
        root.addView(panel, params);
        return panel;
    }

protected LinearLayout configSection(LinearLayout root, String title) {
        LinearLayout section = panel(root);
        section.setPadding(dp(18), dp(18), dp(18), dp(20));
        sectionTitle(section, title);
        return section;
    }

protected LinearLayout configGroup(LinearLayout root, String title, String appliesWhen) {
        LinearLayout group = new LinearLayout(this);
        group.setOrientation(LinearLayout.VERTICAL);
        group.setPadding(dp(12), dp(10), dp(12), dp(12));
        group.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        LinearLayout heading = horizontalRow();
        TextView titleView = titleText(title, 13f);
        heading.addView(titleView, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        TextView badge = chip(appliesWhen, COLOR_STATUS_STOPPED);
        heading.addView(badge, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        group.addView(heading, matchWrap());

        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(12), 0, 0);
        root.addView(group, params);
        return group;
    }

protected LinearLayout screenTabBar() {
        LinearLayout row = horizontalRow();
        row.setPadding(dp(4), dp(4), dp(4), dp(4));
        row.setBackground(rounded(COLOR_SURFACE, alphaColor(COLOR_ACTION_INFO, 42)));
        row.setStateListAnimator(null);
        row.setElevation(dp(3));
        row.setTranslationZ(dp(1));
        return row;
    }

protected FrameLayout screenPageHost(LinearLayout root) {
        FrameLayout host = new FrameLayout(this);
        host.setClipChildren(false);
        host.setClipToPadding(false);
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(14), 0, 0);
        root.addView(host, params);
        screenPageHost = host;
        return host;
    }

protected LinearLayout screenPage(FrameLayout host) {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setVisibility(View.GONE);
        page.setAlpha(0f);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        host.addView(page, params);
        screenPages.add(page);
        return page;
    }

protected void addScreenTab(LinearLayout tabBar, String title, View page) {
        Button button = new Button(this);
        button.setText(title);
        button.setTextSize(14f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(dp(8), 0, dp(8), 0);
        flattenButton(button);
        int index = screenTabButtons.size();
        button.setOnClickListener(view -> selectScreen(index));
        screenTabButtons.add(button);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(44), 1f);
        if (index > 0) {
            params.setMargins(dp(4), 0, 0, 0);
        }
        tabBar.addView(button, params);

        if (!screenPages.contains(page)) {
            screenPages.add(page);
        }
    }

protected void selectScreen(int selectedIndex) {
        if (screenPages.isEmpty()) {
            selectedScreenIndex = 0;
            return;
        }
        int boundedIndex = Math.max(0, Math.min(selectedIndex, screenPages.size() - 1));
        int previousIndex = Math.max(0, Math.min(selectedScreenIndex, screenPages.size() - 1));
        View previousPage = screenPages.get(previousIndex);
        boolean firstSelection = previousPage.getVisibility() != View.VISIBLE
                || screenPageHost == null
                || screenPageHost.getWidth() == 0;

        if (boundedIndex == previousIndex && !firstSelection) {
            updateScreenTabs(boundedIndex);
            return;
        }

        selectedScreenIndex = boundedIndex;
        updateScreenTabs(boundedIndex);
        if (firstSelection) {
            showScreenWithoutAnimation(boundedIndex);
            return;
        }
        animateScreenSwitch(previousIndex, boundedIndex);
    }

private void updateScreenTabs(int selectedIndex) {
        for (int i = 0; i < screenTabButtons.size(); i++) {
            Button button = screenTabButtons.get(i);
            boolean selected = i == selectedIndex;
            button.setTextColor(selected ? COLOR_ACTION_INFO : COLOR_MUTED);
            button.setBackground(selected
                    ? rounded(COLOR_ACTION_INFO_SOFT, COLOR_ACTION_INFO_SOFT)
                    : rounded(COLOR_CONTROL, COLOR_CONTROL));
        }
    }

private void showScreenWithoutAnimation(int selectedIndex) {
        cancelScreenAnimations();
        for (int i = 0; i < screenPages.size(); i++) {
            View page = screenPages.get(i);
            boolean selected = i == selectedIndex;
            page.setVisibility(selected ? View.VISIBLE : View.GONE);
            page.setAlpha(selected ? 1f : 0f);
            page.setTranslationX(0f);
        }
    }

private void animateScreenSwitch(int fromIndex, int toIndex) {
        cancelScreenAnimations();

        View fromPage = screenPages.get(fromIndex);
        View toPage = screenPages.get(toIndex);
        int direction = toIndex > fromIndex ? 1 : -1;
        int width = Math.max(
                screenPageHost == null ? 0 : screenPageHost.getWidth(),
                getResources().getDisplayMetrics().widthPixels);
        float incomingOffset = width * 0.22f * direction;
        float outgoingOffset = width * -0.16f * direction;
        long duration = 240L;

        screenSwitchAnimating = true;
        toPage.setVisibility(View.VISIBLE);
        toPage.setAlpha(0f);
        toPage.setTranslationX(incomingOffset);
        fromPage.setVisibility(View.VISIBLE);
        fromPage.setAlpha(1f);
        fromPage.setTranslationX(0f);

        android.view.animation.Interpolator interpolator =
                new android.view.animation.DecelerateInterpolator(1.6f);
        fromPage.animate()
                .translationX(outgoingOffset)
                .alpha(0f)
                .setDuration(duration)
                .setInterpolator(interpolator)
                .start();
        toPage.animate()
                .translationX(0f)
                .alpha(1f)
                .setDuration(duration)
                .setInterpolator(interpolator)
                .withEndAction(() -> finishScreenSwitch(toIndex))
                .start();
    }

private void finishScreenSwitch(int selectedIndex) {
        for (int i = 0; i < screenPages.size(); i++) {
            View page = screenPages.get(i);
            boolean selected = i == selectedIndex;
            page.setVisibility(selected ? View.VISIBLE : View.GONE);
            page.setAlpha(selected ? 1f : 0f);
            page.setTranslationX(0f);
        }
        screenSwitchAnimating = false;
    }

private void cancelScreenAnimations() {
        for (View page : screenPages) {
            page.animate().cancel();
        }
        screenSwitchAnimating = false;
    }

protected void handleScreenSwipeEvent(MotionEvent event) {
        if (screenPages.size() < 2) {
            resetScreenSwipe();
            return;
        }

        int action = event.getActionMasked();
        if (action == MotionEvent.ACTION_DOWN) {
            resetScreenSwipe();
            screenSwipeTracking = true;
            screenSwipeStartX = event.getRawX();
            screenSwipeStartY = event.getRawY();
            screenSwipeVelocityTracker = VelocityTracker.obtain();
            screenSwipeVelocityTracker.addMovement(event);
            return;
        }

        if (!screenSwipeTracking) {
            return;
        }

        if (screenSwipeVelocityTracker != null) {
            screenSwipeVelocityTracker.addMovement(event);
        }

        if (action == MotionEvent.ACTION_MOVE) {
            float dx = event.getRawX() - screenSwipeStartX;
            float dy = event.getRawY() - screenSwipeStartY;
            int touchSlop = ViewConfiguration.get(this).getScaledTouchSlop();
            if (Math.abs(dy) > touchSlop && Math.abs(dy) > Math.abs(dx)) {
                resetScreenSwipe();
            }
            return;
        }

        if (action == MotionEvent.ACTION_UP) {
            maybeSelectScreenFromSwipe(
                    event.getRawX() - screenSwipeStartX,
                    event.getRawY() - screenSwipeStartY);
            resetScreenSwipe();
            return;
        }

        if (action == MotionEvent.ACTION_CANCEL) {
            resetScreenSwipe();
        }
    }

private void maybeSelectScreenFromSwipe(float dx, float dy) {
        float absDx = Math.abs(dx);
        float absDy = Math.abs(dy);
        if (absDx <= absDy * 1.35f) {
            return;
        }

        float velocityX = 0f;
        if (screenSwipeVelocityTracker != null) {
            screenSwipeVelocityTracker.computeCurrentVelocity(1000);
            velocityX = screenSwipeVelocityTracker.getXVelocity();
        }

        boolean distanceSwipe = absDx >= dp(72);
        boolean flingSwipe = absDx >= dp(36) && Math.abs(velocityX) >= dp(420);
        if (!distanceSwipe && !flingSwipe) {
            return;
        }

        selectScreen(selectedScreenIndex + (dx < 0 ? 1 : -1));
    }

private void resetScreenSwipe() {
        screenSwipeTracking = false;
        if (screenSwipeVelocityTracker != null) {
            screenSwipeVelocityTracker.recycle();
            screenSwipeVelocityTracker = null;
        }
    }

protected TextView statusTile(LinearLayout row, String label, String value) {
        LinearLayout tile = new LinearLayout(this);
        tile.setOrientation(LinearLayout.VERTICAL);
        tile.setPadding(dp(12), dp(10), dp(12), dp(10));
        tile.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        TextView labelView = mutedText(label, 12f);
        tile.addView(labelView, matchWrap());

        TextView valueView = titleText(value, 18f);
        valueView.setSingleLine(true);
        valueView.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams valueParams = matchWrap();
        valueParams.setMargins(0, dp(2), 0, 0);
        tile.addView(valueView, valueParams);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(78), 1f);
        if (row.getChildCount() > 0) {
            params.setMargins(dp(10), 0, 0, 0);
        }
        row.addView(tile, params);
        return valueView;
    }

protected LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        return row;
    }

protected LinearLayout controlRow() {
        LinearLayout row = horizontalRow();
        row.setPadding(0, dp(8), 0, dp(4));
        return row;
    }

protected void sectionTitle(LinearLayout root, String text) {
        LinearLayout row = horizontalRow();
        row.setPadding(0, 0, 0, dp(6));

        ImageView icon = iconPlate(R.drawable.ic_section_24, sectionIconColor(text));
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(28), dp(28));
        iconParams.setMargins(0, 0, dp(8), 0);
        row.addView(icon, iconParams);

        TextView view = titleText(text, 15f);
        row.addView(view, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        root.addView(row, matchWrap());
    }

protected TextView titleText(String text, float size) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(COLOR_TEXT);
        view.setTextSize(size);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        return view;
    }

protected TextView mutedText(String text, float size) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(COLOR_MUTED);
        view.setTextSize(size);
        return view;
    }

protected TextView controlLabel(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(13f);
        view.setTextColor(COLOR_MUTED);
        view.setGravity(Gravity.CENTER_VERTICAL);
        view.setMaxLines(2);
        view.setEllipsize(TextUtils.TruncateAt.END);
        return view;
    }

protected LinearLayout.LayoutParams labelParams() {
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(10), 0, dp(6));
        return params;
    }

protected TextView chip(String text, int color) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(12f);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setTextColor(chipText(color));
        view.setSingleLine(true);
        view.setEllipsize(TextUtils.TruncateAt.END);
        view.setGravity(Gravity.CENTER);
        view.setPadding(dp(10), dp(5), dp(10), dp(5));
        int fill = chipFill(color);
        view.setBackground(rounded(fill, fill));
        return view;
    }

protected int chipFill(int color) {
        if (color == COLOR_ACTION_STOP) {
            return COLOR_ACTION_STOP_SOFT;
        }
        if (color == COLOR_ACTION_INFO) {
            return COLOR_ACTION_INFO_SOFT;
        }
        if (color == COLOR_ACTION_WARN) {
            return COLOR_ACTION_WARN_SOFT;
        }
        if (color == COLOR_STATUS_STOPPED) {
            return COLOR_STATUS_STOPPED_SOFT;
        }
        if (color == COLOR_ACTION_START) {
            return COLOR_ACTION_START_SOFT;
        }
        if (color == COLOR_STATUS_RUNNING) {
            return Color.rgb(222, 247, 238);
        }
        return COLOR_ACTION_WARN_SOFT;
    }

    protected int chipText(int color) {
        if (color == COLOR_ACTION_STOP) {
            return COLOR_ACTION_STOP;
        }
        if (color == COLOR_ACTION_INFO) {
            return COLOR_ACTION_INFO;
        }
        if (color == COLOR_ACTION_WARN) {
            return COLOR_ACTION_WARN;
        }
        if (color == COLOR_STATUS_STOPPED) {
            return COLOR_MUTED;
        }
        if (color == COLOR_ACTION_START) {
            return COLOR_ACTION_START;
        }
        if (color == COLOR_STATUS_RUNNING) {
            return COLOR_STATUS_RUNNING;
        }
        return COLOR_ACCENT;
    }

}
