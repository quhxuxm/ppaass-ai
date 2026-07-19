package com.ppaass.ai.agent;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.List;

// VPN 应用选择列表只负责渲染，选中状态仍由 Activity 统一保存。
final class AppListAdapter extends BaseAdapter {
    private final int COLOR_SURFACE = UiPalette.SURFACE;
    private final int COLOR_CONTROL = UiPalette.CONTROL;
    private final int COLOR_TEXT = UiPalette.TEXT;
    private final int COLOR_MUTED = UiPalette.MUTED;
    private final int COLOR_BORDER = UiPalette.BORDER;
    private final int COLOR_ACCENT = UiPalette.ACCENT;
    private final int COLOR_ACCENT_DARK = UiPalette.ACCENT_STRONG;
    private final int COLOR_ACCENT_SOFT = UiPalette.ACCENT_SOFT;
    private final int COLOR_ACTION_START = UiPalette.ACTION_WARN;

    private final Context context;
    private final List<AppEntry> apps;
    private final boolean[] checked;

    AppListAdapter(Context context, List<AppEntry> apps, boolean[] checked) {
        this.context = context;
        this.apps = apps;
        this.checked = checked;
    }

    @Override
    public int getCount() {
        return apps.size();
    }

    @Override
    public AppEntry getItem(int position) {
        return apps.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        AppRow row;
        if (convertView == null) {
            LinearLayout container = new FullWidthRow(context);
            container.setOrientation(LinearLayout.HORIZONTAL);
            container.setGravity(Gravity.CENTER_VERTICAL);
            container.setMinimumHeight(dp(68));
            container.setPadding(dp(12), dp(10), dp(12), dp(10));
            // 实际绘制项目背景的容器必须直接作为 ListView 的行根视图。
            // 如果再套一层透明 LinearLayout，部分系统会让内层按内容宽度收缩。
            container.setLayoutParams(new AbsListView.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT));

            ImageView icon = new ImageView(context);
            icon.setPadding(dp(4), dp(4), dp(4), dp(4));
            icon.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
            LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(44), dp(44));
            iconParams.setMargins(0, 0, dp(12), 0);
            container.addView(icon, iconParams);

            LinearLayout textColumn = new LinearLayout(context);
            textColumn.setOrientation(LinearLayout.VERTICAL);
            TextView label = newLabelView();
            TextView systemBadge = systemBadge();
            LinearLayout labelRow = horizontalRow(label, systemBadge);
            textColumn.addView(labelRow, matchWrap());

            TextView packageName = new TextView(context);
            packageName.setSingleLine(true);
            packageName.setEllipsize(TextUtils.TruncateAt.END);
            packageName.setTextSize(12f);
            packageName.setTextColor(COLOR_MUTED);
            textColumn.addView(packageName, matchWrap());

            container.addView(textColumn, new LinearLayout.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f));
            CheckBox checkBox = new CheckBox(context);
            checkBox.setClickable(false);
            checkBox.setFocusable(false);
            checkBox.setButtonTintList(new ColorStateList(
                    new int[][]{
                            new int[]{android.R.attr.state_checked},
                            new int[]{-android.R.attr.state_enabled},
                            new int[]{}
                    },
                    new int[]{COLOR_ACCENT, alphaColor(COLOR_MUTED, 104), COLOR_MUTED}));
            container.addView(checkBox, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT));

            row = new AppRow(container, icon, label, packageName, systemBadge, checkBox);
            container.setTag(row);
            convertView = container;
        } else {
            row = (AppRow) convertView.getTag();
        }

        bindRow(row, getItem(position), checked[position]);
        return convertView;
    }

    private void bindRow(AppRow row, AppEntry app, boolean selected) {
        row.icon.setImageDrawable(app.icon);
        row.icon.setBackground(iconPlate(selected ? COLOR_ACCENT_DARK : COLOR_ACTION_START));
        row.item.setBackground(interactiveRounded(
                selected ? COLOR_ACCENT_SOFT : COLOR_SURFACE,
                selected ? alphaColor(COLOR_ACCENT, 138) : COLOR_BORDER));
        row.label.setText(app.label);
        row.label.setTextColor(selected ? COLOR_ACCENT_DARK : COLOR_TEXT);
        row.packageName.setText(app.packageName);
        row.systemBadge.setVisibility(app.systemApp ? View.VISIBLE : View.GONE);
        row.checkBox.setChecked(selected);
    }

    private LinearLayout horizontalRow(TextView label, TextView systemBadge) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.addView(label, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        LinearLayout.LayoutParams badgeParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        badgeParams.setMargins(dp(8), 0, 0, 0);
        row.addView(systemBadge, badgeParams);
        return row;
    }

    private TextView newLabelView() {
        TextView label = new TextView(context);
        label.setSingleLine(true);
        label.setEllipsize(TextUtils.TruncateAt.END);
        label.setTextSize(15f);
        label.setTypeface(Typeface.DEFAULT_BOLD);
        return label;
    }

    private TextView systemBadge() {
        TextView badge = new TextView(context);
        badge.setText("系统");
        badge.setTextSize(11f);
        badge.setTextColor(COLOR_MUTED);
        badge.setTypeface(Typeface.DEFAULT_BOLD);
        badge.setPadding(dp(8), dp(2), dp(8), dp(2));
        badge.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        return badge;
    }

    private GradientDrawable rounded(int fill, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(12));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private GradientDrawable iconPlate(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(alphaColor(color, 24));
        drawable.setCornerRadius(dp(12));
        drawable.setStroke(dp(1), alphaColor(color, 108));
        return drawable;
    }

    private Drawable interactiveRounded(int fill, int stroke) {
        return new RippleDrawable(
                ColorStateList.valueOf(alphaColor(COLOR_ACCENT, 74)),
                rounded(fill, stroke),
                null);
    }

    private int alphaColor(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }

    // 部分 Android 厂商的 ListView 会使用 AT_MOST 测量行根视图。
    // 即使 LayoutParams 是 MATCH_PARENT，LinearLayout 仍会按内容宽度收缩；
    // 将 ListView 给出的可用宽度改为 EXACTLY，保证每个项目等宽铺满。
    private static final class FullWidthRow extends LinearLayout {
        FullWidthRow(Context context) {
            super(context);
        }

        @Override
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            if (View.MeasureSpec.getMode(widthMeasureSpec) == View.MeasureSpec.AT_MOST) {
                widthMeasureSpec = View.MeasureSpec.makeMeasureSpec(
                        View.MeasureSpec.getSize(widthMeasureSpec),
                        View.MeasureSpec.EXACTLY);
            }
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        }
    }

    private static final class AppRow {
        final View item;
        final ImageView icon;
        final TextView label;
        final TextView packageName;
        final TextView systemBadge;
        final CheckBox checkBox;

        AppRow(View item, ImageView icon, TextView label, TextView packageName, TextView systemBadge, CheckBox checkBox) {
            this.item = item;
            this.icon = icon;
            this.label = label;
            this.packageName = packageName;
            this.systemBadge = systemBadge;
            this.checkBox = checkBox;
        }
    }
}
