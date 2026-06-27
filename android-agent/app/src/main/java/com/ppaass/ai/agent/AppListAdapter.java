package com.ppaass.ai.agent;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.List;

// VPN 应用选择列表只负责渲染，选中状态仍由 Activity 统一保存。
final class AppListAdapter extends BaseAdapter {
    private static final int COLOR_SURFACE = Color.WHITE;
    private static final int COLOR_CONTROL = Color.rgb(241, 245, 249);
    private static final int COLOR_TEXT = Color.rgb(17, 24, 39);
    private static final int COLOR_MUTED = Color.rgb(100, 116, 139);
    private static final int COLOR_BORDER = Color.rgb(226, 232, 240);
    private static final int COLOR_ACCENT_DARK = Color.rgb(29, 78, 216);
    private static final int COLOR_ACCENT_SOFT = Color.rgb(219, 234, 254);

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
            LinearLayout outer = new LinearLayout(context);
            outer.setOrientation(LinearLayout.VERTICAL);
            outer.setPadding(0, 0, 0, dp(4));

            LinearLayout container = new LinearLayout(context);
            container.setOrientation(LinearLayout.HORIZONTAL);
            container.setGravity(Gravity.CENTER_VERTICAL);
            container.setMinimumHeight(dp(68));
            container.setPadding(dp(12), dp(10), dp(12), dp(10));

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
            container.addView(checkBox, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT));

            outer.addView(container, matchWrap());
            row = new AppRow(container, icon, label, packageName, systemBadge, checkBox);
            outer.setTag(row);
            convertView = outer;
        } else {
            row = (AppRow) convertView.getTag();
        }

        bindRow(row, getItem(position), checked[position]);
        return convertView;
    }

    private void bindRow(AppRow row, AppEntry app, boolean selected) {
        row.icon.setImageDrawable(app.icon);
        row.item.setBackground(rounded(
                selected ? COLOR_ACCENT_SOFT : COLOR_SURFACE,
                selected ? COLOR_ACCENT_SOFT : COLOR_BORDER));
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

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
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
