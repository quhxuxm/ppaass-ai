package com.ppaass.ai.agent;

import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.ArrayAdapter;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class ProxyEntryAdapter extends ArrayAdapter<ManagedProxyEntries.Entry> {
    static final int ROW_HEIGHT_DP = 146;
    static final int ROW_DIVIDER_DP = 12;

    private final MainActivityConfigScreen host;
    private final String currentId;
    private final Map<String, String> speedResults = new HashMap<>();
    private String pendingId;
    private String testingId;

    ProxyEntryAdapter(
            MainActivityConfigScreen host,
            List<ManagedProxyEntries.Entry> entries,
            String currentId) {
        super(host, 0, entries);
        this.host = host;
        this.currentId = currentId;
        this.pendingId = currentId;
    }

    void setPendingId(String id) {
        if (id.equals(pendingId)) {
            return;
        }
        pendingId = id;
        notifyDataSetChanged();
    }

    ManagedProxyEntries.Entry pendingEntry() {
        for (int index = 0; index < getCount(); index++) {
            ManagedProxyEntries.Entry entry = getItem(index);
            if (entry != null && entry.id.equals(pendingId)) {
                return entry;
            }
        }
        return null;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        RowHolder holder;
        if (convertView != null && convertView.getTag() instanceof RowHolder) {
            holder = (RowHolder) convertView.getTag();
        } else {
            holder = createRow();
        }
        ManagedProxyEntries.Entry entry = getItem(position);
        bind(holder, entry);
        return holder.row;
    }

    private RowHolder createRow() {
        LinearLayout row = new LinearLayout(host);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(host.dp(12), host.dp(12), host.dp(12), host.dp(12));
        row.setLayoutParams(new AbsListView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                host.dp(ROW_HEIGHT_DP)));

        FrameLayout badge = new FrameLayout(host);
        ImageView icon = new ImageView(host);
        icon.setImageResource(R.drawable.ic_proxy_24);
        icon.setColorFilter(Color.WHITE);
        icon.setPadding(host.dp(12), host.dp(12), host.dp(12), host.dp(12));
        badge.addView(icon, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        row.addView(badge, new LinearLayout.LayoutParams(host.dp(46), host.dp(46)));

        TextColumn column = createTextColumn();
        LinearLayout.LayoutParams columnParams = new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f);
        columnParams.setMargins(host.dp(12), 0, host.dp(8), 0);
        row.addView(column.root, columnParams);

        ActionColumn actions = createActionColumn();
        row.addView(actions.root, new LinearLayout.LayoutParams(
                host.dp(64),
                ViewGroup.LayoutParams.WRAP_CONTENT));

        RowHolder holder = new RowHolder(row, badge, column, actions);
        row.setTag(holder);
        return holder;
    }

    private TextColumn createTextColumn() {
        LinearLayout root = new LinearLayout(host);
        root.setOrientation(LinearLayout.VERTICAL);
        TextView name = label("", 16f, host.COLOR_TEXT);
        name.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        name.setSingleLine(true);
        name.setEllipsize(TextUtils.TruncateAt.END);
        root.addView(name);
        TextView description = label("", 13f, host.COLOR_MUTED);
        description.setMaxLines(2);
        description.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams descriptionParams = host.matchWrap();
        descriptionParams.setMargins(0, host.dp(2), 0, host.dp(3));
        root.addView(description, descriptionParams);

        LinearLayout statusLine = new LinearLayout(host);
        statusLine.setOrientation(LinearLayout.HORIZONTAL);
        statusLine.setGravity(Gravity.CENTER_VERTICAL);
        View statusDot = new View(host);
        statusLine.addView(statusDot, new LinearLayout.LayoutParams(host.dp(7), host.dp(7)));
        TextView status = label("", 12f, host.COLOR_MUTED);
        status.setSingleLine(true);
        LinearLayout.LayoutParams statusParams = wrapContent();
        statusParams.setMargins(host.dp(6), 0, 0, 0);
        statusLine.addView(status, statusParams);
        TextView stateTag = stateTag();
        LinearLayout.LayoutParams tagParams = wrapContent();
        tagParams.setMargins(host.dp(8), 0, 0, 0);
        statusLine.addView(stateTag, tagParams);
        root.addView(statusLine);

        TextView speedResult = label("测速结果", 12f, host.COLOR_ACTION_INFO);
        speedResult.setSingleLine(true);
        speedResult.setEllipsize(TextUtils.TruncateAt.END);
        speedResult.setVisibility(View.INVISIBLE);
        LinearLayout.LayoutParams resultParams = host.matchWrap();
        resultParams.setMargins(0, host.dp(3), 0, 0);
        root.addView(speedResult, resultParams);
        return new TextColumn(root, name, description, statusDot, status, stateTag, speedResult);
    }

    private ActionColumn createActionColumn() {
        LinearLayout root = new LinearLayout(host);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        TextView mark = label("", 17f, Color.WHITE);
        mark.setSingleLine(true);
        mark.setGravity(Gravity.CENTER);
        root.addView(mark, new LinearLayout.LayoutParams(host.dp(32), host.dp(32)));
        TextView speed = label("测速", 12f, host.COLOR_ACTION_INFO);
        speed.setSingleLine(true);
        speed.setGravity(Gravity.CENTER);
        speed.setPadding(host.dp(8), host.dp(5), host.dp(8), host.dp(5));
        speed.setBackground(host.interactiveRounded(
                host.COLOR_ACTION_INFO_SOFT,
                host.COLOR_ACTION_INFO,
                host.COLOR_ACTION_INFO));
        LinearLayout.LayoutParams speedParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        speedParams.setMargins(0, host.dp(8), 0, 0);
        root.addView(speed, speedParams);
        return new ActionColumn(root, mark, speed);
    }

    private TextView stateTag() {
        TextView tag = label("待切换", 10f, host.COLOR_ACTION_INFO);
        tag.setSingleLine(true);
        tag.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        tag.setPadding(host.dp(7), host.dp(2), host.dp(7), host.dp(2));
        tag.setVisibility(View.INVISIBLE);
        return tag;
    }

    private void bind(RowHolder holder, ManagedProxyEntries.Entry entry) {
        boolean current = entry.id.equals(currentId);
        boolean pending = entry.id.equals(pendingId) && !current;
        int fill = current
                ? host.COLOR_ACCENT_SOFT
                : pending ? host.COLOR_ACTION_INFO_SOFT : host.COLOR_CONTROL;
        int stroke = current
                ? host.COLOR_ACCENT
                : pending ? host.COLOR_ACTION_INFO : host.COLOR_BORDER;
        holder.row.setBackground(host.interactiveRounded(fill, stroke, host.COLOR_ACCENT));
        holder.badge.setBackground(iconBackground(entry));
        holder.text.name.setText(entry.name);
        holder.text.description.setText(entry.description);
        bindStatus(holder.text, entry, current, pending);
        bindSpeedResult(holder.text.speedResult, entry);
        bindActions(holder.actions, entry, current, pending);
    }

    private void bindStatus(
            TextColumn text,
            ManagedProxyEntries.Entry entry,
            boolean current,
            boolean pending) {
        int statusColor = entry.online ? host.COLOR_STATUS_RUNNING : host.COLOR_MUTED;
        GradientDrawable dot = new GradientDrawable();
        dot.setShape(GradientDrawable.OVAL);
        dot.setColor(statusColor);
        text.statusDot.setBackground(dot);
        text.status.setText(entry.online ? "在线" : "状态未知");
        text.status.setTextColor(statusColor);
        if (current || pending) {
            int color = current ? host.COLOR_ACCENT : host.COLOR_ACTION_INFO;
            text.stateTag.setText(current ? "当前" : "待切换");
            text.stateTag.setTextColor(color);
            text.stateTag.setBackground(host.roundedFill(
                    current ? host.COLOR_ACCENT_SOFT : host.COLOR_ACTION_INFO_SOFT));
            text.stateTag.setVisibility(View.VISIBLE);
        } else {
            text.stateTag.setVisibility(View.INVISIBLE);
        }
    }

    private void bindSpeedResult(TextView result, ManagedProxyEntries.Entry entry) {
        String value = speedResults.get(entry.id);
        if (entry.id.equals(testingId)) {
            result.setText("正在测速…");
            result.setVisibility(View.VISIBLE);
        } else if (value != null) {
            result.setText(value);
            result.setVisibility(View.VISIBLE);
        } else {
            result.setText("测速结果");
            result.setVisibility(View.INVISIBLE);
        }
    }

    private void bindActions(
            ActionColumn actions,
            ManagedProxyEntries.Entry entry,
            boolean current,
            boolean pending) {
        actions.mark.setText(current ? "✓" : pending ? "→" : "");
        if (current || pending) {
            GradientDrawable background = new GradientDrawable();
            background.setShape(GradientDrawable.OVAL);
            background.setColor(current ? host.COLOR_ACCENT : host.COLOR_ACTION_INFO);
            actions.mark.setBackground(background);
        } else {
            actions.mark.setBackground(null);
        }
        actions.speed.setText(entry.id.equals(testingId) ? "测速中" : "测速");
        actions.speed.setEnabled(testingId == null);
        actions.speed.setAlpha(testingId == null || entry.id.equals(testingId) ? 1f : 0.45f);
        actions.speed.setOnClickListener(view -> startSpeedTest(entry));
    }

    private GradientDrawable iconBackground(ManagedProxyEntries.Entry entry) {
        GradientDrawable circle = new GradientDrawable();
        circle.setShape(GradientDrawable.OVAL);
        float hue = Math.floorMod(entry.iconKey.hashCode(), 360);
        circle.setColor(Color.HSVToColor(new float[]{hue, 0.58f, 0.82f}));
        return circle;
    }

    private void startSpeedTest(ManagedProxyEntries.Entry entry) {
        if (testingId != null) {
            return;
        }
        testingId = entry.id;
        speedResults.remove(entry.id);
        notifyDataSetChanged();
        ProxyEntrySpeedTest.start(host, entry, new ProxyEntrySpeedTest.Listener() {
            @Override
            public void onSuccess(ProxyEntrySpeedTest.Result result) {
                testingId = null;
                speedResults.put(entry.id, result.summary());
                notifyDataSetChanged();
            }

            @Override
            public void onFailure(String message) {
                testingId = null;
                speedResults.put(entry.id, "测速失败 · 点击重试");
                notifyDataSetChanged();
                Toast.makeText(host, message, Toast.LENGTH_LONG).show();
            }
        });
    }

    private TextView label(String value, float size, int color) {
        TextView label = new TextView(host);
        label.setText(value);
        label.setTextSize(size);
        label.setTextColor(color);
        label.setIncludeFontPadding(false);
        return label;
    }

    private LinearLayout.LayoutParams wrapContent() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private static final class RowHolder {
        final LinearLayout row;
        final FrameLayout badge;
        final TextColumn text;
        final ActionColumn actions;

        RowHolder(
                LinearLayout row,
                FrameLayout badge,
                TextColumn text,
                ActionColumn actions) {
            this.row = row;
            this.badge = badge;
            this.text = text;
            this.actions = actions;
        }
    }

    private static final class TextColumn {
        final LinearLayout root;
        final TextView name;
        final TextView description;
        final View statusDot;
        final TextView status;
        final TextView stateTag;
        final TextView speedResult;

        TextColumn(
                LinearLayout root,
                TextView name,
                TextView description,
                View statusDot,
                TextView status,
                TextView stateTag,
                TextView speedResult) {
            this.root = root;
            this.name = name;
            this.description = description;
            this.statusDot = statusDot;
            this.status = status;
            this.stateTag = stateTag;
            this.speedResult = speedResult;
        }
    }

    private static final class ActionColumn {
        final LinearLayout root;
        final TextView mark;
        final TextView speed;

        ActionColumn(LinearLayout root, TextView mark, TextView speed) {
            this.root = root;
            this.mark = mark;
            this.speed = speed;
        }
    }
}
