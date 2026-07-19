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
abstract class MainActivityDirectRules extends MainActivityAppSelector {

protected void addDraftDirectRules() {
        if (directRuleDraft == null) {
            return;
        }
        addDirectRules(parseDirectRuleInput(directRuleDraft.getText().toString()));
        directRuleDraft.setText("");
    }

protected void addDirectRules(String[] rules) {
        List<String> values = new ArrayList<>();
        Collections.addAll(values, rules);
        addDirectRules(values);
    }

protected void addDirectRules(List<String> rules) {
        List<String> merged = new ArrayList<>(directRuleValues);
        merged.addAll(rules);
        directRuleValues.clear();
        directRuleValues.addAll(normalizeDirectRules(merged));
        renderDirectRuleList();
    }

protected void removeDirectRule(int index) {
        if (index < 0 || index >= directRuleValues.size()) {
            return;
        }
        directRuleValues.remove(index);
        renderDirectRuleList();
    }

protected void renderDirectRuleList() {
        if (directRuleGroupList == null) {
            return;
        }
        directRuleGroupList.removeAllViews();
        int groupCount = 0;
        groupCount += addDirectRuleGroup(
                "通配符",
                "wildcard",
                new String[]{"HTTP/SOCKS5", "TUN + DNS 缓存"});
        groupCount += addDirectRuleGroup(
                "IP / CIDR",
                "network",
                new String[]{"TUN", "已解析 IP"});
        groupCount += addDirectRuleGroup(
                "域名",
                "domain",
                new String[]{"HTTP/SOCKS5", "TUN + DNS 缓存"});
        groupCount += addDirectRuleGroup(
                "其他",
                "other",
                new String[]{"按规则值"});

        if (directRuleValues.isEmpty()) {
            TextView empty = mutedText("未配置", 14f);
            empty.setGravity(Gravity.CENTER);
            empty.setTypeface(Typeface.DEFAULT_BOLD);
            empty.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
            directRuleGroupList.addView(empty, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    dp(64)));
        }

        if (directRuleGroupSummary != null) {
            directRuleGroupSummary.setText(groupCount + " 组");
        }
        updateDirectAccessSummary();
    }

protected int addDirectRuleGroup(String label, String groupKey, String[] modes) {
        int count = 0;
        for (String rule : directRuleValues) {
            if (groupKey.equals(ruleGroupKey(rule))) {
                count++;
            }
        }
        if (count == 0) {
            return 0;
        }

        LinearLayout group = new LinearLayout(this);
        group.setOrientation(LinearLayout.VERTICAL);
        group.setPadding(0, 0, 0, 0);
        LinearLayout.LayoutParams groupParams = matchWrap();
        if (directRuleGroupList.getChildCount() > 0) {
            groupParams.setMargins(0, dp(8), 0, 0);
        }

        LinearLayout heading = horizontalRow();
        heading.setGravity(Gravity.CENTER_VERTICAL);
        heading.setPadding(dp(4), 0, dp(4), 0);
        TextView title = titleText(label, 12f);
        heading.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView countView = mutedText(String.valueOf(count), 11f);
        countView.setTypeface(Typeface.DEFAULT_BOLD);
        heading.addView(countView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams headingParams = matchWrap();
        group.addView(heading, headingParams);

        LinearLayout modeRow = new LinearLayout(this);
        modeRow.setOrientation(LinearLayout.HORIZONTAL);
        modeRow.setGravity(Gravity.START);
        // 规则组标题区域宽度有限，模式标签单独占一行，避免 Wildcard 这类长标签被截断。
        addModeChips(modeRow, modes);
        LinearLayout.LayoutParams modeParams = matchWrap();
        modeParams.setMargins(dp(4), dp(4), 0, dp(2));
        group.addView(modeRow, modeParams);

        for (int i = 0; i < directRuleValues.size(); i++) {
            String rule = directRuleValues.get(i);
            if (!groupKey.equals(ruleGroupKey(rule))) {
                continue;
            }
            addDirectRuleChip(group, rule, i);
        }

        directRuleGroupList.addView(group, groupParams);
        return 1;
    }

protected void addModeChips(LinearLayout root, String[] modes) {
        for (String mode : modes) {
            TextView modeView = chip(mode, COLOR_STATUS_STOPPED);
            modeView.setTextSize(10f);
            // mode 标签通常放在横向 LinearLayout 里，不能复用 matchWrap()。
            // matchWrap() 的宽度是 MATCH_PARENT，会把每个标签撑满整行，导致规则组标题区被挤高。
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            if (root.getChildCount() > 0) {
                params.setMargins(dp(5), 0, 0, 0);
            }
            root.addView(modeView, params);
        }
    }

protected void addDirectRuleChip(LinearLayout root, String rule, int index) {
        LinearLayout row = horizontalRow();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(8), dp(4), dp(5), dp(4));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        TextView text = titleText(rule, 11.5f);
        text.setSingleLine(true);
        text.setEllipsize(TextUtils.TruncateAt.END);
        row.addView(text, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        ImageButton remove = new ImageButton(this);
        remove.setImageResource(R.drawable.ic_close_24);
        remove.setImageTintList(interactiveTextColors(
                COLOR_ACTION_STOP,
                Color.rgb(255, 240, 246)));
        remove.setContentDescription("删除规则");
        remove.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        remove.setMinimumHeight(0);
        remove.setMinimumWidth(0);
        remove.setPadding(dp(4), dp(4), dp(4), dp(4));
        remove.setBackground(interactiveRounded(
                COLOR_SURFACE,
                alphaColor(COLOR_ACTION_STOP, 92),
                COLOR_ACTION_STOP));
        flattenButton(remove);
        remove.setOnClickListener(view -> removeDirectRule(index));
        trackEditable(remove);
        LinearLayout.LayoutParams removeParams = new LinearLayout.LayoutParams(dp(28), dp(28));
        removeParams.setMargins(dp(6), 0, 0, 0);
        row.addView(remove, removeParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        rowParams.setMargins(0, dp(5), 0, 0);
        root.addView(row, rowParams);
    }

protected void updateDirectModeButtons() {
        String selectedMode = normalizeDirectAccessMode(directAccessModeValue);
        directAccessModeValue = selectedMode;
        for (Button button : directModeButtons) {
            boolean selected = selectedMode.equals(String.valueOf(button.getTag()));
            button.setSelected(selected);
            button.setTextColor(interactiveTextColors(
                    selected ? COLOR_ACCENT_DARK : COLOR_MUTED,
                    COLOR_ACCENT_DARK));
            int fill = selected ? COLOR_ACCENT_SOFT : COLOR_CONTROL;
            int stroke = selected ? alphaColor(COLOR_ACCENT, 138) : COLOR_CONTROL;
            button.setBackground(interactiveRounded(fill, stroke, COLOR_ACCENT));
        }
        updateDirectAccessSummary();
        updateDirectRuleConfigVisibility();
    }

protected void updateDirectAccessSummary() {
        if (directModeSummary != null) {
            directModeSummary.setText(directModeLabel(directAccessModeValue));
        }
        if (directRuleCountSummary != null) {
            directRuleCountSummary.setText(directRuleCountLabel());
        }
    }

protected void updateDirectRuleConfigVisibility() {
        int visibility = "rules".equals(normalizeDirectAccessMode(directAccessModeValue))
                ? View.VISIBLE
                : View.GONE;
        if (directRulesConfig != null) {
            directRulesConfig.setVisibility(visibility);
        }
        if (directRuleCountFact != null) {
            directRuleCountFact.setVisibility(visibility);
        }
    }

protected String directRuleCountLabel() {
        int count = directRuleValues.size();
        return count + " 条";
    }

protected List<String> parseDirectRuleInput(String value) {
        List<String> rules = new ArrayList<>();
        if (value == null || value.trim().isEmpty()) {
            return rules;
        }
        String[] tokens = value.split("[\\s,;\\uFF0C\\uFF1B]+");
        for (String token : tokens) {
            rules.add(token);
        }
        return rules;
    }

protected List<String> normalizeDirectRules(List<String> rules) {
        List<String> normalized = new ArrayList<>();
        HashSet<String> seen = new HashSet<>();
        for (String rule : rules) {
            if (rule == null) {
                continue;
            }
            String value = rule.trim();
            if (value.isEmpty()) {
                continue;
            }
            String key = value.toLowerCase(Locale.US);
            if (seen.contains(key)) {
                continue;
            }
            seen.add(key);
            normalized.add(value);
        }
        return normalized;
    }

protected String serializeDirectAccessRules() {
        return TextUtils.join("\n", directRuleValues);
    }

protected String normalizeDirectAccessMode(String value) {
        if (value == null) {
            return DefaultConfig.DIRECT_ACCESS_MODE;
        }
        String normalized = value.trim().toLowerCase(Locale.US);
        if ("proxy_all".equals(normalized)
                || "direct_all".equals(normalized)
                || "rules".equals(normalized)) {
            return normalized;
        }
        return DefaultConfig.DIRECT_ACCESS_MODE;
    }

protected String directModeLabel(String mode) {
        String normalized = normalizeDirectAccessMode(mode);
        if ("direct_all".equals(normalized)) {
            return "全量直连";
        }
        if ("rules".equals(normalized)) {
            return "按规则";
        }
        return "全走代理";
    }

protected String ruleGroupKey(String rule) {
        String normalized = rule == null ? "" : rule.trim().toLowerCase(Locale.US);
        if (normalized.contains("*")) {
            return "wildcard";
        }
        if (isNetworkRule(normalized)) {
            return "network";
        }
        if (normalized.matches("^[a-z0-9._-]+(\\.[a-z0-9._-]+)*$")) {
            return "domain";
        }
        return "other";
    }

protected boolean isNetworkRule(String rule) {
        return rule.matches("^(\\d{1,3}\\.){3}\\d{1,3}(/\\d{1,2})?$")
                || rule.matches("^([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}(/\\d{1,3})?$");
    }

}
