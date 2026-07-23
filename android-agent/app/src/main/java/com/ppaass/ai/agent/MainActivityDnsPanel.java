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
abstract class MainActivityDnsPanel extends MainActivityConnectivity {

protected void updateDnsRecords() {
        if (dnsRecordList == null) {
            return;
        }

        boolean running = isVpnRunning();
        JSONArray records;
        String recordsJson;
        try {
            recordsJson = NativeAgent.dnsResolutionRecordsJson();
            String stateKey = running + ":" + recordsJson;
            if (stateKey.equals(lastDnsRecordsStateKey)) {
                return;
            }
            lastDnsRecordsStateKey = stateKey;
            records = new JSONArray(recordsJson);
        } catch (JSONException | RuntimeException e) {
            hideDnsSelectionToolbar();
            dnsRecordList.removeAllViews();
            addDnsEmptyRow("DNS 记录不可用");
            return;
        }

        dnsRecordList.removeAllViews();
        if (records.length() == 0) {
            hideDnsSelectionToolbar();
            addDnsEmptyRow(running ? "等待代理 DNS 请求" : "VPN 已停止");
            return;
        }

        List<JSONObject> agentRecords = new ArrayList<>();
        for (int index = records.length() - 1; index >= 0; index--) {
            JSONObject record = records.optJSONObject(index);
            if (record != null && isAgentDnsRecord(record)) {
                agentRecords.add(record);
            }
        }
        if (agentRecords.isEmpty()) {
            hideDnsSelectionToolbar();
            addDnsEmptyRow(running ? "等待代理 DNS 请求" : "VPN 已停止");
            return;
        }

        pruneDnsSelection(agentRecords);
        addDnsSelectionToolbar(agentRecords);
        for (JSONObject record : agentRecords) {
            addDnsRecordRow(record);
        }
    }

protected boolean isAgentDnsRecord(JSONObject record) {
        return "agent".equals(record.optString("resolver", ""));
    }

protected void addDnsEmptyRow(String text) {
        TextView empty = mutedText(text, 14f);
        empty.setGravity(Gravity.CENTER);
        empty.setTypeface(Typeface.DEFAULT_BOLD);
        empty.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
        dnsRecordList.addView(empty, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(72)));
    }

protected void addDnsRecordRow(JSONObject record) {
        String domain = dnsRecordDomain(record);
        boolean direct = dnsDomainIsDirect(domain);
        boolean selected = selectedDnsDomains.containsKey(domain.toLowerCase(Locale.US));

        LinearLayout row = horizontalRow();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(9), dp(6), dp(9), dp(6));
        row.setMinimumHeight(dp(50));
        row.setBackground(rounded(
                selected ? COLOR_ACCENT_SOFT : COLOR_SURFACE,
                selected ? COLOR_ACCENT : COLOR_BORDER));
        row.setEnabled(!direct);
        row.setClickable(!direct);
        row.setFocusable(!direct);
        row.setContentDescription(direct
                ? domain + "，已在直连规则中"
                : domain + (selected ? "，已选择" : "，未选择"));
        row.setOnClickListener(view -> toggleDnsDomainSelection(domain));

        TextView selector = new TextView(this);
        selector.setText(selected || direct ? "✓" : "");
        selector.setTextSize(14f);
        selector.setTypeface(Typeface.DEFAULT_BOLD);
        selector.setGravity(Gravity.CENTER);
        selector.setTextColor(direct ? COLOR_MUTED : COLOR_ACCENT_DARK);
        selector.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        selector.setBackground(rounded(
                selected || direct ? COLOR_ACCENT_SOFT : COLOR_CONTROL,
                selected ? COLOR_ACCENT : COLOR_BORDER));
        LinearLayout.LayoutParams selectorParams = new LinearLayout.LayoutParams(dp(23), dp(23));
        selectorParams.setMargins(0, 0, dp(8), 0);
        row.addView(selector, selectorParams);

        LinearLayout textColumn = new LinearLayout(this);
        textColumn.setOrientation(LinearLayout.VERTICAL);
        TextView query = titleText(record.optString("query", "<unknown>"), 13f);
        query.setSingleLine(true);
        query.setEllipsize(TextUtils.TruncateAt.END);
        textColumn.addView(query, matchWrap());

        TextView answer = mutedText(dnsAnswerLabel(record), 11f);
        answer.setSingleLine(true);
        answer.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams answerParams = matchWrap();
        answerParams.setMargins(0, dp(3), 0, 0);
        textColumn.addView(answer, answerParams);
        row.addView(textColumn, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        LinearLayout meta = new LinearLayout(this);
        meta.setOrientation(LinearLayout.VERTICAL);
        meta.setGravity(Gravity.END);
        LinearLayout metaChips = horizontalRow();
        metaChips.setGravity(Gravity.END);
        if (direct) {
            TextView directChip = chip("已直连", COLOR_ACTION_INFO);
            directChip.setTextSize(9f);
            metaChips.addView(directChip, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT));
        }
        TextView type = chip(record.optString("record_type", "DNS"), COLOR_ACCENT);
        type.setTextSize(9f);
        LinearLayout.LayoutParams typeParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        if (metaChips.getChildCount() > 0) {
            typeParams.setMargins(dp(4), 0, 0, 0);
        }
        metaChips.addView(type, typeParams);

        TextView cache = dnsCacheChip(record);
        if (cache != null) {
            cache.setTextSize(9f);
            LinearLayout.LayoutParams cacheParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            cacheParams.setMargins(dp(4), 0, 0, 0);
            metaChips.addView(cache, cacheParams);
        }
        LinearLayout.LayoutParams metaChipsParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        metaChipsParams.gravity = Gravity.END;
        meta.addView(metaChips, metaChipsParams);

        String statusText = record.optString("status", "UNKNOWN") + " · "
                + Math.max(1, record.optLong("duration_ms", 0)) + " ms";
        TextView status = mutedText(statusText, 10f);
        status.setTextColor("NOERROR".equals(record.optString("status", ""))
                ? COLOR_STATUS_RUNNING
                : COLOR_ACTION_STOP);
        status.setTypeface(Typeface.DEFAULT_BOLD);
        status.setSingleLine(true);
        LinearLayout.LayoutParams statusParams = matchWrap();
        statusParams.setMargins(0, dp(2), 0, 0);
        meta.addView(status, statusParams);
        LinearLayout.LayoutParams metaParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        metaParams.setMargins(dp(10), 0, 0, 0);
        row.addView(meta, metaParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        if (dnsRecordList.getChildCount() > 0) {
            rowParams.setMargins(0, dp(8), 0, 0);
        }
        dnsRecordList.addView(row, rowParams);
    }

protected void addDnsSelectionToolbar(List<JSONObject> records) {
        if (dnsSelectionToolbar == null) {
            return;
        }
        List<String> selectable = selectableDnsDomains(records);
        boolean allSelected = !selectable.isEmpty();
        for (String domain : selectable) {
            if (!selectedDnsDomains.containsKey(domain.toLowerCase(Locale.US))) {
                allSelected = false;
                break;
            }
        }

        dnsSelectionToolbar.removeAllViews();
        dnsSelectionToolbar.setVisibility(View.VISIBLE);

        List<String> rules = DirectRuleDomains.toDirectRules(selectedDnsDomains.values());
        TextView summary = mutedText(
                "已选 " + selectedDnsDomains.size() + " · 生成 " + rules.size() + " 条",
                10.5f);
        summary.setSingleLine(true);
        summary.setEllipsize(TextUtils.TruncateAt.END);
        dnsSelectionToolbar.addView(summary, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        Button selectAll = secondaryButton(allSelected ? "清空" : "全选");
        selectAll.setTextSize(11f);
        selectAll.setMinHeight(0);
        selectAll.setMinWidth(0);
        selectAll.setPadding(dp(8), 0, dp(8), 0);
        selectAll.setEnabled(!selectable.isEmpty());
        boolean finalAllSelected = allSelected;
        selectAll.setOnClickListener(view -> {
            selectedDnsDomains.clear();
            if (!finalAllSelected) {
                for (String domain : selectable) {
                    selectedDnsDomains.put(domain.toLowerCase(Locale.US), domain);
                }
            }
            refreshDnsSelectionUi();
        });
        dnsSelectionToolbar.addView(selectAll, new LinearLayout.LayoutParams(dp(64), dp(34)));

        Button add = actionButton(
                isVpnRunning() || isHttpProxyRunning()
                        ? "添加并重启"
                        : "添加",
                COLOR_ACTION_START);
        add.setTextSize(11f);
        add.setMinHeight(0);
        add.setMinWidth(0);
        add.setPadding(dp(8), 0, dp(8), 0);
        add.setEnabled(!rules.isEmpty());
        add.setOnClickListener(view -> addSelectedDnsRules());
        LinearLayout.LayoutParams addParams = new LinearLayout.LayoutParams(
                isVpnRunning() || isHttpProxyRunning() ? dp(94) : dp(64),
                dp(34));
        addParams.setMargins(dp(6), 0, 0, 0);
        dnsSelectionToolbar.addView(add, addParams);
    }

protected void hideDnsSelectionToolbar() {
        if (dnsSelectionToolbar == null) {
            return;
        }
        dnsSelectionToolbar.removeAllViews();
        dnsSelectionToolbar.setVisibility(View.GONE);
    }

protected void toggleDnsDomainSelection(String domain) {
        String key = domain.toLowerCase(Locale.US);
        if (dnsDomainIsDirect(domain)) {
            return;
        }
        if (selectedDnsDomains.containsKey(key)) {
            selectedDnsDomains.remove(key);
        } else {
            selectedDnsDomains.put(key, domain);
        }
        refreshDnsSelectionUi();
    }

protected void addSelectedDnsRules() {
        List<String> rules = DirectRuleDomains.toDirectRules(selectedDnsDomains.values());
        if (rules.isEmpty()) {
            return;
        }
        boolean restartVpn = isVpnRunning();
        boolean restartHttpProxy = isHttpProxyRunning();
        addDirectRules(rules);
        saveConfig();
        selectedDnsDomains.clear();
        refreshDnsSelectionUi();
        restartRunningAgentsAfterRuleUpdate(restartVpn, restartHttpProxy);
    }

protected void refreshDnsSelectionUi() {
        lastDnsRecordsStateKey = "";
        updateDnsRecords();
    }

protected void pruneDnsSelection(List<JSONObject> records) {
        HashSet<String> available = new HashSet<>();
        for (JSONObject record : records) {
            String domain = dnsRecordDomain(record);
            if (!dnsDomainIsDirect(domain)) {
                available.add(domain.toLowerCase(Locale.US));
            }
        }
        selectedDnsDomains.keySet().retainAll(available);
    }

protected List<String> selectableDnsDomains(List<JSONObject> records) {
        LinkedHashMap<String, String> domains = new LinkedHashMap<>();
        for (JSONObject record : records) {
            String domain = dnsRecordDomain(record);
            String key = domain.toLowerCase(Locale.US);
            if (!domain.isEmpty() && !dnsDomainIsDirect(domain) && !domains.containsKey(key)) {
                domains.put(key, domain);
            }
        }
        return new ArrayList<>(domains.values());
    }

protected boolean dnsDomainIsDirect(String domain) {
        for (String rule : directRuleValues) {
            if (DirectRuleDomains.ruleCoversDomain(rule, domain)) {
                return true;
            }
        }
        return false;
    }

protected String dnsRecordDomain(JSONObject record) {
        String domain = record.optString("query", "").trim();
        while (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        return domain;
    }

protected String dnsAnswerLabel(JSONObject record) {
        JSONArray answers = record.optJSONArray("answers");
        if (answers != null && answers.length() > 0) {
            List<String> values = new ArrayList<>();
            for (int i = 0; i < Math.min(3, answers.length()); i++) {
                values.add(answers.optString(i));
            }
            return TextUtils.join(", ", values);
        }
        String status = record.optString("status", "");
        if ("NOERROR".equals(status)) {
            return "无响应记录";
        }
        if ("TIMEOUT".equals(status)) {
            return "查询超时";
        }
        return record.optString("upstream", "代理 DNS");
    }

protected TextView dnsCacheChip(JSONObject record) {
        String resolver = record.optString("resolver", "agent");
        if ("agent-cache".equals(resolver)) {
            return chip("缓存命中", COLOR_STATUS_RUNNING);
        }
        if ("system".equals(resolver)) {
            return chip("系统 DNS", COLOR_ACTION_STOP);
        }
        if ("agent".equals(resolver) || "agent-direct".equals(resolver) || resolver.isEmpty()) {
            return chip("缓存未命中", COLOR_STATUS_STOPPED);
        }
        return null;
    }

}
