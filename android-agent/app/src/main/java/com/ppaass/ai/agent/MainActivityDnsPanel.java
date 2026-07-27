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

        int scrollY = mainScrollView == null ? 0 : mainScrollView.getScrollY();
        boolean running = isVpnRunning();
        JSONArray records;
        String recordsJson;
        try {
            recordsJson = NativeAgent.dnsResolutionRecordsJson();
            String stateKey = dnsRecordsStateKey(
                    running,
                    dnsFilterQuery(),
                    directRuleValues,
                    recordsJson);
            if (stateKey.equals(lastDnsRecordsStateKey)) {
                return;
            }
            lastDnsRecordsStateKey = stateKey;
            records = new JSONArray(recordsJson);
        } catch (JSONException | RuntimeException e) {
            hideDnsSelectionToolbar();
            updateDnsFilterSummary(0, 0);
            dnsRecordList.removeAllViews();
            addDnsEmptyRow("DNS 记录不可用");
            stabilizeMainScroll(scrollY);
            return;
        }

        dnsRecordList.removeAllViews();
        if (records.length() == 0) {
            hideDnsSelectionToolbar();
            updateDnsFilterSummary(0, 0);
            addDnsEmptyRow(running ? "等待代理 DNS 请求" : "VPN 已停止");
            stabilizeMainScroll(scrollY);
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
            updateDnsFilterSummary(0, 0);
            addDnsEmptyRow(running ? "等待代理 DNS 请求" : "VPN 已停止");
            stabilizeMainScroll(scrollY);
            return;
        }

        pruneDnsSelection(agentRecords);
        List<JSONObject> filteredRecords = filterDnsRecords(agentRecords);
        updateDnsFilterSummary(filteredRecords.size(), agentRecords.size());
        addDnsSelectionToolbar(agentRecords, filteredRecords);
        if (filteredRecords.isEmpty()) {
            addDnsEmptyRow("没有符合过滤条件的 DNS 记录");
            stabilizeMainScroll(scrollY);
            return;
        }
        for (JSONObject record : filteredRecords) {
            addDnsRecordRow(record);
        }
        stabilizeMainScroll(scrollY);
    }

static String dnsRecordsStateKey(
        boolean running,
        String filter,
        Collection<String> directRules,
        String recordsJson) {
        StringBuilder key = new StringBuilder(running ? "1" : "0");
        appendDnsStatePart(key, filter);
        if (directRules == null) {
            key.append("|-1");
        } else {
            key.append('|').append(directRules.size());
            for (String rule : directRules) {
                appendDnsStatePart(key, rule);
            }
        }
        appendDnsStatePart(key, recordsJson);
        return key.toString();
    }

private static void appendDnsStatePart(StringBuilder key, String value) {
        String safeValue = value == null ? "" : value;
        key.append('|').append(safeValue.length()).append(':').append(safeValue);
    }

protected void stabilizeMainScroll(int scrollY) {
        if (mainScrollView == null || !mainScrollView.isLaidOut()) {
            return;
        }
        ViewTreeObserver observer = mainScrollView.getViewTreeObserver();
        observer.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() {
            @Override
            public boolean onPreDraw() {
                if (observer.isAlive()) {
                    observer.removeOnPreDrawListener(this);
                }
                mainScrollView.scrollTo(0, scrollY);
                return true;
            }
        });
    }

protected boolean isAgentDnsRecord(JSONObject record) {
        String resolver = record.optString("resolver", "");
        return resolver.isEmpty()
                || "agent".equals(resolver)
                || "agent-cache".equals(resolver)
                || "agent-direct".equals(resolver)
                || "system".equals(resolver);
    }

protected void addDnsEmptyRow(String text) {
        TextView empty = mutedText(text, 14f);
        empty.setGravity(Gravity.CENTER);
        empty.setTypeface(Typeface.DEFAULT_BOLD);
        empty.setBackgroundColor(COLOR_SURFACE);
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
        row.setPadding(dp(4), dp(5), dp(4), dp(5));
        row.setMinimumHeight(dp(46));
        row.setBackgroundColor(selected ? COLOR_ACCENT_SOFT : COLOR_SURFACE);
        row.setEnabled(true);
        row.setClickable(true);
        row.setFocusable(false);
        row.setContentDescription(tr(direct
                ? domain + "，已在直连规则中，点击选择后可移出"
                : domain + (selected ? "，已选择" : "，未选择")));
        row.setOnClickListener(view -> toggleDnsDomainSelection(domain));

        TextView selector = new TextView(this);
        selector.setText(selected ? "✓" : "");
        selector.setTextSize(11f);
        selector.setTypeface(Typeface.DEFAULT_BOLD);
        selector.setGravity(Gravity.CENTER);
        selector.setTextColor(COLOR_ACCENT_DARK);
        selector.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        selector.setBackground(rounded(
                selected ? COLOR_ACCENT_SOFT : COLOR_CONTROL,
                selected ? COLOR_ACCENT : (direct ? COLOR_ACTION_INFO : COLOR_BORDER)));
        LinearLayout.LayoutParams selectorParams = new LinearLayout.LayoutParams(dp(18), dp(18));
        selectorParams.setMargins(0, 0, dp(6), 0);
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

        String rawStatus = record.optString("status", "UNKNOWN");
        String statusLabel;
        if ("NOERROR".equals(rawStatus)) {
            statusLabel = "成功";
        } else if ("NXDOMAIN".equals(rawStatus)) {
            statusLabel = "不存在";
        } else if ("TIMEOUT".equals(rawStatus)) {
            statusLabel = "超时";
        } else {
            statusLabel = rawStatus;
        }
        String statusText = statusLabel + " · "
                + Math.max(1, record.optLong("duration_ms", 0)) + " ms";
        TextView status = mutedText(statusText, 10f);
        status.setTextColor("NOERROR".equals(rawStatus)
                ? COLOR_STATUS_RUNNING
                : COLOR_ACTION_STOP);
        status.setTypeface(Typeface.DEFAULT_BOLD);
        status.setSingleLine(true);
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        statusParams.gravity = Gravity.END;
        statusParams.setMargins(0, dp(2), 0, 0);
        meta.addView(status, statusParams);
        LinearLayout.LayoutParams metaParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        metaParams.setMargins(dp(4), 0, 0, 0);
        row.addView(meta, metaParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        if (dnsRecordList.getChildCount() > 0) {
            rowParams.setMargins(0, dp(1), 0, 0);
        }
        dnsRecordList.addView(row, rowParams);
    }

protected void addDnsSelectionToolbar(
        List<JSONObject> records,
        List<JSONObject> filteredRecords) {
        if (dnsSelectionToolbar == null) {
            return;
        }
        List<String> selectable = selectableDnsDomains(filteredRecords);
        boolean allSelected = !selectable.isEmpty();
        for (String domain : selectable) {
            if (!selectedDnsDomains.containsKey(domain.toLowerCase(Locale.US))) {
                allSelected = false;
                break;
            }
        }

        dnsSelectionToolbar.removeAllViews();
        dnsSelectionToolbar.setVisibility(View.VISIBLE);

        List<String> rulesToAdd = selectedDnsRulesToAdd(records);
        List<String> rulesToRemove = selectedDnsRulesToRemove(records);
        TextView summary = mutedText(
                "已选 " + selectedDnsDomains.size()
                        + " · 待添加 " + rulesToAdd.size() + " 条"
                        + " · 待移出 " + rulesToRemove.size() + " 条",
                10.5f);
        summary.setSingleLine(true);
        summary.setEllipsize(TextUtils.TruncateAt.END);
        dnsSelectionToolbar.addView(summary, matchWrap());

        LinearLayout actions = horizontalRow();
        String filter = dnsFilterQuery();
        String selectAllLabel;
        if (filter.isEmpty()) {
            selectAllLabel = allSelected ? "清空" : "全选";
        } else {
            selectAllLabel = allSelected ? "取消结果" : "全选结果";
        }
        Button selectAll = secondaryButton(selectAllLabel);
        selectAll.setTextSize(11f);
        selectAll.setMinHeight(0);
        selectAll.setMinWidth(0);
        selectAll.setPadding(dp(8), 0, dp(8), 0);
        selectAll.setEnabled(!selectable.isEmpty());
        boolean finalAllSelected = allSelected;
        selectAll.setOnClickListener(view -> {
            if (finalAllSelected) {
                HashSet<String> visibleKeys = new HashSet<>();
                for (String domain : selectable) {
                    visibleKeys.add(domain.toLowerCase(Locale.US));
                }
                selectedDnsDomains.keySet().removeAll(visibleKeys);
            } else {
                for (String domain : selectable) {
                    selectedDnsDomains.put(domain.toLowerCase(Locale.US), domain);
                }
            }
            refreshDnsSelectionUi();
        });
        actions.addView(selectAll, new LinearLayout.LayoutParams(0, dp(36), 1f));

        Button add = actionButton(
                isVpnRunning() || isHttpProxyRunning()
                        ? "添加并重启"
                        : "添加",
                COLOR_ACTION_START);
        add.setTextSize(11f);
        add.setMinHeight(0);
        add.setMinWidth(0);
        add.setPadding(dp(8), 0, dp(8), 0);
        add.setEnabled(!rulesToAdd.isEmpty());
        add.setOnClickListener(view -> addSelectedDnsRules(records));
        LinearLayout.LayoutParams addParams = new LinearLayout.LayoutParams(0, dp(36), 1f);
        addParams.setMargins(dp(6), 0, 0, 0);
        actions.addView(add, addParams);

        Button remove = actionButton(
                isVpnRunning() || isHttpProxyRunning()
                        ? "移出并重启"
                        : "移出",
                COLOR_ACTION_STOP);
        remove.setTextSize(11f);
        remove.setMinHeight(0);
        remove.setMinWidth(0);
        remove.setPadding(dp(8), 0, dp(8), 0);
        remove.setEnabled(!rulesToRemove.isEmpty());
        remove.setOnClickListener(view -> removeSelectedDnsRules(records));
        LinearLayout.LayoutParams removeParams = new LinearLayout.LayoutParams(
                0,
                dp(36),
                1f);
        removeParams.setMargins(dp(6), 0, 0, 0);
        actions.addView(remove, removeParams);

        LinearLayout.LayoutParams actionsParams = matchWrap();
        actionsParams.setMargins(0, dp(5), 0, 0);
        dnsSelectionToolbar.addView(actions, actionsParams);
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
        if (selectedDnsDomains.containsKey(key)) {
            selectedDnsDomains.remove(key);
        } else {
            selectedDnsDomains.put(key, domain);
        }
        refreshDnsSelectionUi();
    }

protected void addSelectedDnsRules(List<JSONObject> records) {
        List<String> rules = selectedDnsRulesToAdd(records);
        if (rules.isEmpty()) {
            return;
        }
        boolean restartVpn = isVpnActiveForRuleReload();
        boolean restartHttpProxy = isHttpProxyActiveForRuleReload();
        addDirectRules(rules);
        saveConfig();
        selectedDnsDomains.clear();
        refreshDnsSelectionUi();
        restartRunningAgentsAfterRuleUpdate(restartVpn, restartHttpProxy);
    }

protected void removeSelectedDnsRules(List<JSONObject> records) {
        List<String> rules = selectedDnsRulesToRemove(records);
        if (rules.isEmpty()) {
            return;
        }
        boolean restartVpn = isVpnActiveForRuleReload();
        boolean restartHttpProxy = isHttpProxyActiveForRuleReload();
        removeDirectRules(rules);
        saveConfig();
        selectedDnsDomains.clear();
        refreshDnsSelectionUi();
        restartRunningAgentsAfterRuleUpdate(
                restartVpn,
                restartHttpProxy,
                "直连规则已移出",
                "直连规则已移出，正在重启");
    }

protected List<String> selectedDnsRulesToAdd(List<JSONObject> records) {
        LinkedHashMap<String, String> domains = new LinkedHashMap<>();
        List<String> addresses = new ArrayList<>();
        for (JSONObject record : records) {
            String domain = dnsRecordDomain(record);
            String domainKey = domain.toLowerCase(Locale.US);
            if (!selectedDnsDomains.containsKey(domainKey)) {
                continue;
            }
            if (dnsDomainIsDirect(domain)) {
                continue;
            }
            domains.put(domainKey, domain);
            addresses.addAll(dnsRecordAnswers(record));
        }
        HashSet<String> existingRuleKeys = new HashSet<>();
        for (String rule : directRuleValues) {
            existingRuleKeys.add(rule.trim().toLowerCase(Locale.US));
        }
        List<String> rules = DirectRuleDomains.toDirectRules(domains.values(), addresses);
        rules.removeIf(rule ->
                existingRuleKeys.contains(rule.trim().toLowerCase(Locale.US)));
        return rules;
    }

protected List<String> selectedDnsRulesToRemove(List<JSONObject> records) {
        List<String> addresses = new ArrayList<>();
        for (JSONObject record : records) {
            String domainKey = dnsRecordDomain(record).toLowerCase(Locale.US);
            if (selectedDnsDomains.containsKey(domainKey)) {
                addresses.addAll(dnsRecordAnswers(record));
            }
        }
        return DirectRuleDomains.directRulesMatchingDomainsAndAddresses(
                directRuleValues,
                selectedDnsDomains.values(),
                addresses);
    }

protected void refreshDnsSelectionUi() {
        lastDnsRecordsStateKey = "";
        updateDnsRecords();
    }

protected void pruneDnsSelection(List<JSONObject> records) {
        HashSet<String> available = new HashSet<>();
        for (JSONObject record : records) {
            String domain = dnsRecordDomain(record);
            if (!domain.isEmpty()) {
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
            if (!domain.isEmpty() && !domains.containsKey(key)) {
                domains.put(key, domain);
            }
        }
        return new ArrayList<>(domains.values());
    }

protected List<JSONObject> filterDnsRecords(List<JSONObject> records) {
        String filter = dnsFilterQuery();
        if (filter.isEmpty()) {
            return new ArrayList<>(records);
        }
        List<JSONObject> filtered = new ArrayList<>();
        for (JSONObject record : records) {
            String domain = dnsRecordDomain(record);
            if (DnsRecordFilter.matches(
                    filter,
                    domain,
                    dnsRecordAnswers(record),
                    record.optString("client", ""),
                    record.optString("upstream", ""),
                    record.optString("resolver", ""),
                    record.optString("record_type", ""),
                    record.optString("status", ""),
                    record.optLong("duration_ms", 0),
                    dnsDomainIsDirect(domain))) {
                filtered.add(record);
            }
        }
        return filtered;
    }

protected String dnsFilterQuery() {
        if (dnsFilterInput == null || dnsFilterInput.getText() == null) {
            return "";
        }
        return dnsFilterInput.getText().toString().trim();
    }

protected void updateDnsFilterSummary(int filteredCount, int totalCount) {
        if (dnsFilterSummary != null) {
            dnsFilterSummary.setText(tr(
                    "显示 " + filteredCount + " / " + totalCount + " 条"));
        }
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
        List<String> answers = dnsRecordAnswers(record);
        if (!answers.isEmpty()) {
            return TextUtils.join(", ", answers.subList(0, Math.min(3, answers.size())));
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

protected List<String> dnsRecordAnswers(JSONObject record) {
        List<String> answers = new ArrayList<>();
        JSONArray rawAnswers = record.optJSONArray("answers");
        if (rawAnswers == null) {
            return answers;
        }
        for (int index = 0; index < rawAnswers.length(); index++) {
            String answer = rawAnswers.optString(index, "").trim();
            if (!answer.isEmpty()) {
                answers.add(answer);
            }
        }
        return answers;
    }

protected TextView dnsCacheChip(JSONObject record) {
        String resolver = record.optString("resolver", "agent");
        if ("agent-cache".equals(resolver)) {
            return chip("缓存命中", COLOR_STATUS_RUNNING);
        }
        if ("system".equals(resolver)) {
            return chip("系统 DNS", COLOR_ACTION_STOP);
        }
        if ("agent-direct".equals(resolver)) {
            return chip("直连解析", COLOR_ACTION_INFO);
        }
        return null;
    }

}
