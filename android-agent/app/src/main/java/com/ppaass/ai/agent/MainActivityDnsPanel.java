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
            dnsRecordList.removeAllViews();
            addDnsEmptyRow("DNS 记录不可用");
            return;
        }

        dnsRecordList.removeAllViews();
        if (records.length() == 0) {
            addDnsEmptyRow(running ? "等待代理 DNS 请求" : "VPN 已停止");
            return;
        }

        boolean hasAgentRecords = false;
        for (int index = records.length() - 1; index >= 0; index--) {
            JSONObject record = records.optJSONObject(index);
            if (record != null && isAgentDnsRecord(record)) {
                addDnsRecordRow(record);
                hasAgentRecords = true;
            }
        }
        if (!hasAgentRecords) {
            addDnsEmptyRow(running ? "等待代理 DNS 请求" : "VPN 已停止");
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
        LinearLayout row = horizontalRow();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(10), dp(9), dp(10), dp(9));
        row.setMinimumHeight(dp(58));
        row.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));

        LinearLayout textColumn = new LinearLayout(this);
        textColumn.setOrientation(LinearLayout.VERTICAL);
        TextView query = titleText(record.optString("query", "<unknown>"), 14f);
        query.setSingleLine(true);
        query.setEllipsize(TextUtils.TruncateAt.END);
        textColumn.addView(query, matchWrap());

        TextView answer = mutedText(dnsAnswerLabel(record), 12f);
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
        TextView type = chip(record.optString("record_type", "DNS"), COLOR_ACCENT);
        LinearLayout.LayoutParams typeParams = matchWrap();
        typeParams.gravity = Gravity.END;
        meta.addView(type, typeParams);

        TextView cache = dnsCacheChip(record);
        if (cache != null) {
            LinearLayout.LayoutParams cacheParams = matchWrap();
            cacheParams.gravity = Gravity.END;
            cacheParams.setMargins(0, dp(4), 0, 0);
            meta.addView(cache, cacheParams);
        }

        String statusText = record.optString("status", "UNKNOWN") + " · "
                + Math.max(1, record.optLong("duration_ms", 0)) + " ms";
        TextView status = mutedText(statusText, 11f);
        status.setTextColor("NOERROR".equals(record.optString("status", ""))
                ? COLOR_STATUS_RUNNING
                : COLOR_ACTION_STOP);
        status.setTypeface(Typeface.DEFAULT_BOLD);
        status.setSingleLine(true);
        LinearLayout.LayoutParams statusParams = matchWrap();
        statusParams.setMargins(0, dp(4), 0, 0);
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
