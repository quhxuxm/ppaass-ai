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
abstract class MainActivityConfig extends MainActivityDirectAccessUi {

protected int httpProxyListenPort() {
        String value;
        if (httpProxyPort != null) {
            value = httpProxyPort.getText().toString();
        } else {
            value = prefs.getString(
                    "http_proxy_port",
                    String.valueOf(DefaultConfig.HTTP_PROXY_PORT));
        }

        try {
            int parsed = Integer.parseInt(value == null ? "" : value.trim());
            if (parsed >= 1 && parsed <= 65535) {
                return parsed;
            }
        } catch (NumberFormatException ignored) {
        }
        return DefaultConfig.HTTP_PROXY_PORT;
    }

protected void updateConfigEditability(boolean editable) {
        for (View control : editableControls) {
            if (control instanceof EditText) {
                updateEditTextEditable((EditText) control, editable);
            } else {
                control.setEnabled(editable);
            }
        }
    }

protected void updateEditTextEditable(EditText editText, boolean editable) {
        if (editText == null) {
            return;
        }
        editText.setEnabled(editable);
        editText.setFocusable(editable);
        editText.setFocusableInTouchMode(editable);
        editText.setCursorVisible(editable);
    }

protected void saveConfig() {
        String quicPolicyValue = selectedQuicPolicy();
        prefs.edit()
                .putString("proxy_addrs", proxyAddrs.getText().toString())
                .putString("username", username.getText().toString())
                .putString("private_key_pem", DefaultConfig.normalizePrivateKeyPem(privateKey.getText().toString()))
                .putString("http_proxy_port", String.valueOf(httpProxyListenPort()))
                .putString("http_proxy_threads", httpProxyThreads.getText().toString())
                .putString(
                        "http_proxy_max_concurrent_connects",
                        httpProxyMaxConcurrentConnects.getText().toString())
                .putString("tun_ipv4", DefaultConfig.TUN_IPV4)
                .putString("tun_ipv6", DefaultConfig.TUN_IPV6)
                .putString("mtu", String.valueOf(DefaultConfig.TUN_MTU))
                .putString("quic_policy", quicPolicyValue)
                .putString("runtime_threads", runtimeThreads.getText().toString())
                .putString("compression_mode", selectedCompressionMode())
                .putString("direct_access_mode", selectedDirectAccessMode())
                .putString("direct_access_rules", serializeDirectAccessRules())
                .putString("yamux_udp_sessions", yamuxUdpSessions.getText().toString())
                .putString(
                        "yamux_udp_max_streams_per_session",
                        yamuxUdpMaxStreamsPerSession.getText().toString())
                .putString(
                        "yamux_udp_open_stream_timeout_secs",
                        yamuxUdpOpenStreamTimeoutSecs.getText().toString())
                .putString(
                        "yamux_udp_keepalive_interval_secs",
                        yamuxUdpKeepaliveIntervalSecs.getText().toString())
                .putString(
                        "yamux_udp_connection_write_timeout_secs",
                        yamuxUdpConnectionWriteTimeoutSecs.getText().toString())
                .putString(
                        "yamux_udp_stream_window_size_kb",
                        yamuxUdpStreamWindowSizeKb.getText().toString())
                .apply();
    }

protected void restoreDefaultConfig() {
        if (isVpnRunning() || isHttpProxyRunning()) {
            Toast.makeText(this, "修改配置前请先停止 VPN 和 HTTP / SOCKS5 代理", Toast.LENGTH_SHORT).show();
            return;
        }

        proxyAddrs.setText(DefaultConfig.PROXY_ADDR);
        httpProxyPort.setText(String.valueOf(DefaultConfig.HTTP_PROXY_PORT));
        httpProxyThreads.setText(String.valueOf(DefaultConfig.HTTP_PROXY_THREADS));
        httpProxyMaxConcurrentConnects.setText(
                String.valueOf(DefaultConfig.HTTP_PROXY_MAX_CONCURRENT_CONNECTS));
        username.setText(DefaultConfig.USERNAME);
        privateKey.setText(DefaultConfig.normalizePrivateKeyPem(DefaultConfig.PRIVATE_KEY_PEM));
        setQuicPolicy(quicPolicy, DefaultConfig.QUIC_POLICY);
        runtimeThreads.setText(String.valueOf(DefaultConfig.RUNTIME_THREADS));
        setSpinnerValue(compressionMode, DefaultConfig.COMPRESSION_MODE);
        yamuxUdpSessions.setText(String.valueOf(DefaultConfig.UDP_YAMUX_SESSIONS));
        yamuxUdpMaxStreamsPerSession.setText(String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION));
        yamuxUdpOpenStreamTimeoutSecs.setText(String.valueOf(DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS));
        yamuxUdpKeepaliveIntervalSecs.setText(String.valueOf(DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS));
        yamuxUdpConnectionWriteTimeoutSecs.setText(String.valueOf(DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS));
        yamuxUdpStreamWindowSizeKb.setText(String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB));
        directAccessModeValue = DefaultConfig.DIRECT_ACCESS_MODE;
        directRuleValues.clear();
        directRuleValues.addAll(normalizeDirectRules(parseDirectRuleInput(DefaultConfig.DIRECT_ACCESS_RULES)));
        if (directRuleDraft != null) {
            directRuleDraft.setText("");
        }

        updateDirectModeButtons();
        renderDirectRuleList();
        saveConfig();
        prefs.edit().putStringSet("vpn_apps", Collections.emptySet()).apply();
        updateSelectedAppsSummary();
        Toast.makeText(this, "已恢复默认配置", Toast.LENGTH_SHORT).show();
    }

protected void setSpinnerValue(Spinner spinner, String value) {
        if (spinner == null || spinner.getAdapter() == null) {
            return;
        }
        for (int i = 0; i < spinner.getAdapter().getCount(); i++) {
            Object item = spinner.getAdapter().getItem(i);
            if (item != null && String.valueOf(item).equalsIgnoreCase(value)) {
                spinner.setSelection(i);
                return;
            }
        }
        spinner.setSelection(0);
    }

protected void setQuicPolicy(Spinner spinner, String fallback) {
        if (spinner == null || spinner.getAdapter() == null) {
            return;
        }
        String normalized = normalizeQuicPolicy(fallback);
        for (int i = 0; i < spinner.getAdapter().getCount(); i++) {
            Object item = spinner.getAdapter().getItem(i);
            if (item instanceof QuicPolicyOption
                    && ((QuicPolicyOption) item).value.equalsIgnoreCase(normalized)) {
                spinner.setSelection(i);
                return;
            }
        }
        spinner.setSelection(0);
    }

protected Spinner spinner(LinearLayout root, String title, String[] values, String selected) {
        root.addView(controlLabel(title), labelParams());
        Spinner spinner = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                this,
                android.R.layout.simple_spinner_item,
                values);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        int selectedIndex = 0;
        for (int i = 0; i < values.length; i++) {
            if (values[i].equalsIgnoreCase(selected)) {
                selectedIndex = i;
                break;
            }
        }
        spinner.setSelection(selectedIndex);
        spinner.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        spinner.setPadding(dp(12), 0, dp(12), 0);
        root.addView(spinner, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));
        trackEditable(spinner);
        return spinner;
    }

protected Spinner quicPolicySpinner(LinearLayout root, String title, String selected) {
        root.addView(controlLabel(title), labelParams());
        Spinner spinner = new Spinner(this);
        ArrayAdapter<QuicPolicyOption> adapter = new ArrayAdapter<>(
                this,
                android.R.layout.simple_spinner_item,
                QUIC_POLICY_OPTIONS);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        setQuicPolicy(spinner, selected);
        spinner.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        spinner.setPadding(dp(12), 0, dp(12), 0);
        root.addView(spinner, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));
        trackEditable(spinner);
        addFieldHelp(root, "允许时按直连规则发送 QUIC，未命中的 UDP/443 使用代理 UDP relay；阻断会丢弃 UDP/443 以强制回落到 TCP/TLS。");
        return spinner;
    }

protected String selectedCompressionMode() {
        if (compressionMode == null || compressionMode.getSelectedItem() == null) {
            return DefaultConfig.COMPRESSION_MODE;
        }
        String value = compressionMode.getSelectedItem().toString().trim().toLowerCase();
        if ("none".equals(value) || "lz4".equals(value) || "gzip".equals(value) || "zstd".equals(value)) {
            return value;
        }
        return DefaultConfig.COMPRESSION_MODE;
    }

protected String prefQuicPolicy() {
        String stored = prefs.getString("quic_policy", null);
        if (stored != null) {
            return normalizeQuicPolicy(stored);
        }
        return DefaultConfig.QUIC_POLICY;
    }

protected String selectedQuicPolicy() {
        if (quicPolicy == null || quicPolicy.getSelectedItem() == null) {
            return DefaultConfig.QUIC_POLICY;
        }
        Object selected = quicPolicy.getSelectedItem();
        if (selected instanceof QuicPolicyOption) {
            return normalizeQuicPolicy(((QuicPolicyOption) selected).value);
        }
        return normalizeQuicPolicy(selected.toString());
    }

protected String normalizeQuicPolicy(String value) {
        if (value == null) {
            return DefaultConfig.QUIC_POLICY;
        }
        String normalized = value.trim().toLowerCase();
        if ("allow".equals(normalized) || "block".equals(normalized)) {
            return normalized;
        }
        return DefaultConfig.QUIC_POLICY;
    }

protected String selectedDirectAccessMode() {
        return normalizeDirectAccessMode(directAccessModeValue);
    }

protected String prefString(String key, String fallback) {
        String value = prefs.getString(key, fallback);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        return value;
    }

protected EditText field(LinearLayout root, String title, String value) {
        return field(root, title, value, 1, InputType.TYPE_CLASS_TEXT);
    }

protected EditText field(LinearLayout root, String title, String value, int lines, int inputType) {
        root.addView(controlLabel(title), labelParams());
        EditText edit = new EditText(this);
        edit.setText(value == null ? "" : value);
        edit.setMinLines(lines);
        edit.setMaxLines(lines == 1 ? 1 : lines + 4);
        edit.setInputType(inputType);
        edit.setTextColor(COLOR_TEXT);
        edit.setTextSize(lines == 1 ? 16f : 13f);
        edit.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        edit.setMinHeight(dp(48));
        edit.setPadding(dp(12), 0, dp(12), 0);
        if (lines > 1) {
            edit.setGravity(Gravity.TOP | Gravity.START);
            edit.setPadding(dp(12), dp(10), dp(12), dp(10));
        }
        root.addView(edit, matchWrap());
        trackEditable(edit);
        return edit;
    }

protected EditText numberControl(LinearLayout root, String title, String value, int step, int min) {
        root.addView(controlLabel(title), labelParams());
        LinearLayout row = horizontalRow();

        Button minus = stepButton("-");
        EditText edit = new EditText(this);
        edit.setText(value == null ? "" : value);
        edit.setInputType(InputType.TYPE_CLASS_NUMBER);
        edit.setGravity(Gravity.CENTER);
        edit.setSingleLine(true);
        edit.setTextColor(COLOR_TEXT);
        edit.setTextSize(16f);
        edit.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        edit.setPadding(0, 0, 0, 0);
        Button plus = stepButton("+");

        minus.setOnClickListener(view -> adjustNumber(edit, -step, min));
        plus.setOnClickListener(view -> adjustNumber(edit, step, min));

        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(dp(46), dp(46));
        row.addView(minus, buttonParams);
        LinearLayout.LayoutParams valueParams = new LinearLayout.LayoutParams(0, dp(46), 1f);
        valueParams.setMargins(dp(10), 0, dp(10), 0);
        row.addView(edit, valueParams);
        row.addView(plus, new LinearLayout.LayoutParams(dp(46), dp(46)));
        root.addView(row, matchWrap());

        trackEditable(minus);
        trackEditable(edit);
        trackEditable(plus);
        return edit;
    }

protected void addFieldHelp(LinearLayout root, String text) {
        TextView help = mutedText(text, 12f);
        help.setMaxLines(3);
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(4), 0, dp(10));
        root.addView(help, params);
    }

protected Switch switchControl(LinearLayout root, String title, boolean checked) {
        LinearLayout row = controlRow();
        TextView label = controlLabel(title);
        row.addView(label, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        Switch switchView = new Switch(this);
        switchView.setChecked(checked);
        row.addView(switchView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(row, matchWrap());
        trackEditable(switchView);
        return switchView;
    }

protected void adjustNumber(EditText edit, int delta, int min) {
        int current;
        try {
            current = Integer.parseInt(edit.getText().toString().trim());
        } catch (NumberFormatException ignored) {
            current = min;
        }
        edit.setText(String.valueOf(Math.max(min, current + delta)));
        edit.setSelection(edit.getText().length());
    }

protected Button stepButton(String text) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(18f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setTextColor(COLOR_ACCENT_DARK);
        button.setAllCaps(false);
        button.setIncludeFontPadding(false);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(0, 0, 0, 0);
        button.setBackground(rounded(COLOR_ACCENT_SOFT, COLOR_ACCENT_SOFT));
        flattenButton(button);
        return button;
    }

}
