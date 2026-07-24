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
        String udpSessionPoolSizeValue = boundedIntString(
                udpSessionPoolSize == null
                        ? null
                        : udpSessionPoolSize.getText().toString(),
                DefaultConfig.UDP_SESSION_POOL_SIZE,
                DefaultConfig.MIN_UDP_SESSION_POOL_SIZE,
                DefaultConfig.MAX_UDP_SESSION_POOL_SIZE);
        if (udpSessionPoolSize != null) {
            udpSessionPoolSize.setText(udpSessionPoolSizeValue);
            udpSessionPoolSize.setSelection(udpSessionPoolSizeValue.length());
        }
        prefs.edit()
                .putString("proxy_addrs", proxyAddrs.getText().toString())
                .putString("username", username.getText().toString())
                .putString("private_key_pem", DefaultConfig.normalizePrivateKeyPem(privateKey.getText().toString()))
                .putString("transport_mode", selectedTransportMode())
                .putString("udp_session_pool_size", udpSessionPoolSizeValue)
                .putString("connect_timeout_secs", connectTimeoutSecs.getText().toString())
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
        setTransportMode(DefaultConfig.TRANSPORT_MODE, false);
        udpSessionPoolSize.setText(String.valueOf(DefaultConfig.UDP_SESSION_POOL_SIZE));
        connectTimeoutSecs.setText(String.valueOf(DefaultConfig.CONNECT_TIMEOUT_SECS));
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
        MockGeoConfig.reset(prefs);
        prefs.edit()
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false)
                .remove(PpaassVpnService.PREF_MOCK_GEO_ERROR)
                .remove(PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND)
                .apply();
        prefs.edit().putStringSet("vpn_apps", Collections.emptySet()).apply();
        updateSelectedAppsSummary();
        cleanupStaleMockGeoState();
        refreshMockGeoUi();
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
        ArrayAdapter<String> adapter = spinnerAdapter(values);
        spinner.setAdapter(adapter);
        int selectedIndex = 0;
        for (int i = 0; i < values.length; i++) {
            if (values[i].equalsIgnoreCase(selected)) {
                selectedIndex = i;
                break;
            }
        }
        spinner.setSelection(selectedIndex);
        spinner.setBackground(controlBackground());
        spinner.setPopupBackgroundDrawable(rounded(COLOR_SURFACE, COLOR_BORDER));
        spinner.setPadding(dp(12), 0, dp(12), 0);
        root.addView(spinner, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));
        trackEditable(spinner);
        return spinner;
    }

protected void transportModeControl(LinearLayout root, String selected) {
        transportModeValue = normalizeTransportMode(selected);
        root.addView(controlLabel("UDP 代理通道"), labelParams());

        LinearLayout row = horizontalRow();
        row.setPadding(dp(4), dp(4), dp(4), dp(4));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        addTransportModeButton(row, transportModeLabel("auto"), "auto");
        addTransportModeButton(row, transportModeLabel("udp"), "udp");
        addTransportModeButton(row, transportModeLabel("tcp"), "tcp");
        root.addView(row, matchWrap());
        updateTransportModeButtons();
    }

protected void addTransportModeButton(LinearLayout row, String label, String value) {
        Button button = new Button(this);
        button.setText(label);
        button.setTag(value);
        button.setContentDescription(transportModeDescription(value));
        button.setTextSize(13f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setMaxLines(1);
        button.setEllipsize(null);
        button.setGravity(Gravity.CENTER);
        button.setIncludeFontPadding(false);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(dp(6), 0, dp(6), 0);
        flattenButton(button);
        button.setOnClickListener(view -> {
            if (isVpnRunning() || isHttpProxyRunning()) {
                Toast.makeText(
                        this,
                        "修改传输模式前请先停止 VPN 和 HTTP / SOCKS5 代理",
                        Toast.LENGTH_SHORT).show();
                return;
            }
            setTransportMode(String.valueOf(view.getTag()), true);
        });
        transportModeButtons.add(button);
        trackEditable(button);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(46), 1f);
        if (row.getChildCount() > 0) {
            params.setMargins(dp(4), 0, 0, 0);
        }
        row.addView(button, params);
    }

protected void setTransportMode(String value, boolean persist) {
        transportModeValue = normalizeTransportMode(value);
        updateTransportModeButtons();
        updateTransportModeSettingsVisibility();
        if (persist && prefs != null) {
            prefs.edit().putString("transport_mode", transportModeValue).apply();
        }
    }

protected void updateTransportModeSettingsVisibility() {
        String mode = normalizeTransportMode(transportModeValue);
        boolean udpMode = "udp".equals(mode) || "auto".equals(mode);
        boolean tcpMode = "tcp".equals(mode) || "auto".equals(mode);
        if (udpSessionPoolConfig != null) {
            udpSessionPoolConfig.setVisibility(udpMode ? View.VISIBLE : View.GONE);
        }
        if (udpYamuxConfig != null) {
            udpYamuxConfig.setVisibility(tcpMode ? View.VISIBLE : View.GONE);
        }
    }

protected void updateTransportModeButtons() {
        String selected = normalizeTransportMode(transportModeValue);
        transportModeValue = selected;
        for (Button button : transportModeButtons) {
            boolean active = selected.equals(String.valueOf(button.getTag()));
            button.setSelected(active);
            String label = transportModeLabel(String.valueOf(button.getTag()));
            button.setText(active ? "✓ " + label : label);
            button.setTextColor(interactiveTextColors(
                    active ? COLOR_ACCENT_DARK : COLOR_MUTED,
                    COLOR_ACCENT_DARK));
            int fill = active ? COLOR_ACCENT_SOFT : COLOR_CONTROL;
            int stroke = active ? alphaColor(COLOR_ACCENT, 138) : COLOR_CONTROL;
            button.setBackground(interactiveRounded(fill, stroke, COLOR_ACCENT));
        }
    }

protected String transportModeLabel(String value) {
        String normalized = normalizeTransportMode(value);
        if ("auto".equals(normalized)) {
            return "自动";
        }
        return "tcp".equals(normalized) ? "全 TCP" : "原生 UDP";
}

protected String transportModeDescription(String value) {
        String normalized = normalizeTransportMode(value);
        if ("auto".equals(normalized)) {
            return "优先使用原生加密 UDP，超时后自动切换到 TCP/Yamux";
        }
        return "tcp".equals(normalized)
                ? "使用全 TCP 模式，TCP 和 UDP relay 均通过 TCP"
                : "使用原生 UDP 模式，TCP 数据走 TCP，UDP 报文逐包使用 AES-256-GCM 加密";
    }

protected String normalizeTransportMode(String value) {
        if (value == null || value.trim().isEmpty()) {
            return DefaultConfig.TRANSPORT_MODE;
        }
        String normalized = value.trim().toLowerCase();
        if ("auto".equals(normalized) || "udp".equals(normalized) || "tcp".equals(normalized)) {
            return normalized;
        }
        // 保留未知值，让 AgentConfigJson 在启动时明确拒绝。不将旧 quic
        // 配置静默迁移成语义不同的原生 UDP。
        return normalized;
    }

protected Spinner quicPolicySpinner(LinearLayout root, String title, String selected) {
        root.addView(controlLabel(title), labelParams());
        Spinner spinner = new Spinner(this);
        ArrayAdapter<QuicPolicyOption> adapter = spinnerAdapter(QUIC_POLICY_OPTIONS);
        spinner.setAdapter(adapter);
        setQuicPolicy(spinner, selected);
        spinner.setBackground(controlBackground());
        spinner.setPopupBackgroundDrawable(rounded(COLOR_SURFACE, COLOR_BORDER));
        spinner.setPadding(dp(12), 0, dp(12), 0);
        root.addView(spinner, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));
        trackEditable(spinner);
        addFieldHelp(root, "允许：UDP/443 按规则转发；阻断：回退 TCP/TLS。");
        return spinner;
    }

protected String selectedTransportMode() {
        return normalizeTransportMode(transportModeValue);
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
        edit.setTextSize(lines == 1 ? 16f : 13f);
        styleInput(edit);
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
        return numberControl(root, title, value, step, min, Integer.MAX_VALUE);
    }

protected EditText numberControl(
        LinearLayout root,
        String title,
        String value,
        int step,
        int min,
        int max) {
        root.addView(controlLabel(title), labelParams());
        LinearLayout row = horizontalRow();

        Button minus = stepButton("-");
        EditText edit = new EditText(this);
        edit.setText(value == null ? "" : value);
        edit.setInputType(InputType.TYPE_CLASS_NUMBER);
        edit.setGravity(Gravity.CENTER);
        edit.setSingleLine(true);
        edit.setTextSize(16f);
        styleInput(edit);
        edit.setPadding(0, 0, 0, 0);
        if (max < Integer.MAX_VALUE) {
            edit.setFilters(new InputFilter[]{boundedIntegerFilter(min, max)});
        }
        Button plus = stepButton("+");

        minus.setOnClickListener(view -> adjustNumber(edit, -step, min, max));
        plus.setOnClickListener(view -> adjustNumber(edit, step, min, max));

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

protected InputFilter boundedIntegerFilter(int min, int max) {
        return (source, start, end, dest, destStart, destEnd) -> {
            String candidate = dest.subSequence(0, destStart).toString()
                    + source.subSequence(start, end)
                    + dest.subSequence(destEnd, dest.length());
            if (candidate.isEmpty()) {
                return null;
            }
            try {
                int parsed = Integer.parseInt(candidate);
                int minDigits = String.valueOf(Math.max(0, min)).length();
                if (parsed > max || (parsed < min && candidate.length() >= minDigits)) {
                    return "";
                }
                return null;
            } catch (NumberFormatException ignored) {
                return "";
            }
        };
    }

protected String boundedIntString(String value, int fallback, int min, int max) {
        int parsed;
        try {
            parsed = Integer.parseInt(value == null ? "" : value.trim());
        } catch (NumberFormatException ignored) {
            parsed = fallback;
        }
        return String.valueOf(Math.max(min, Math.min(max, parsed)));
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
        switchView.setThumbTintList(new android.content.res.ColorStateList(
                new int[][]{
                        new int[]{android.R.attr.state_checked},
                        new int[]{-android.R.attr.state_enabled},
                        new int[]{}
                },
                new int[]{COLOR_ACCENT_DARK, alphaColor(COLOR_MUTED, 104), COLOR_MUTED}));
        switchView.setTrackTintList(new android.content.res.ColorStateList(
                new int[][]{
                        new int[]{android.R.attr.state_checked},
                        new int[]{-android.R.attr.state_enabled},
                        new int[]{}
                },
                new int[]{COLOR_ACCENT_SOFT, alphaColor(COLOR_CONTROL, 132), COLOR_CONTROL}));
        row.addView(switchView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(row, matchWrap());
        trackEditable(switchView);
        return switchView;
    }

protected void adjustNumber(EditText edit, int delta, int min) {
        adjustNumber(edit, delta, min, Integer.MAX_VALUE);
    }

protected void adjustNumber(EditText edit, int delta, int min, int max) {
        int current;
        try {
            current = Integer.parseInt(edit.getText().toString().trim());
        } catch (NumberFormatException ignored) {
            current = min;
        }
        long adjusted = Math.max(min, Math.min((long) max, (long) current + delta));
        edit.setText(String.valueOf(adjusted));
        edit.setSelection(edit.getText().length());
    }

protected Button stepButton(String text) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(18f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setTextColor(interactiveTextColors(
                COLOR_ACCENT_DARK,
                Color.rgb(245, 246, 255)));
        button.setAllCaps(false);
        button.setIncludeFontPadding(false);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(0, 0, 0, 0);
        button.setBackground(interactiveRounded(
                COLOR_ACCENT_SOFT,
                alphaColor(COLOR_ACCENT, 110),
                COLOR_ACCENT));
        flattenButton(button);
        return button;
    }

}
