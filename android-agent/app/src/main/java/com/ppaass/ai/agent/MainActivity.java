package com.ppaass.ai.agent;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {
    private static final int VPN_PERMISSION_REQUEST = 1001;
    private static final String PREF_MODE_DEFAULTS_MIGRATED = "mode_defaults_migrated_v2";
    private static final int COLOR_BACKGROUND = Color.rgb(246, 248, 251);
    private static final int COLOR_SURFACE = Color.WHITE;
    private static final int COLOR_CONTROL = Color.rgb(241, 245, 249);
    private static final int COLOR_TEXT = Color.rgb(17, 24, 39);
    private static final int COLOR_MUTED = Color.rgb(100, 116, 139);
    private static final int COLOR_BORDER = Color.rgb(226, 232, 240);
    private static final int COLOR_ACCENT = Color.rgb(37, 99, 235);
    private static final int COLOR_ACCENT_DARK = Color.rgb(29, 78, 216);
    private static final int COLOR_ACCENT_SOFT = Color.rgb(219, 234, 254);
    private static final int COLOR_ACTION_START = Color.rgb(15, 118, 110);
    private static final int COLOR_ACTION_STOP = Color.rgb(220, 38, 38);
    private static final int COLOR_STATUS_RUNNING = Color.rgb(22, 163, 74);
    private static final int COLOR_STATUS_STOPPED = Color.rgb(100, 116, 139);

    private SharedPreferences prefs;
    private EditText proxyAddrs;
    private EditText username;
    private EditText privateKey;
    private EditText tcpPoolSize;
    private EditText udpPoolSize;
    private Spinner compressionMode;
    private Spinner tcpMode;
    private Spinner udpMode;
    private EditText yamuxTcpSessions;
    private EditText yamuxTcpMaxStreamsPerSession;
    private EditText yamuxTcpOpenStreamTimeoutSecs;
    private EditText yamuxTcpKeepaliveIntervalSecs;
    private EditText yamuxTcpConnectionWriteTimeoutSecs;
    private EditText yamuxTcpStreamWindowSizeKb;
    private EditText yamuxUdpSessions;
    private EditText yamuxUdpMaxStreamsPerSession;
    private EditText yamuxUdpOpenStreamTimeoutSecs;
    private EditText yamuxUdpKeepaliveIntervalSecs;
    private EditText yamuxUdpConnectionWriteTimeoutSecs;
    private EditText yamuxUdpStreamWindowSizeKb;
    private Switch blockQuic;
    private TextView selectedAppsSummary;
    private Button selectAppsButton;
    private Button vpnToggle;
    private TextView vpnStatus;
    private final List<View> editableControls = new ArrayList<>();
    private final List<Button> configTabButtons = new ArrayList<>();
    private final List<View> configTabPages = new ArrayList<>();
    private final SharedPreferences.OnSharedPreferenceChangeListener preferenceChangeListener =
            (sharedPreferences, key) -> {
                if (PpaassVpnService.PREF_RUNNING.equals(key)
                        || PpaassVpnService.PREF_SYSTEM_MANAGED.equals(key)) {
                    runOnUiThread(this::updateVpnToggle);
                }
            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        configureWindow();
        prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        migrateModeDefaults();
        prefs.registerOnSharedPreferenceChangeListener(preferenceChangeListener);
        buildUi();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateVpnToggle();
    }

    @Override
    protected void onDestroy() {
        if (prefs != null) {
            prefs.unregisterOnSharedPreferenceChangeListener(preferenceChangeListener);
        }
        super.onDestroy();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_PERMISSION_REQUEST && resultCode == RESULT_OK) {
            startVpnService();
        }
    }

    @SuppressWarnings("deprecation")
    private void configureWindow() {
        getWindow().setStatusBarColor(COLOR_BACKGROUND);
        getWindow().setNavigationBarColor(COLOR_SURFACE);

        int flags = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        }
        getWindow().getDecorView().setSystemUiVisibility(flags);
    }

    private void migrateModeDefaults() {
        if (prefs.getBoolean(PREF_MODE_DEFAULTS_MIGRATED, false)) {
            return;
        }

        String compression = prefs.getString("compression_mode", "none");
        String tcp = prefs.getString("tcp_mode", "auto");
        String udp = prefs.getString("udp_mode", "auto");
        SharedPreferences.Editor editor = prefs.edit()
                .putBoolean(PREF_MODE_DEFAULTS_MIGRATED, true);

        if ("none".equalsIgnoreCase(compression)
                && "auto".equalsIgnoreCase(tcp)
                && "auto".equalsIgnoreCase(udp)) {
            editor.putString("compression_mode", DefaultConfig.COMPRESSION_MODE)
                    .putString("tcp_mode", DefaultConfig.TCP_MODE)
                    .putString("udp_mode", DefaultConfig.UDP_MODE);
        }

        editor.apply();
    }

    private void buildUi() {
        editableControls.clear();
        configTabButtons.clear();
        configTabPages.clear();

        ScrollView scroll = new ScrollView(this);
        scroll.setClipToPadding(false);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(COLOR_BACKGROUND);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int horizontalPadding = dp(16);
        int topPadding = dp(20);
        int bottomPadding = dp(24);
        root.setPadding(horizontalPadding, topPadding, horizontalPadding, bottomPadding);
        applySystemBarPadding(root, horizontalPadding, topPadding, horizontalPadding, bottomPadding);
        scroll.addView(root);

        LinearLayout header = panel(root);
        header.setPadding(dp(18), dp(18), dp(18), dp(18));
        LinearLayout headerRow = horizontalRow();

        ImageView appIcon = new ImageView(this);
        appIcon.setImageResource(R.drawable.ic_vpn);
        appIcon.setBackground(rounded(COLOR_ACCENT_SOFT, COLOR_ACCENT_SOFT));
        appIcon.setPadding(dp(10), dp(10), dp(10), dp(10));
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(48), dp(48));
        iconParams.setMargins(0, 0, dp(12), 0);
        headerRow.addView(appIcon, iconParams);

        LinearLayout titleColumn = new LinearLayout(this);
        titleColumn.setOrientation(LinearLayout.VERTICAL);
        TextView title = titleText(getString(R.string.app_name), 24f);
        titleColumn.addView(title, matchWrap());

        TextView subtitle = mutedText("Tunnel dashboard", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(2), 0, 0);
        titleColumn.addView(subtitle, subtitleParams);

        vpnStatus = chip("Stopped", COLOR_STATUS_STOPPED);
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        statusParams.setMargins(0, dp(10), 0, 0);
        titleColumn.addView(vpnStatus, statusParams);
        headerRow.addView(titleColumn, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        vpnToggle = actionButton("Start", COLOR_ACTION_START);
        vpnToggle.setOnClickListener(view -> toggleVpn());
        LinearLayout.LayoutParams toggleParams = new LinearLayout.LayoutParams(dp(112), dp(48));
        headerRow.addView(vpnToggle, toggleParams);
        header.addView(headerRow, matchWrap());

        LinearLayout apps = panel(root);
        sectionTitle(apps, "VPN apps");

        selectAppsButton = new Button(this);
        selectAppsButton.setText("Choose");
        selectAppsButton.setAllCaps(false);
        selectAppsButton.setTextSize(14f);
        selectAppsButton.setTypeface(Typeface.DEFAULT_BOLD);
        selectAppsButton.setTextColor(COLOR_ACCENT_DARK);
        selectAppsButton.setSingleLine(true);
        selectAppsButton.setMinHeight(0);
        selectAppsButton.setMinWidth(0);
        selectAppsButton.setPadding(dp(14), 0, dp(14), 0);
        selectAppsButton.setBackground(rounded(COLOR_ACCENT_SOFT, COLOR_ACCENT_SOFT));
        selectAppsButton.setOnClickListener(view -> showAppSelector());
        trackEditable(selectAppsButton);
        selectedAppsSummary = new TextView(this);
        selectedAppsSummary.setTextSize(16f);
        selectedAppsSummary.setTypeface(Typeface.DEFAULT_BOLD);
        selectedAppsSummary.setTextColor(COLOR_MUTED);
        updateSelectedAppsSummary();

        LinearLayout appsRow = horizontalRow();
        appsRow.addView(selectedAppsSummary, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        LinearLayout.LayoutParams selectAppsParams = new LinearLayout.LayoutParams(dp(104), dp(42));
        appsRow.addView(selectAppsButton, selectAppsParams);
        LinearLayout.LayoutParams appsRowParams = matchWrap();
        appsRowParams.setMargins(0, dp(4), 0, 0);
        apps.addView(appsRow, appsRowParams);

        LinearLayout configPanel = panel(root);
        sectionTitle(configPanel, "Configuration");
        LinearLayout tabBar = tabBar();
        configPanel.addView(tabBar, matchWrap());

        LinearLayout runtime = tabPage(configPanel);
        LinearLayout tcpYamux = tabPage(configPanel);
        LinearLayout udpYamux = tabPage(configPanel);
        LinearLayout connection = tabPage(configPanel);

        addConfigTab(tabBar, "Runtime", runtime);
        addConfigTab(tabBar, "TCP Yamux", tcpYamux);
        addConfigTab(tabBar, "UDP Yamux", udpYamux);
        addConfigTab(tabBar, "Connection", connection);

        blockQuic = switchControl(runtime, "Block QUIC", prefs.getBoolean("block_quic", DefaultConfig.BLOCK_QUIC));
        compressionMode = spinner(
                runtime,
                "Compression mode",
                new String[]{"none", "lz4", "gzip", "zstd"},
                prefs.getString("compression_mode", DefaultConfig.COMPRESSION_MODE));
        tcpMode = spinner(
                runtime,
                "TCP mode",
                new String[]{"auto", "yamux", "legacy"},
                prefs.getString("tcp_mode", DefaultConfig.TCP_MODE));
        udpMode = spinner(
                runtime,
                "UDP mode",
                new String[]{"auto", "yamux", "legacy"},
                prefs.getString("udp_mode", DefaultConfig.UDP_MODE));
        tcpPoolSize = numberControl(
                runtime,
                "TCP pool size",
                prefs.getString("tcp_pool_size", String.valueOf(DefaultConfig.TCP_POOL_SIZE)),
                1,
                0);
        udpPoolSize = numberControl(
                runtime,
                "UDP pool size",
                prefs.getString("udp_pool_size", String.valueOf(DefaultConfig.UDP_POOL_SIZE)),
                1,
                0);

        yamuxTcpSessions = numberControl(
                tcpYamux,
                "TCP Yamux sessions",
                prefs.getString(
                        "yamux_tcp_sessions",
                        String.valueOf(DefaultConfig.TCP_YAMUX_SESSIONS)),
                1,
                1);
        yamuxTcpMaxStreamsPerSession = numberControl(
                tcpYamux,
                "TCP Yamux max streams/session",
                prefs.getString(
                        "yamux_tcp_max_streams_per_session",
                        String.valueOf(DefaultConfig.TCP_YAMUX_MAX_STREAMS_PER_SESSION)),
                1,
                1);
        yamuxTcpOpenStreamTimeoutSecs = numberControl(
                tcpYamux,
                "TCP Yamux open stream timeout",
                prefs.getString(
                        "yamux_tcp_open_stream_timeout_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
                1,
                1);
        yamuxTcpKeepaliveIntervalSecs = numberControl(
                tcpYamux,
                "TCP Yamux keepalive interval",
                prefs.getString(
                        "yamux_tcp_keepalive_interval_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
                5,
                0);
        yamuxTcpConnectionWriteTimeoutSecs = numberControl(
                tcpYamux,
                "TCP Yamux write timeout",
                prefs.getString(
                        "yamux_tcp_connection_write_timeout_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
                1,
                1);
        yamuxTcpStreamWindowSizeKb = numberControl(
                tcpYamux,
                "TCP Yamux stream window KB",
                prefs.getString(
                        "yamux_tcp_stream_window_size_kb",
                        String.valueOf(DefaultConfig.TCP_YAMUX_STREAM_WINDOW_SIZE_KB)),
                256,
                DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB);

        yamuxUdpSessions = numberControl(
                udpYamux,
                "UDP Yamux sessions",
                prefs.getString(
                        "yamux_udp_sessions",
                        String.valueOf(DefaultConfig.UDP_YAMUX_SESSIONS)),
                1,
                1);
        yamuxUdpMaxStreamsPerSession = numberControl(
                udpYamux,
                "UDP Yamux max streams/session",
                prefs.getString(
                        "yamux_udp_max_streams_per_session",
                        String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION)),
                1,
                1);
        yamuxUdpOpenStreamTimeoutSecs = numberControl(
                udpYamux,
                "UDP Yamux open stream timeout",
                prefs.getString(
                        "yamux_udp_open_stream_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
                1,
                1);
        yamuxUdpKeepaliveIntervalSecs = numberControl(
                udpYamux,
                "UDP Yamux keepalive interval",
                prefs.getString(
                        "yamux_udp_keepalive_interval_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
                5,
                0);
        yamuxUdpConnectionWriteTimeoutSecs = numberControl(
                udpYamux,
                "UDP Yamux write timeout",
                prefs.getString(
                        "yamux_udp_connection_write_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
                1,
                1);
        yamuxUdpStreamWindowSizeKb = numberControl(
                udpYamux,
                "UDP Yamux stream window KB",
                prefs.getString(
                        "yamux_udp_stream_window_size_kb",
                        String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB)),
                256,
                DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB);

        proxyAddrs = field(connection, "Proxy addrs", prefs.getString("proxy_addrs", DefaultConfig.PROXY_ADDR), 2,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        username = field(connection, "Username", prefs.getString("username", DefaultConfig.USERNAME));
        privateKey = field(
                connection,
                "Private key PEM",
                DefaultConfig.normalizePrivateKeyPem(prefs.getString("private_key_pem", DefaultConfig.PRIVATE_KEY_PEM)),
                5,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);

        selectConfigTab(0);

        updateVpnToggle();

        setContentView(scroll);
        root.requestApplyInsets();
    }

    private void applySystemBarPadding(
            View view,
            int baseLeft,
            int baseTop,
            int baseRight,
            int baseBottom) {
        view.setOnApplyWindowInsetsListener((target, insets) -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Insets systemBars = insets.getInsets(WindowInsets.Type.systemBars());
                target.setPadding(
                        baseLeft + systemBars.left,
                        baseTop + systemBars.top,
                        baseRight + systemBars.right,
                        baseBottom + systemBars.bottom);
            } else {
                applyLegacySystemBarPadding(target, insets, baseLeft, baseTop, baseRight, baseBottom);
            }
            return insets;
        });
    }

    @SuppressWarnings("deprecation")
    private void applyLegacySystemBarPadding(
            View target,
            WindowInsets insets,
            int baseLeft,
            int baseTop,
            int baseRight,
            int baseBottom) {
        target.setPadding(
                baseLeft + insets.getSystemWindowInsetLeft(),
                baseTop + insets.getSystemWindowInsetTop(),
                baseRight + insets.getSystemWindowInsetRight(),
                baseBottom + insets.getSystemWindowInsetBottom());
    }

    private void toggleVpn() {
        if (isVpnRunning()) {
            stopVpnService();
            return;
        }

        saveConfig();
        Intent permissionIntent = VpnService.prepare(this);
        if (permissionIntent != null) {
            startActivityForResult(permissionIntent, VPN_PERMISSION_REQUEST);
        } else {
            startVpnService();
        }
    }

    private void startVpnService() {
        Intent intent = new Intent(this, PpaassVpnService.class);
        intent.setAction(PpaassVpnService.ACTION_START);
        intent.putExtra(PpaassVpnService.EXTRA_STARTED_BY_APP, true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        updateVpnToggle();
    }

    private void stopVpnService() {
        Intent intent = new Intent(this, PpaassVpnService.class);
        intent.setAction(PpaassVpnService.ACTION_STOP);
        startService(intent);
        updateVpnToggle();
    }

    private boolean isVpnRunning() {
        boolean running = prefs.getBoolean(PpaassVpnService.PREF_RUNNING, false);
        if (running && !PpaassVpnService.isRunningInProcess()) {
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_RUNNING, false)
                    .putBoolean(PpaassVpnService.PREF_SYSTEM_MANAGED, false)
                    .apply();
            return false;
        }
        return running;
    }

    private void updateVpnToggle() {
        if (vpnToggle == null) {
            return;
        }

        boolean running = isVpnRunning();
        boolean systemManaged = prefs.getBoolean(PpaassVpnService.PREF_SYSTEM_MANAGED, false);
        vpnToggle.setText(systemManaged ? "Always-on VPN" : running ? "Stop" : "Start");
        vpnToggle.setTextColor(Color.WHITE);
        int actionColor = running ? COLOR_ACTION_STOP : COLOR_ACTION_START;
        vpnToggle.setBackground(rounded(actionColor, actionColor));
        vpnToggle.setEnabled(!systemManaged);
        if (vpnStatus != null) {
            vpnStatus.setText(systemManaged ? "Always-on" : running ? "Running" : "Stopped");
            int statusColor = running ? COLOR_STATUS_RUNNING : COLOR_STATUS_STOPPED;
            vpnStatus.setBackground(rounded(statusColor, statusColor));
        }
        updateConfigEditability(!running);
    }

    private void updateConfigEditability(boolean editable) {
        for (View control : editableControls) {
            if (control instanceof EditText) {
                updateEditTextEditable((EditText) control, editable);
            } else {
                control.setEnabled(editable);
            }
        }
    }

    private void updateEditTextEditable(EditText editText, boolean editable) {
        if (editText == null) {
            return;
        }
        editText.setEnabled(editable);
        editText.setFocusable(editable);
        editText.setFocusableInTouchMode(editable);
        editText.setCursorVisible(editable);
    }

    private void saveConfig() {
        prefs.edit()
                .putString("proxy_addrs", proxyAddrs.getText().toString())
                .putString("username", username.getText().toString())
                .putString("private_key_pem", DefaultConfig.normalizePrivateKeyPem(privateKey.getText().toString()))
                .putString("tun_ipv4", DefaultConfig.TUN_IPV4)
                .putString("tun_ipv6", DefaultConfig.TUN_IPV6)
                .putString("mtu", "1500")
                .putBoolean("block_quic", blockQuic.isChecked())
                .putString("tcp_pool_size", tcpPoolSize.getText().toString())
                .putString("udp_pool_size", udpPoolSize.getText().toString())
                .putString("compression_mode", selectedCompressionMode())
                .putString("tcp_mode", selectedTcpMode())
                .putString("udp_mode", selectedUdpMode())
                .putString("yamux_tcp_sessions", yamuxTcpSessions.getText().toString())
                .putString(
                        "yamux_tcp_max_streams_per_session",
                        yamuxTcpMaxStreamsPerSession.getText().toString())
                .putString(
                        "yamux_tcp_open_stream_timeout_secs",
                        yamuxTcpOpenStreamTimeoutSecs.getText().toString())
                .putString(
                        "yamux_tcp_keepalive_interval_secs",
                        yamuxTcpKeepaliveIntervalSecs.getText().toString())
                .putString(
                        "yamux_tcp_connection_write_timeout_secs",
                        yamuxTcpConnectionWriteTimeoutSecs.getText().toString())
                .putString(
                        "yamux_tcp_stream_window_size_kb",
                        yamuxTcpStreamWindowSizeKb.getText().toString())
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

    private Spinner spinner(LinearLayout root, String title, String[] values, String selected) {
        LinearLayout row = controlRow();
        TextView label = controlLabel(title);
        row.addView(label, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

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
        spinner.setPadding(dp(8), 0, dp(8), 0);
        row.addView(spinner, new LinearLayout.LayoutParams(dp(148), dp(44)));
        root.addView(row, matchWrap());
        trackEditable(spinner);
        return spinner;
    }

    private String selectedTcpMode() {
        return selectedTransportMode(tcpMode, DefaultConfig.TCP_MODE);
    }

    private String selectedUdpMode() {
        return selectedTransportMode(udpMode, DefaultConfig.UDP_MODE);
    }

    private String selectedCompressionMode() {
        if (compressionMode == null || compressionMode.getSelectedItem() == null) {
            return DefaultConfig.COMPRESSION_MODE;
        }
        String value = compressionMode.getSelectedItem().toString().trim().toLowerCase();
        if ("none".equals(value) || "lz4".equals(value) || "gzip".equals(value) || "zstd".equals(value)) {
            return value;
        }
        return DefaultConfig.COMPRESSION_MODE;
    }

    private String selectedTransportMode(Spinner spinner, String fallback) {
        if (spinner == null || spinner.getSelectedItem() == null) {
            return fallback;
        }
        String value = spinner.getSelectedItem().toString().trim().toLowerCase();
        if ("yamux".equals(value) || "legacy".equals(value) || "auto".equals(value)) {
            return value;
        }
        return fallback;
    }

    private EditText field(LinearLayout root, String title, String value) {
        return field(root, title, value, 1, InputType.TYPE_CLASS_TEXT);
    }

    private EditText field(LinearLayout root, String title, String value, int lines, int inputType) {
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

    private EditText numberControl(LinearLayout root, String title, String value, int step, int min) {
        LinearLayout row = controlRow();
        TextView label = controlLabel(title);
        row.addView(label, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

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

        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(dp(40), dp(40));
        row.addView(minus, buttonParams);
        LinearLayout.LayoutParams valueParams = new LinearLayout.LayoutParams(dp(76), dp(40));
        valueParams.setMargins(dp(8), 0, dp(8), 0);
        row.addView(edit, valueParams);
        row.addView(plus, new LinearLayout.LayoutParams(dp(40), dp(40)));
        root.addView(row, matchWrap());

        trackEditable(minus);
        trackEditable(edit);
        trackEditable(plus);
        return edit;
    }

    private Switch switchControl(LinearLayout root, String title, boolean checked) {
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

    private void adjustNumber(EditText edit, int delta, int min) {
        int current;
        try {
            current = Integer.parseInt(edit.getText().toString().trim());
        } catch (NumberFormatException ignored) {
            current = min;
        }
        edit.setText(String.valueOf(Math.max(min, current + delta)));
        edit.setSelection(edit.getText().length());
    }

    private Button stepButton(String text) {
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
        return button;
    }

    private Button actionButton(String text, int color) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(15f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setTextColor(Color.WHITE);
        button.setSingleLine(true);
        button.setEllipsize(TextUtils.TruncateAt.END);
        button.setIncludeFontPadding(false);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setBackground(rounded(color, color));
        return button;
    }

    private LinearLayout panel(LinearLayout root) {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(18), dp(16), dp(18), dp(18));
        panel.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
        panel.setElevation(dp(2));
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, root.getChildCount() == 0 ? 0 : dp(14), 0, 0);
        root.addView(panel, params);
        return panel;
    }

    private LinearLayout tabBar() {
        LinearLayout grid = new LinearLayout(this);
        grid.setOrientation(LinearLayout.VERTICAL);
        grid.setPadding(dp(4), dp(4), dp(4), dp(4));
        grid.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        return grid;
    }

    private LinearLayout tabPage(LinearLayout root) {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(0, dp(12), 0, 0);
        page.setVisibility(View.GONE);
        configTabPages.add(page);
        root.addView(page, matchWrap());
        return page;
    }

    private void addConfigTab(LinearLayout tabBar, String title, View page) {
        Button button = new Button(this);
        button.setText(title);
        button.setTextSize(13f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setSingleLine(false);
        button.setMaxLines(2);
        button.setGravity(Gravity.CENTER);
        button.setEllipsize(TextUtils.TruncateAt.END);
        button.setPadding(dp(8), 0, dp(8), 0);
        int index = configTabButtons.size();
        button.setOnClickListener(view -> selectConfigTab(index));
        configTabButtons.add(button);

        LinearLayout row;
        if (index % 2 == 0) {
            row = horizontalRow();
            LinearLayout.LayoutParams rowParams = matchWrap();
            if (index > 0) {
                rowParams.setMargins(0, dp(4), 0, 0);
            }
            tabBar.addView(row, rowParams);
        } else {
            row = (LinearLayout) tabBar.getChildAt(tabBar.getChildCount() - 1);
        }

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(42), 1f);
        if (index % 2 == 1) {
            params.setMargins(dp(4), 0, 0, 0);
        }
        row.addView(button, params);

        if (!configTabPages.contains(page)) {
            configTabPages.add(page);
        }
    }

    private void selectConfigTab(int selectedIndex) {
        for (int i = 0; i < configTabPages.size(); i++) {
            configTabPages.get(i).setVisibility(i == selectedIndex ? View.VISIBLE : View.GONE);
        }
        for (int i = 0; i < configTabButtons.size(); i++) {
            Button button = configTabButtons.get(i);
            boolean selected = i == selectedIndex;
            button.setTextColor(selected ? COLOR_ACCENT_DARK : COLOR_MUTED);
            button.setBackground(rounded(
                    selected ? COLOR_SURFACE : COLOR_CONTROL,
                    selected ? COLOR_SURFACE : COLOR_CONTROL));
            button.setElevation(selected ? dp(1) : 0);
        }
    }

    private LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        return row;
    }

    private LinearLayout controlRow() {
        LinearLayout row = horizontalRow();
        row.setPadding(0, dp(8), 0, dp(4));
        return row;
    }

    private void sectionTitle(LinearLayout root, String text) {
        LinearLayout row = horizontalRow();
        row.setPadding(0, 0, 0, dp(6));

        View accent = new View(this);
        accent.setBackground(rounded(COLOR_ACCENT, COLOR_ACCENT));
        LinearLayout.LayoutParams accentParams = new LinearLayout.LayoutParams(dp(4), dp(18));
        accentParams.setMargins(0, 0, dp(8), 0);
        row.addView(accent, accentParams);

        TextView view = titleText(text, 15f);
        row.addView(view, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        root.addView(row, matchWrap());
    }

    private TextView titleText(String text, float size) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(COLOR_TEXT);
        view.setTextSize(size);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        return view;
    }

    private TextView mutedText(String text, float size) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(COLOR_MUTED);
        view.setTextSize(size);
        return view;
    }

    private TextView controlLabel(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(13f);
        view.setTextColor(COLOR_MUTED);
        view.setGravity(Gravity.CENTER_VERTICAL);
        view.setMaxLines(2);
        view.setEllipsize(TextUtils.TruncateAt.END);
        return view;
    }

    private LinearLayout.LayoutParams labelParams() {
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(10), 0, dp(6));
        return params;
    }

    private TextView chip(String text, int color) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(12f);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setTextColor(Color.WHITE);
        view.setPadding(dp(10), dp(5), dp(10), dp(5));
        view.setBackground(rounded(color, color));
        return view;
    }

    private GradientDrawable rounded(int fill, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(8));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private void trackEditable(View view) {
        editableControls.add(view);
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density);
    }

    private void showAppSelector() {
        List<AppEntry> apps = loadVpnCapableApps();
        Set<String> selected = selectedPackages();
        boolean[] checked = new boolean[apps.size()];
        for (int i = 0; i < apps.size(); i++) {
            AppEntry app = apps.get(i);
            checked[i] = selected.contains(app.packageName);
        }

        AppListAdapter adapter = new AppListAdapter(apps, checked);
        ListView list = new ListView(this);
        list.setAdapter(adapter);
        list.setFastScrollEnabled(true);
        list.setOnItemClickListener((parent, view, position, id) -> {
            checked[position] = !checked[position];
            adapter.notifyDataSetChanged();
        });

        new AlertDialog.Builder(this)
                .setTitle("VPN apps")
                .setView(list)
                .setPositiveButton("OK", (dialog, which) -> {
                    Set<String> next = new HashSet<>();
                    for (int i = 0; i < apps.size(); i++) {
                        if (checked[i]) {
                            next.add(apps.get(i).packageName);
                        }
                    }
                    prefs.edit().putStringSet("vpn_apps", next).apply();
                    updateSelectedAppsSummary();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private List<AppEntry> loadVpnCapableApps() {
        PackageManager pm = getPackageManager();
        List<PackageInfo> installed = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        List<AppEntry> apps = new ArrayList<>();
        for (PackageInfo info : installed) {
            if (info.packageName == null) {
                continue;
            }
            String packageName = info.packageName;
            if (getPackageName().equals(packageName) || !requestsInternet(info)) {
                continue;
            }
            ApplicationInfo appInfo = info.applicationInfo;
            CharSequence label = appInfo == null ? null : appInfo.loadLabel(pm);
            boolean systemApp = appInfo != null && (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            Drawable icon = loadIcon(pm, appInfo);
            apps.add(new AppEntry(label == null ? packageName : label.toString(), packageName, systemApp, icon));
        }
        Collections.sort(apps, (left, right) -> {
            if (left.systemApp != right.systemApp) {
                return left.systemApp ? 1 : -1;
            }
            int labelCompare = left.label.compareToIgnoreCase(right.label);
            if (labelCompare != 0) {
                return labelCompare;
            }
            return left.packageName.compareTo(right.packageName);
        });
        return apps;
    }

    private boolean requestsInternet(PackageInfo info) {
        if (info.requestedPermissions == null) {
            return false;
        }
        for (String permission : info.requestedPermissions) {
            if (Manifest.permission.INTERNET.equals(permission)) {
                return true;
            }
        }
        return false;
    }

    private Drawable loadIcon(PackageManager pm, ApplicationInfo appInfo) {
        if (appInfo == null) {
            return pm.getDefaultActivityIcon();
        }
        try {
            return appInfo.loadIcon(pm);
        } catch (RuntimeException ignored) {
            return pm.getDefaultActivityIcon();
        }
    }

    private Set<String> selectedPackages() {
        return new HashSet<>(prefs.getStringSet("vpn_apps", Collections.emptySet()));
    }

    private void updateSelectedAppsSummary() {
        if (selectedAppsSummary == null) {
            return;
        }

        Set<String> selected = selectedPackages();
        if (selected.isEmpty()) {
            selectedAppsSummary.setText("All apps");
            return;
        }

        selectedAppsSummary.setText(selected.size() + " selected");
    }

    private final class AppListAdapter extends BaseAdapter {
        private final List<AppEntry> apps;
        private final boolean[] checked;

        AppListAdapter(List<AppEntry> apps, boolean[] checked) {
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
                LinearLayout container = new LinearLayout(MainActivity.this);
                container.setOrientation(LinearLayout.HORIZONTAL);
                container.setGravity(Gravity.CENTER_VERTICAL);
                container.setPadding(dp(12), dp(8), dp(12), dp(8));

                ImageView icon = new ImageView(MainActivity.this);
                LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(40), dp(40));
                iconParams.setMargins(0, 0, dp(12), 0);
                container.addView(icon, iconParams);

                LinearLayout textColumn = new LinearLayout(MainActivity.this);
                textColumn.setOrientation(LinearLayout.VERTICAL);

                TextView label = new TextView(MainActivity.this);
                label.setSingleLine(true);
                label.setEllipsize(TextUtils.TruncateAt.END);
                label.setTextSize(15f);
                textColumn.addView(label, matchWrap());

                TextView packageName = new TextView(MainActivity.this);
                packageName.setSingleLine(true);
                packageName.setEllipsize(TextUtils.TruncateAt.END);
                packageName.setTextSize(12f);
                textColumn.addView(packageName, matchWrap());

                LinearLayout.LayoutParams textParams = new LinearLayout.LayoutParams(
                        0,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        1f);
                container.addView(textColumn, textParams);

                CheckBox checkBox = new CheckBox(MainActivity.this);
                checkBox.setClickable(false);
                checkBox.setFocusable(false);
                container.addView(checkBox, new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));

                row = new AppRow(icon, label, packageName, checkBox);
                container.setTag(row);
                convertView = container;
            } else {
                row = (AppRow) convertView.getTag();
            }

            AppEntry app = getItem(position);
            row.icon.setImageDrawable(app.icon);
            row.label.setText(app.label + (app.systemApp ? " (system)" : ""));
            row.packageName.setText(app.packageName);
            row.checkBox.setChecked(checked[position]);
            return convertView;
        }
    }

    private static final class AppRow {
        final ImageView icon;
        final TextView label;
        final TextView packageName;
        final CheckBox checkBox;

        AppRow(ImageView icon, TextView label, TextView packageName, CheckBox checkBox) {
            this.icon = icon;
            this.label = label;
            this.packageName = packageName;
            this.checkBox = checkBox;
        }
    }

    private static final class AppEntry {
        final String label;
        final String packageName;
        final boolean systemApp;
        final Drawable icon;

        AppEntry(String label, String packageName, boolean systemApp, Drawable icon) {
            this.label = label;
            this.packageName = packageName;
            this.systemApp = systemApp;
            this.icon = icon;
        }
    }
}
