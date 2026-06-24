package com.ppaass.ai.agent;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.inputmethod.EditorInfo;
import android.widget.AdapterView;
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
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class MainActivity extends Activity {
    private static final int VPN_PERMISSION_REQUEST = 1001;
    private static final String PREF_MODE_DEFAULTS_MIGRATED = "mode_defaults_migrated_v2";
    private static final String PREF_PERFORMANCE_DEFAULTS_MIGRATED = "performance_defaults_migrated_v4";
    private static final String PREF_TRAFFIC_DAY = "traffic_day";
    private static final String PREF_TRAFFIC_RX_BASE = "traffic_rx_base";
    private static final String PREF_TRAFFIC_TX_BASE = "traffic_tx_base";
    private static final String PREF_TRAFFIC_HOURLY = "traffic_hourly";
    private static final String PREF_TRAFFIC_TX_HOURLY = "traffic_tx_hourly";
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
    private static final int DIRECT_RULE_LIST_VISIBLE_RULES = 10;
    private static final int DIRECT_RULE_LIST_ROW_HEIGHT_DP = 48;
    private static final int DIRECT_RULE_LIST_CHROME_HEIGHT_DP = 52;
    private static final TransportModeOption[] TRANSPORT_MODE_OPTIONS = {
            new TransportModeOption("auto", "Auto"),
            new TransportModeOption("yamux", "Yamux"),
            new TransportModeOption("legacy", "Standard channel")
    };
    private static final QuicPolicyOption[] QUIC_POLICY_OPTIONS = {
            new QuicPolicyOption("allow", "Send QUIC by rules"),
            new QuicPolicyOption("block", "Block")
    };
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int CONNECTIVITY_TIMEOUT_MS = 8_000;
    private static final int QUIC_MIN_INITIAL_PACKET_BYTES = 1200;
    private static final int QUIC_RESERVED_VERSION = 0x0a0a0a0a;

    private SharedPreferences prefs;
    private EditText proxyAddrs;
    private EditText username;
    private EditText privateKey;
    private EditText runtimeThreads;
    private EditText tcpPoolSize;
    private EditText udpPoolSize;
    private Spinner compressionMode;
    private Spinner tcpMode;
    private Spinner udpMode;
    private LinearLayout tcpPoolConfig;
    private LinearLayout udpPoolConfig;
    private LinearLayout tcpYamuxConfig;
    private LinearLayout udpYamuxConfig;
    private String directAccessModeValue;
    private EditText directRuleDraft;
    private LinearLayout directRuleGroupList;
    private LinearLayout directRulesConfig;
    private TextView directModeSummary;
    private TextView directRuleCountSummary;
    private TextView directRuleGroupSummary;
    private View directRuleCountFact;
    private final List<Button> directModeButtons = new ArrayList<>();
    private final List<String> directRuleValues = new ArrayList<>();
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
    private Spinner quicPolicy;
    private TextView selectedAppsSummary;
    private Button selectAppsButton;
    private Button restoreDefaultsButton;
    private AlertDialog appSelectorDialog;
    private Button vpnToggle;
    private TextView vpnStatus;
    private TextView downloadSpeed;
    private TextView uploadSpeed;
    private TextView trafficDownload;
    private TextView trafficUpload;
    private LinearLayout dnsRecordList;
    private Button connectivityTestButton;
    private TextView connectivitySummary;
    private LinearLayout connectivityResultList;
    private SpeedGaugeView speedGauge;
    private TrafficBarView trafficChart;
    private final long[] hourlyDownloadBytes = new long[24];
    private final long[] hourlyUploadBytes = new long[24];
    private String lastVpnToggleLabel;
    private long lastRxBytes = -1;
    private long lastTxBytes = -1;
    private long lastTrafficSampleMs;
    private String lastDnsRecordsStateKey = "";
    private boolean connectivityTestsRunning;
    private final List<View> editableControls = new ArrayList<>();
    private final List<Button> screenTabButtons = new ArrayList<>();
    private final List<View> screenPages = new ArrayList<>();
    private final List<Button> configTabButtons = new ArrayList<>();
    private final List<View> configTabPages = new ArrayList<>();
    private final Handler statusHandler = new Handler(Looper.getMainLooper());
    private final Runnable statusRefresh = new Runnable() {
        @Override
        public void run() {
            updateStatusMetrics();
            statusHandler.postDelayed(this, 1000);
        }
    };
    private final SharedPreferences.OnSharedPreferenceChangeListener preferenceChangeListener =
            (sharedPreferences, key) -> {
                if (PpaassVpnService.PREF_RUNNING.equals(key)
                        || PpaassVpnService.PREF_SYSTEM_MANAGED.equals(key)) {
                    runOnUiThread(() -> {
                        updateVpnToggle();
                        updateStatusMetrics();
                    });
                }
            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        configureWindow();
        prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        migrateModeDefaults();
        migratePerformanceDefaults();
        prefs.registerOnSharedPreferenceChangeListener(preferenceChangeListener);
        buildUi();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateVpnToggle();
        startStatusRefresh();
    }

    @Override
    protected void onPause() {
        statusHandler.removeCallbacks(statusRefresh);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        statusHandler.removeCallbacks(statusRefresh);
        if (appSelectorDialog != null) {
            appSelectorDialog.dismiss();
            appSelectorDialog = null;
        }
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

    private void migratePerformanceDefaults() {
        if (prefs.getBoolean(PREF_PERFORMANCE_DEFAULTS_MIGRATED, false)) {
            return;
        }

        SharedPreferences.Editor editor = prefs.edit()
                .putBoolean(PREF_PERFORMANCE_DEFAULTS_MIGRATED, true);
        migrateStringDefault(editor, "compression_mode", "lz4", DefaultConfig.COMPRESSION_MODE);
        // v3 曾把 TCP Yamux 默认外层连接数调到 16；实测 HLS/TUN 场景下该值
        // 可能增加 agent<->proxy 侧竞争。如果用户沿用的是当时的默认 16，
        // 这里迁回保守默认 5；用户主动调成其他值时不覆盖。
        migrateStringDefault(
                editor,
                "yamux_tcp_sessions",
                "16",
                String.valueOf(DefaultConfig.TCP_YAMUX_SESSIONS));
        migrateStringDefault(
                editor,
                "yamux_tcp_max_streams_per_session",
                "32",
                String.valueOf(DefaultConfig.TCP_YAMUX_MAX_STREAMS_PER_SESSION));
        migrateStringDefault(
                editor,
                "yamux_udp_max_streams_per_session",
                "32",
                String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION));
        migrateStringDefault(
                editor,
                "yamux_tcp_stream_window_size_kb",
                new String[]{"256", "2048"},
                String.valueOf(DefaultConfig.TCP_YAMUX_STREAM_WINDOW_SIZE_KB));
        migrateStringDefault(
                editor,
                "yamux_udp_stream_window_size_kb",
                new String[]{"256", "2048"},
                String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB));
        editor.apply();
    }

    private void migrateStringDefault(
            SharedPreferences.Editor editor,
            String key,
            String oldDefault,
            String newDefault) {
        if (!prefs.contains(key) || oldDefault.equalsIgnoreCase(prefs.getString(key, oldDefault))) {
            editor.putString(key, newDefault);
        }
    }

    private void migrateStringDefault(
            SharedPreferences.Editor editor,
            String key,
            String[] oldDefaults,
            String newDefault) {
        String current = prefs.getString(key, oldDefaults.length > 0 ? oldDefaults[0] : newDefault);
        if (!prefs.contains(key)) {
            editor.putString(key, newDefault);
            return;
        }
        for (String oldDefault : oldDefaults) {
            if (oldDefault.equalsIgnoreCase(current)) {
                editor.putString(key, newDefault);
                return;
            }
        }
    }

    private void buildUi() {
        editableControls.clear();
        screenTabButtons.clear();
        screenPages.clear();
        configTabButtons.clear();
        configTabPages.clear();
        directModeButtons.clear();
        directRuleValues.clear();
        directRulesConfig = null;
        directRuleCountFact = null;
        lastVpnToggleLabel = null;
        lastRxBytes = -1;
        lastTxBytes = -1;
        lastTrafficSampleMs = 0;
        loadHourlyTrafficState();

        ScrollView scroll = new ScrollView(this);
        scroll.setClipToPadding(false);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(COLOR_BACKGROUND);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int horizontalPadding = dp(16);
        int topPadding = dp(20);
        int bottomPadding = dp(24);
        root.setPadding(
                horizontalPadding,
                topPadding + systemBarInsetFallback("status_bar_height"),
                horizontalPadding,
                bottomPadding + systemBarInsetFallback("navigation_bar_height"));
        applySystemBarPadding(root, horizontalPadding, topPadding, horizontalPadding, bottomPadding);
        scroll.addView(root);

        LinearLayout screenTabs = screenTabBar();
        root.addView(screenTabs, matchWrap());

        LinearLayout statusScreen = screenPage(root);
        LinearLayout configScreen = screenPage(root);
        addScreenTab(screenTabs, "Status", statusScreen);
        addScreenTab(screenTabs, "Config", configScreen);

        buildStatusScreen(statusScreen);
        buildConfigScreen(configScreen);

        selectScreen(0);
        updateVpnToggle();
        updateStatusMetrics();

        setContentView(scroll);
        root.requestApplyInsets();
    }

    private void buildStatusScreen(LinearLayout root) {
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

        TextView subtitle = mutedText("System status", 13f);
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

        buildConnectivityPanel(root);

        LinearLayout dashboard = panel(root);
        sectionTitle(dashboard, "Live dashboard");
        speedGauge = new SpeedGaugeView();
        LinearLayout.LayoutParams gaugeParams = matchWrap();
        gaugeParams.height = dp(210);
        gaugeParams.setMargins(0, dp(6), 0, dp(12));
        dashboard.addView(speedGauge, gaugeParams);

        LinearLayout speedRow = horizontalRow();
        downloadSpeed = statusTile(speedRow, "Download", "0 B/s");
        uploadSpeed = statusTile(speedRow, "Upload", "0 B/s");
        dashboard.addView(speedRow, matchWrap());

        LinearLayout dailyPanel = panel(root);
        sectionTitle(dailyPanel, "Data usage");
        trafficChart = new TrafficBarView();
        LinearLayout.LayoutParams chartParams = matchWrap();
        chartParams.height = dp(150);
        chartParams.setMargins(0, dp(8), 0, dp(10));
        dailyPanel.addView(trafficChart, chartParams);
        LinearLayout trafficRow = horizontalRow();
        trafficDownload = statusTile(trafficRow, "Download", "0 B");
        trafficUpload = statusTile(trafficRow, "Upload", "0 B");
        dailyPanel.addView(trafficRow, matchWrap());

        LinearLayout dnsPanel = panel(root);
        sectionTitle(dnsPanel, "Agent DNS records");
        TextView dnsSubtitle = mutedText("Last 80 DNS resolutions handled by Agent", 13f);
        LinearLayout.LayoutParams dnsSubtitleParams = matchWrap();
        dnsSubtitleParams.setMargins(0, dp(2), 0, dp(10));
        dnsPanel.addView(dnsSubtitle, dnsSubtitleParams);

        ScrollView dnsScroll = new ScrollView(this);
        dnsScroll.setVerticalScrollBarEnabled(true);
        dnsScroll.setClipToPadding(false);
        dnsScroll.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            dnsScroll.setNestedScrollingEnabled(true);
        }
        dnsRecordList = new LinearLayout(this);
        dnsRecordList.setOrientation(LinearLayout.VERTICAL);
        dnsRecordList.setPadding(dp(8), dp(8), dp(8), dp(8));
        dnsScroll.addView(dnsRecordList, matchWrap());
        LinearLayout.LayoutParams dnsScrollParams = matchWrap();
        dnsScrollParams.height = dp(300);
        dnsPanel.addView(dnsScroll, dnsScrollParams);
    }

    private void buildConnectivityPanel(LinearLayout root) {
        LinearLayout panel = panel(root);
        sectionTitle(panel, "VPN connectivity");
        TextView subtitle = mutedText("Google / YouTube HTTPS and QUIC over the VPN path", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(2), 0, dp(10));
        panel.addView(subtitle, subtitleParams);

        LinearLayout actionRow = horizontalRow();
        connectivitySummary = mutedText("Start VPN, then run tests", 13f);
        connectivitySummary.setTypeface(Typeface.DEFAULT_BOLD);
        actionRow.addView(connectivitySummary, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        connectivityTestButton = actionButton("Test", COLOR_ACCENT);
        connectivityTestButton.setOnClickListener(view -> runConnectivityTests());
        actionRow.addView(connectivityTestButton, new LinearLayout.LayoutParams(dp(104), dp(42)));
        panel.addView(actionRow, matchWrap());

        connectivityResultList = new LinearLayout(this);
        connectivityResultList.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams resultParams = matchWrap();
        resultParams.setMargins(0, dp(10), 0, 0);
        panel.addView(connectivityResultList, resultParams);
        addConnectivityEmptyRow("No tests run");
    }

    private void buildConfigScreen(LinearLayout root) {
        LinearLayout actions = configSection(root, "Configuration");
        TextView actionsSubtitle = mutedText("Restore all Agent settings to the built-in defaults", 13f);
        LinearLayout.LayoutParams actionsSubtitleParams = matchWrap();
        actionsSubtitleParams.setMargins(0, 0, 0, dp(10));
        actions.addView(actionsSubtitle, actionsSubtitleParams);
        restoreDefaultsButton = actionButton("Restore defaults", COLOR_ACCENT);
        restoreDefaultsButton.setOnClickListener(view -> restoreDefaultConfig());
        trackEditable(restoreDefaultsButton);
        actions.addView(restoreDefaultsButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));

        LinearLayout connection = configSection(root, "Connection");
        proxyAddrs = field(connection, "Proxy addrs", prefString("proxy_addrs", DefaultConfig.PROXY_ADDR), 2,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        username = field(connection, "Username", prefString("username", DefaultConfig.USERNAME));
        privateKey = field(
                connection,
                "Private key PEM",
                DefaultConfig.normalizePrivateKeyPem(prefString("private_key_pem", DefaultConfig.PRIVATE_KEY_PEM)),
                5,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);

        LinearLayout runtime = configSection(root, "Runtime");
        quicPolicy = quicPolicySpinner(runtime, "QUIC policy", prefQuicPolicy());
        runtimeThreads = numberControl(
                runtime,
                "Runtime threads",
                prefString("runtime_threads", String.valueOf(DefaultConfig.RUNTIME_THREADS)),
                1,
                1);
        compressionMode = spinner(
                runtime,
                "Compression mode",
                new String[]{"none", "lz4", "gzip", "zstd"},
                prefString("compression_mode", DefaultConfig.COMPRESSION_MODE));

        LinearLayout tcpConfig = configSection(root, "TCP");
        tcpMode = transportModeSpinner(tcpConfig, "Transport", prefString("tcp_mode", DefaultConfig.TCP_MODE));
        tcpPoolConfig = configGroup(
                tcpConfig,
                "Connection pool",
                "Applies in Standard channel and Auto");
        tcpPoolSize = numberControl(
                tcpPoolConfig,
                "Pool size",
                prefString("tcp_pool_size", String.valueOf(DefaultConfig.TCP_POOL_SIZE)),
                1,
                0);
        tcpYamuxConfig = configGroup(
                tcpConfig,
                "TCP Yamux",
                "Applies in Yamux and Auto");
        yamuxTcpSessions = numberControl(
                tcpYamuxConfig,
                "Outer sessions",
                prefString(
                        "yamux_tcp_sessions",
                        String.valueOf(DefaultConfig.TCP_YAMUX_SESSIONS)),
                1,
                1);
        yamuxTcpMaxStreamsPerSession = numberControl(
                tcpYamuxConfig,
                "Max streams/session",
                prefString(
                        "yamux_tcp_max_streams_per_session",
                        String.valueOf(DefaultConfig.TCP_YAMUX_MAX_STREAMS_PER_SESSION)),
                1,
                1);
        yamuxTcpOpenStreamTimeoutSecs = numberControl(
                tcpYamuxConfig,
                "Open stream timeout",
                prefString(
                        "yamux_tcp_open_stream_timeout_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
                1,
                1);
        yamuxTcpKeepaliveIntervalSecs = numberControl(
                tcpYamuxConfig,
                "Keepalive interval",
                prefString(
                        "yamux_tcp_keepalive_interval_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
                5,
                0);
        yamuxTcpConnectionWriteTimeoutSecs = numberControl(
                tcpYamuxConfig,
                "Write timeout",
                prefString(
                        "yamux_tcp_connection_write_timeout_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
                1,
                1);
        yamuxTcpStreamWindowSizeKb = numberControl(
                tcpYamuxConfig,
                "Stream window KB",
                prefString(
                        "yamux_tcp_stream_window_size_kb",
                        String.valueOf(DefaultConfig.TCP_YAMUX_STREAM_WINDOW_SIZE_KB)),
                256,
                DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB);

        LinearLayout udpConfig = configSection(root, "UDP");
        udpMode = transportModeSpinner(udpConfig, "Transport", prefString("udp_mode", DefaultConfig.UDP_MODE));
        udpPoolConfig = configGroup(
                udpConfig,
                "Connection pool",
                "Applies in Standard channel and Auto");
        udpPoolSize = numberControl(
                udpPoolConfig,
                "Pool size",
                prefString("udp_pool_size", String.valueOf(DefaultConfig.UDP_POOL_SIZE)),
                1,
                0);
        udpYamuxConfig = configGroup(
                udpConfig,
                "UDP Yamux",
                "Applies in Yamux and Auto");
        yamuxUdpSessions = numberControl(
                udpYamuxConfig,
                "Outer sessions",
                prefString(
                        "yamux_udp_sessions",
                        String.valueOf(DefaultConfig.UDP_YAMUX_SESSIONS)),
                1,
                1);
        yamuxUdpMaxStreamsPerSession = numberControl(
                udpYamuxConfig,
                "Max streams/session",
                prefString(
                        "yamux_udp_max_streams_per_session",
                        String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION)),
                1,
                1);
        yamuxUdpOpenStreamTimeoutSecs = numberControl(
                udpYamuxConfig,
                "Open stream timeout",
                prefString(
                        "yamux_udp_open_stream_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
                1,
                1);
        yamuxUdpKeepaliveIntervalSecs = numberControl(
                udpYamuxConfig,
                "Keepalive interval",
                prefString(
                        "yamux_udp_keepalive_interval_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
                5,
                0);
        yamuxUdpConnectionWriteTimeoutSecs = numberControl(
                udpYamuxConfig,
                "Write timeout",
                prefString(
                        "yamux_udp_connection_write_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
                1,
                1);
        yamuxUdpStreamWindowSizeKb = numberControl(
                udpYamuxConfig,
                "Stream window KB",
                prefString(
                        "yamux_udp_stream_window_size_kb",
                        String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB)),
                256,
                DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB);

        updateTransportVisibility();

        buildDirectAccessSection(root);
    }

    private void buildDirectAccessSection(LinearLayout root) {
        directAccessModeValue = normalizeDirectAccessMode(
                prefs.getString("direct_access_mode", DefaultConfig.DIRECT_ACCESS_MODE));
        directRuleValues.clear();
        directRuleValues.addAll(normalizeDirectRules(parseDirectRuleInput(
                prefs.getString("direct_access_rules", DefaultConfig.DIRECT_ACCESS_RULES))));

        LinearLayout section = configSection(root, "Direct access");
        TextView subtitle = mutedText("Shared direct policy", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, 0, 0, dp(8));
        section.addView(subtitle, subtitleParams);

        addDirectModeControl(section);
        addDirectPolicyFacts(section);
        addForwardingMethodRows(section);
        directRulesConfig = new LinearLayout(this);
        directRulesConfig.setOrientation(LinearLayout.VERTICAL);
        section.addView(directRulesConfig, matchWrap());
        addDirectRulePresets(directRulesConfig);
        addDirectRuleManager(directRulesConfig);
        updateDirectModeButtons();
        renderDirectRuleList();
    }

    private void addDirectModeControl(LinearLayout root) {
        root.addView(controlLabel("Mode"), labelParams());
        LinearLayout row = horizontalRow();
        row.setPadding(dp(4), dp(4), dp(4), dp(4));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        addDirectModeButton(row, "All proxy", "proxy_all");
        addDirectModeButton(row, "All direct", "direct_all");
        addDirectModeButton(row, "By rules", "rules");
        root.addView(row, matchWrap());
    }

    private void addDirectModeButton(LinearLayout row, String label, String value) {
        Button button = new Button(this);
        button.setText(label);
        button.setTag(value);
        button.setTextSize(13f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(dp(6), 0, dp(6), 0);
        button.setOnClickListener(view -> {
            directAccessModeValue = String.valueOf(view.getTag());
            updateDirectModeButtons();
        });
        directModeButtons.add(button);
        trackEditable(button);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(44), 1f);
        if (row.getChildCount() > 0) {
            params.setMargins(dp(4), 0, 0, 0);
        }
        row.addView(button, params);
    }

    private void addDirectPolicyFacts(LinearLayout root) {
        LinearLayout row = horizontalRow();
        LinearLayout.LayoutParams rowParams = matchWrap();
        rowParams.setMargins(0, dp(12), 0, 0);
        directModeSummary = addPolicyFact(row, "Current mode", directModeLabel(directAccessModeValue));
        directRuleCountSummary = addPolicyFact(row, "Rule count", directRuleCountLabel());
        directRuleCountFact = directRuleCountSummary == null ? null : (View) directRuleCountSummary.getParent();
        addPolicyFact(row, "Config section", "direct_access");
        root.addView(row, rowParams);
    }

    private TextView addPolicyFact(LinearLayout row, String label, String value) {
        LinearLayout tile = new LinearLayout(this);
        tile.setOrientation(LinearLayout.VERTICAL);
        tile.setPadding(dp(9), dp(8), dp(9), dp(8));
        tile.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        TextView labelView = mutedText(label, 10f);
        labelView.setSingleLine(true);
        labelView.setEllipsize(TextUtils.TruncateAt.END);
        tile.addView(labelView, matchWrap());

        TextView valueView = titleText(value, 12f);
        valueView.setSingleLine(true);
        valueView.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams valueParams = matchWrap();
        valueParams.setMargins(0, dp(3), 0, 0);
        tile.addView(valueView, valueParams);

        LinearLayout.LayoutParams tileParams = new LinearLayout.LayoutParams(0, dp(70), 1f);
        if (row.getChildCount() > 0) {
            tileParams.setMargins(dp(8), 0, 0, 0);
        }
        row.addView(tile, tileParams);
        return valueView;
    }

    private void addForwardingMethodRows(LinearLayout root) {
        LinearLayout methods = new LinearLayout(this);
        methods.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams methodsParams = matchWrap();
        methodsParams.setMargins(0, dp(12), 0, 0);
        addForwardingMethod(methods, "Android VPN", "TUN traffic policy");
        addForwardingMethod(methods, "Policy routing", "Uses the selected direct access mode");
        root.addView(methods, methodsParams);
    }

    private void addForwardingMethod(LinearLayout root, String title, String detail) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(dp(12), dp(9), dp(12), dp(9));
        row.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));

        TextView titleView = titleText(title, 13f);
        titleView.setSingleLine(true);
        titleView.setEllipsize(TextUtils.TruncateAt.END);
        row.addView(titleView, matchWrap());

        TextView detailView = mutedText(detail, 11f);
        detailView.setSingleLine(true);
        detailView.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams detailParams = matchWrap();
        detailParams.setMargins(0, dp(3), 0, 0);
        row.addView(detailView, detailParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        if (root.getChildCount() > 0) {
            rowParams.setMargins(0, dp(8), 0, 0);
        }
        root.addView(row, rowParams);
    }

    private void addDirectRulePresets(LinearLayout root) {
        LinearLayout.LayoutParams headingParams = matchWrap();
        headingParams.setMargins(0, dp(16), 0, dp(6));
        root.addView(controlLabel("Quick presets"), headingParams);

        LinearLayout firstRow = horizontalRow();
        addPresetButton(firstRow, "Local", new String[]{"localhost", "127.0.0.0/8", "::1"});
        addPresetButton(firstRow, "Private LAN", new String[]{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"});
        root.addView(firstRow, matchWrap());

        LinearLayout secondRow = horizontalRow();
        LinearLayout.LayoutParams secondRowParams = matchWrap();
        secondRowParams.setMargins(0, dp(8), 0, 0);
        addPresetButton(secondRow, "China", new String[]{"*.cn"});
        addPresetButton(secondRow, "Microsoft", new String[]{"*.microsoft.com", "*.bing.com"});
        root.addView(secondRow, secondRowParams);

        LinearLayout thirdRow = horizontalRow();
        LinearLayout.LayoutParams thirdRowParams = matchWrap();
        thirdRowParams.setMargins(0, dp(8), 0, 0);
        addPresetButton(thirdRow, "YouTube", new String[]{
                "youtube.com",
                "*.youtube.com",
                "youtu.be",
                "*.youtu.be",
                "youtubei.googleapis.com",
                "youtube.googleapis.com",
                "suggestqueries.google.com",
                "googlevideo.com",
                "*.googlevideo.com",
                "ytimg.com",
                "*.ytimg.com",
                "ggpht.com",
                "*.ggpht.com",
                "*.gstatic.com"
        });
        root.addView(thirdRow, thirdRowParams);
    }

    private void addPresetButton(LinearLayout row, String label, String[] rules) {
        Button button = secondaryButton(label);
        button.setOnClickListener(view -> addDirectRules(rules));
        trackEditable(button);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(44), 1f);
        if (row.getChildCount() > 0) {
            params.setMargins(dp(8), 0, 0, 0);
        }
        row.addView(button, params);
    }

    private void addDirectRuleManager(LinearLayout root) {
        LinearLayout heading = horizontalRow();
        LinearLayout.LayoutParams headingParams = matchWrap();
        headingParams.setMargins(0, dp(16), 0, dp(6));
        TextView title = controlLabel("Rule management");
        heading.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        directRuleGroupSummary = chip("0 groups", COLOR_ACCENT);
        heading.addView(directRuleGroupSummary, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(heading, headingParams);

        LinearLayout compose = horizontalRow();
        directRuleDraft = new EditText(this);
        directRuleDraft.setHint("Domain / wildcard / CIDR");
        directRuleDraft.setSingleLine(true);
        directRuleDraft.setImeOptions(EditorInfo.IME_ACTION_DONE);
        directRuleDraft.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        directRuleDraft.setTextColor(COLOR_TEXT);
        directRuleDraft.setTextSize(15f);
        directRuleDraft.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        directRuleDraft.setPadding(dp(12), 0, dp(12), 0);
        directRuleDraft.setOnEditorActionListener((view, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                addDraftDirectRules();
                return true;
            }
            return false;
        });
        trackEditable(directRuleDraft);
        compose.addView(directRuleDraft, new LinearLayout.LayoutParams(0, dp(48), 1f));

        Button addButton = actionButton("Add", COLOR_ACCENT);
        addButton.setOnClickListener(view -> addDraftDirectRules());
        trackEditable(addButton);
        LinearLayout.LayoutParams addParams = new LinearLayout.LayoutParams(dp(92), dp(48));
        addParams.setMargins(dp(8), 0, 0, 0);
        compose.addView(addButton, addParams);
        root.addView(compose, matchWrap());

        TextView inventoryLabel = controlLabel("Current rules");
        LinearLayout.LayoutParams inventoryParams = labelParams();
        inventoryParams.setMargins(0, dp(14), 0, dp(6));
        root.addView(inventoryLabel, inventoryParams);

        directRuleGroupList = new LinearLayout(this);
        directRuleGroupList.setOrientation(LinearLayout.VERTICAL);

        MaxHeightScrollView ruleScroll = new MaxHeightScrollView(
                this,
                directRuleListMaxHeightPx());
        ruleScroll.setVerticalScrollBarEnabled(true);
        ruleScroll.setScrollbarFadingEnabled(false);
        ruleScroll.setClipToPadding(false);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            ruleScroll.setNestedScrollingEnabled(true);
        }
        ruleScroll.addView(directRuleGroupList, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(ruleScroll, matchWrap());
    }

    private int directRuleListMaxHeightPx() {
        return dp(DIRECT_RULE_LIST_CHROME_HEIGHT_DP
                + DIRECT_RULE_LIST_VISIBLE_RULES * DIRECT_RULE_LIST_ROW_HEIGHT_DP);
    }

    private Button secondaryButton(String text) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(13f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setEllipsize(TextUtils.TruncateAt.END);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(dp(8), 0, dp(8), 0);
        button.setTextColor(COLOR_ACCENT_DARK);
        button.setBackground(rounded(COLOR_ACCENT_SOFT, COLOR_ACCENT_SOFT));
        return button;
    }

    private void addDraftDirectRules() {
        if (directRuleDraft == null) {
            return;
        }
        addDirectRules(parseDirectRuleInput(directRuleDraft.getText().toString()));
        directRuleDraft.setText("");
    }

    private void addDirectRules(String[] rules) {
        List<String> values = new ArrayList<>();
        Collections.addAll(values, rules);
        addDirectRules(values);
    }

    private void addDirectRules(List<String> rules) {
        List<String> merged = new ArrayList<>(directRuleValues);
        merged.addAll(rules);
        directRuleValues.clear();
        directRuleValues.addAll(normalizeDirectRules(merged));
        renderDirectRuleList();
    }

    private void removeDirectRule(int index) {
        if (index < 0 || index >= directRuleValues.size()) {
            return;
        }
        directRuleValues.remove(index);
        renderDirectRuleList();
    }

    private void renderDirectRuleList() {
        if (directRuleGroupList == null) {
            return;
        }
        directRuleGroupList.removeAllViews();
        int groupCount = 0;
        groupCount += addDirectRuleGroup("Wildcard", "wildcard");
        groupCount += addDirectRuleGroup("IP / CIDR", "network");
        groupCount += addDirectRuleGroup("Domain", "domain");
        groupCount += addDirectRuleGroup("Other", "other");

        if (directRuleValues.isEmpty()) {
            TextView empty = mutedText("Not configured", 14f);
            empty.setGravity(Gravity.CENTER);
            empty.setTypeface(Typeface.DEFAULT_BOLD);
            empty.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
            directRuleGroupList.addView(empty, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    dp(64)));
        }

        if (directRuleGroupSummary != null) {
            directRuleGroupSummary.setText(groupCount + (groupCount == 1 ? " group" : " groups"));
        }
        updateDirectAccessSummary();
    }

    private int addDirectRuleGroup(String label, String groupKey) {
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
        group.setPadding(dp(10), dp(9), dp(10), dp(10));
        group.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
        LinearLayout.LayoutParams groupParams = matchWrap();
        if (directRuleGroupList.getChildCount() > 0) {
            groupParams.setMargins(0, dp(8), 0, 0);
        }

        LinearLayout heading = horizontalRow();
        TextView title = titleText(label, 13f);
        heading.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView countView = mutedText(String.valueOf(count), 12f);
        countView.setTypeface(Typeface.DEFAULT_BOLD);
        heading.addView(countView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        group.addView(heading, matchWrap());

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

    private void addDirectRuleChip(LinearLayout root, String rule, int index) {
        LinearLayout row = horizontalRow();
        row.setPadding(dp(10), dp(7), dp(7), dp(7));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        TextView text = titleText(rule, 12f);
        text.setSingleLine(true);
        text.setEllipsize(TextUtils.TruncateAt.END);
        row.addView(text, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button remove = new Button(this);
        remove.setText("x");
        remove.setTextSize(12f);
        remove.setTypeface(Typeface.DEFAULT_BOLD);
        remove.setAllCaps(false);
        remove.setMinHeight(0);
        remove.setMinWidth(0);
        remove.setPadding(0, 0, 0, 0);
        remove.setTextColor(COLOR_ACTION_STOP);
        remove.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
        remove.setOnClickListener(view -> removeDirectRule(index));
        trackEditable(remove);
        LinearLayout.LayoutParams removeParams = new LinearLayout.LayoutParams(dp(34), dp(32));
        removeParams.setMargins(dp(8), 0, 0, 0);
        row.addView(remove, removeParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        rowParams.setMargins(0, dp(8), 0, 0);
        root.addView(row, rowParams);
    }

    private void updateDirectModeButtons() {
        String selectedMode = normalizeDirectAccessMode(directAccessModeValue);
        directAccessModeValue = selectedMode;
        for (Button button : directModeButtons) {
            boolean selected = selectedMode.equals(String.valueOf(button.getTag()));
            button.setTextColor(selected ? Color.WHITE : COLOR_MUTED);
            int fill = selected ? COLOR_ACCENT : COLOR_CONTROL;
            int stroke = selected ? COLOR_ACCENT : COLOR_CONTROL;
            button.setBackground(rounded(fill, stroke));
            button.setElevation(selected ? dp(1) : 0);
        }
        updateDirectAccessSummary();
        updateDirectRuleConfigVisibility();
    }

    private void updateDirectAccessSummary() {
        if (directModeSummary != null) {
            directModeSummary.setText(directModeLabel(directAccessModeValue));
        }
        if (directRuleCountSummary != null) {
            directRuleCountSummary.setText(directRuleCountLabel());
        }
    }

    private void updateDirectRuleConfigVisibility() {
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

    private String directRuleCountLabel() {
        int count = directRuleValues.size();
        return count + (count == 1 ? " rule" : " rules");
    }

    private List<String> parseDirectRuleInput(String value) {
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

    private List<String> normalizeDirectRules(List<String> rules) {
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

    private String serializeDirectAccessRules() {
        return TextUtils.join("\n", directRuleValues);
    }

    private String normalizeDirectAccessMode(String value) {
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

    private String directModeLabel(String mode) {
        String normalized = normalizeDirectAccessMode(mode);
        if ("direct_all".equals(normalized)) {
            return "All direct";
        }
        if ("rules".equals(normalized)) {
            return "By rules";
        }
        return "All proxy";
    }

    private String ruleGroupKey(String rule) {
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

    private boolean isNetworkRule(String rule) {
        return rule.matches("^(\\d{1,3}\\.){3}\\d{1,3}(/\\d{1,2})?$")
                || rule.matches("^([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}(/\\d{1,3})?$");
    }

    private void applySystemBarPadding(
            View view,
            int baseLeft,
            int baseTop,
            int baseRight,
            int baseBottom) {
        int topFallback = systemBarInsetFallback("status_bar_height");
        int bottomFallback = systemBarInsetFallback("navigation_bar_height");
        view.setOnApplyWindowInsetsListener((target, insets) -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Insets systemBars = insets.getInsets(WindowInsets.Type.systemBars());
                target.setPadding(
                        baseLeft + systemBars.left,
                        baseTop + Math.max(systemBars.top, topFallback),
                        baseRight + systemBars.right,
                        baseBottom + Math.max(systemBars.bottom, bottomFallback));
            } else {
                applyLegacySystemBarPadding(
                        target,
                        insets,
                        baseLeft,
                        baseTop,
                        baseRight,
                        baseBottom,
                        topFallback,
                        bottomFallback);
            }
            return insets;
        });
    }

    private int systemBarInsetFallback(String resourceName) {
        if (Build.VERSION.SDK_INT < 35) {
            return 0;
        }
        int resourceId = getResources().getIdentifier(resourceName, "dimen", "android");
        if (resourceId == 0) {
            return 0;
        }
        return getResources().getDimensionPixelSize(resourceId);
    }

    @SuppressWarnings("deprecation")
    private void applyLegacySystemBarPadding(
            View target,
            WindowInsets insets,
            int baseLeft,
            int baseTop,
            int baseRight,
            int baseBottom,
            int topFallback,
            int bottomFallback) {
        target.setPadding(
                baseLeft + insets.getSystemWindowInsetLeft(),
                baseTop + Math.max(insets.getSystemWindowInsetTop(), topFallback),
                baseRight + insets.getSystemWindowInsetRight(),
                baseBottom + Math.max(insets.getSystemWindowInsetBottom(), bottomFallback));
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

    private void startStatusRefresh() {
        statusHandler.removeCallbacks(statusRefresh);
        updateStatusMetrics();
        statusHandler.postDelayed(statusRefresh, 1000);
    }

    private void updateVpnToggle() {
        if (vpnToggle == null) {
            return;
        }

        boolean running = isVpnRunning();
        boolean systemManaged = prefs.getBoolean(PpaassVpnService.PREF_SYSTEM_MANAGED, false);
        String label = running ? "Stop" : "Start";
        int actionColor = running ? COLOR_ACTION_STOP : COLOR_ACTION_START;
        updateFlipButton(label, actionColor, true);
        if (vpnStatus != null) {
            vpnStatus.setText(systemManaged ? "Always-on VPN" : running ? "Connected" : "Stopped");
            int statusColor = running ? COLOR_STATUS_RUNNING : COLOR_STATUS_STOPPED;
            vpnStatus.setBackground(rounded(statusColor, statusColor));
        }
        updateConfigEditability(!running);
        updateConnectivityButton();
    }

    private void updateFlipButton(String label, int color, boolean enabled) {
        boolean shouldFlip = lastVpnToggleLabel != null && !label.equals(lastVpnToggleLabel);
        lastVpnToggleLabel = label;
        if (!shouldFlip) {
            vpnToggle.animate().cancel();
            vpnToggle.setRotationY(0f);
            applyToggleButtonState(label, color, enabled);
            return;
        }

        vpnToggle.animate()
                .rotationY(90f)
                .setDuration(110)
                .withEndAction(() -> {
                    applyToggleButtonState(label, color, enabled);
                    vpnToggle.setRotationY(-90f);
                    vpnToggle.animate().rotationY(0f).setDuration(110).start();
                })
                .start();
    }

    private void applyToggleButtonState(String label, int color, boolean enabled) {
        vpnToggle.setText(label);
        vpnToggle.setTextColor(Color.WHITE);
        vpnToggle.setBackground(rounded(color, color));
        vpnToggle.setEnabled(enabled);
    }

    private void updateStatusMetrics() {
        long rxBytes = currentVpnDownloadBytes();
        long txBytes = currentVpnUploadBytes();
        long nowMs = SystemClock.elapsedRealtime();
        boolean resetDay = ensureTrafficDay(rxBytes, txBytes);

        long rxRate = 0;
        long txRate = 0;
        long deltaRx = 0;
        long deltaTx = 0;
        if (lastTrafficSampleMs > 0 && !resetDay) {
            long elapsedMs = Math.max(1, nowMs - lastTrafficSampleMs);
            deltaRx = Math.max(0, rxBytes - lastRxBytes);
            deltaTx = Math.max(0, txBytes - lastTxBytes);
            rxRate = deltaRx * 1000 / elapsedMs;
            txRate = deltaTx * 1000 / elapsedMs;
        }

        lastRxBytes = rxBytes;
        lastTxBytes = txBytes;
        lastTrafficSampleMs = nowMs;

        if (deltaRx > 0 || deltaTx > 0) {
            recordHourlyTraffic(deltaRx, deltaTx);
        }

        long downloadBytes = Math.max(0, rxBytes - prefs.getLong(PREF_TRAFFIC_RX_BASE, rxBytes));
        long uploadBytes = Math.max(0, txBytes - prefs.getLong(PREF_TRAFFIC_TX_BASE, txBytes));
        boolean running = isVpnRunning();
        if (!running) {
            rxRate = 0;
            txRate = 0;
        }

        if (downloadSpeed != null) {
            downloadSpeed.setText(formatSpeed(rxRate));
        }
        if (uploadSpeed != null) {
            uploadSpeed.setText(formatSpeed(txRate));
        }
        if (trafficDownload != null) {
            trafficDownload.setText(formatBytes(downloadBytes));
        }
        if (trafficUpload != null) {
            trafficUpload.setText(formatBytes(uploadBytes));
        }
        if (speedGauge != null) {
            speedGauge.setSpeeds(rxRate, txRate, running);
        }
        if (trafficChart != null) {
            trafficChart.setHourlyData(
                    hourlyDownloadBytes,
                    hourlyUploadBytes,
                    Calendar.getInstance().get(Calendar.HOUR_OF_DAY));
        }
        updateDnsRecords();
    }

    private long currentVpnDownloadBytes() {
        return Math.max(0, NativeAgent.vpnDownloadBytes());
    }

    private long currentVpnUploadBytes() {
        return Math.max(0, NativeAgent.vpnUploadBytes());
    }

    private void updateDnsRecords() {
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
            addDnsEmptyRow("DNS records unavailable");
            return;
        }

        dnsRecordList.removeAllViews();
        if (records.length() == 0) {
            addDnsEmptyRow(running ? "Waiting for Agent DNS requests" : "VPN stopped");
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
            addDnsEmptyRow(running ? "Waiting for Agent DNS requests" : "VPN stopped");
        }
    }

    private boolean isAgentDnsRecord(JSONObject record) {
        return "agent".equals(record.optString("resolver", ""));
    }

    private void updateConnectivityButton() {
        if (connectivityTestButton == null) {
            return;
        }
        boolean running = isVpnRunning();
        connectivityTestButton.setEnabled(running && !connectivityTestsRunning);
        connectivityTestButton.setText(connectivityTestsRunning ? "Testing" : "Test");
        connectivityTestButton.setBackground(rounded(
                running ? COLOR_ACCENT : COLOR_STATUS_STOPPED,
                running ? COLOR_ACCENT : COLOR_STATUS_STOPPED));
        if (connectivitySummary != null && !running && !connectivityTestsRunning) {
            connectivitySummary.setText("Start VPN, then run tests");
        }
    }

    private void runConnectivityTests() {
        if (connectivityTestsRunning) {
            return;
        }
        if (!isVpnRunning()) {
            Toast.makeText(this, "Start VPN before running tests", Toast.LENGTH_SHORT).show();
            updateConnectivityButton();
            return;
        }

        connectivityTestsRunning = true;
        updateConnectivityButton();
        if (connectivitySummary != null) {
            connectivitySummary.setText("Testing Google and YouTube");
        }
        if (connectivityResultList != null) {
            connectivityResultList.removeAllViews();
            addConnectivityEmptyRow("Running HTTPS and QUIC checks");
        }

        new Thread(() -> {
            List<ConnectivityCheckResult> results = new ArrayList<>();
            results.add(runHttpsConnectivityCheck(
                    "Google",
                    "https://www.google.com/generate_204"));
            results.add(runHttpsConnectivityCheck(
                    "YouTube",
                    "https://www.youtube.com/generate_204"));
            results.add(runQuicConnectivityCheck("Google", "www.google.com"));
            results.add(runQuicConnectivityCheck("YouTube", "www.youtube.com"));

            runOnUiThread(() -> {
                connectivityTestsRunning = false;
                renderConnectivityResults(results);
                updateConnectivityButton();
            });
        }, "ppaass-connectivity-tests").start();
    }

    private ConnectivityCheckResult runHttpsConnectivityCheck(String target, String urlString) {
        long started = SystemClock.elapsedRealtime();
        long rxBefore = currentVpnDownloadBytes();
        long txBefore = currentVpnUploadBytes();
        HttpURLConnection connection = null;
        boolean networkOk = false;
        String detail;
        try {
            URL url = new URL(urlString);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTIVITY_TIMEOUT_MS);
            connection.setReadTimeout(CONNECTIVITY_TIMEOUT_MS);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "PPAASS-Android-Agent/diagnostic");

            int code = connection.getResponseCode();
            networkOk = code >= 200 && code < 400;
            drainSmallResponse(code >= 400 ? connection.getErrorStream() : connection.getInputStream());
            detail = "HTTP " + code;
        } catch (IOException | RuntimeException error) {
            detail = compactError(error);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return finishConnectivityResult(target, "HTTPS", networkOk, detail, started, rxBefore, txBefore);
    }

    private ConnectivityCheckResult runQuicConnectivityCheck(String target, String host) {
        long started = SystemClock.elapsedRealtime();
        long rxBefore = currentVpnDownloadBytes();
        long txBefore = currentVpnUploadBytes();
        boolean networkOk = false;
        String detail;

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(CONNECTIVITY_TIMEOUT_MS);
            InetAddress address = resolveIpv4(host);
            byte[] dcid = randomConnectionId();
            byte[] scid = randomConnectionId();
            byte[] probe = quicVersionNegotiationProbe(dcid, scid);
            DatagramPacket outbound = new DatagramPacket(probe, probe.length, address, 443);
            socket.send(outbound);

            byte[] response = new byte[1500];
            DatagramPacket inbound = new DatagramPacket(response, response.length);
            socket.receive(inbound);
            networkOk = isQuicVersionNegotiationResponse(response, inbound.getLength());
            detail = networkOk
                    ? "QUIC VN " + inbound.getLength() + " B from " + inbound.getAddress().getHostAddress()
                    : "UDP/443 replied, but not QUIC VN";
        } catch (SocketTimeoutException error) {
            detail = "UDP/443 timeout";
        } catch (IOException | RuntimeException error) {
            detail = compactError(error);
        }

        return finishConnectivityResult(target, "QUIC", networkOk, detail, started, rxBefore, txBefore);
    }

    private InetAddress resolveIpv4(String host) throws IOException {
        InetAddress[] addresses = InetAddress.getAllByName(host);
        for (InetAddress address : addresses) {
            if (address instanceof Inet4Address) {
                return address;
            }
        }
        if (addresses.length > 0) {
            return addresses[0];
        }
        throw new IOException("No address for " + host);
    }

    private ConnectivityCheckResult finishConnectivityResult(
            String target,
            String protocol,
            boolean networkOk,
            String detail,
            long started,
            long rxBefore,
            long txBefore) {
        long durationMs = Math.max(0, SystemClock.elapsedRealtime() - started);
        long rxDelta = Math.max(0, currentVpnDownloadBytes() - rxBefore);
        long txDelta = Math.max(0, currentVpnUploadBytes() - txBefore);
        boolean vpnObserved = rxDelta > 0 || txDelta > 0;
        boolean success = networkOk && vpnObserved;
        String resultDetail = networkOk && !vpnObserved
                ? detail + " · no VPN byte delta"
                : detail;
        return new ConnectivityCheckResult(
                target,
                protocol,
                success,
                resultDetail,
                durationMs,
                rxDelta,
                txDelta);
    }

    private void drainSmallResponse(InputStream stream) throws IOException {
        if (stream == null) {
            return;
        }
        try (InputStream input = stream) {
            byte[] buffer = new byte[256];
            input.read(buffer);
        }
    }

    private byte[] randomConnectionId() {
        byte[] value = new byte[8];
        SECURE_RANDOM.nextBytes(value);
        return value;
    }

    private byte[] quicVersionNegotiationProbe(byte[] dcid, byte[] scid) {
        byte[] packet = new byte[QUIC_MIN_INITIAL_PACKET_BYTES];
        SECURE_RANDOM.nextBytes(packet);
        int offset = 0;
        packet[offset++] = (byte) 0xc0;
        packet[offset++] = (byte) ((QUIC_RESERVED_VERSION >>> 24) & 0xff);
        packet[offset++] = (byte) ((QUIC_RESERVED_VERSION >>> 16) & 0xff);
        packet[offset++] = (byte) ((QUIC_RESERVED_VERSION >>> 8) & 0xff);
        packet[offset++] = (byte) (QUIC_RESERVED_VERSION & 0xff);
        packet[offset++] = (byte) dcid.length;
        System.arraycopy(dcid, 0, packet, offset, dcid.length);
        offset += dcid.length;
        packet[offset++] = (byte) scid.length;
        System.arraycopy(scid, 0, packet, offset, scid.length);
        return packet;
    }

    private boolean isQuicVersionNegotiationResponse(byte[] data, int length) {
        return length >= 7
                && (data[0] & 0x80) != 0
                && data[1] == 0
                && data[2] == 0
                && data[3] == 0
                && data[4] == 0;
    }

    private String compactError(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return error.getClass().getSimpleName();
        }
        return message.length() > 120 ? message.substring(0, 117) + "..." : message;
    }

    private void renderConnectivityResults(List<ConnectivityCheckResult> results) {
        if (connectivityResultList == null) {
            return;
        }
        connectivityResultList.removeAllViews();
        int passed = 0;
        for (ConnectivityCheckResult result : results) {
            if (result.success) {
                passed++;
            }
            addConnectivityResultRow(result);
        }
        if (connectivitySummary != null) {
            connectivitySummary.setText(passed + "/" + results.size() + " checks passed");
        }
    }

    private void addConnectivityEmptyRow(String text) {
        if (connectivityResultList == null) {
            return;
        }
        TextView empty = mutedText(text, 14f);
        empty.setGravity(Gravity.CENTER);
        empty.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        connectivityResultList.addView(empty, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(54)));
    }

    private void addConnectivityResultRow(ConnectivityCheckResult result) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(dp(10), dp(9), dp(10), dp(9));
        row.setMinimumHeight(dp(76));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        LinearLayout heading = horizontalRow();
        TextView name = titleText(result.target + " " + result.protocol, 14f);
        name.setSingleLine(true);
        name.setEllipsize(TextUtils.TruncateAt.END);
        heading.addView(name, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        TextView status = chip(result.success ? "PASS" : "FAIL",
                result.success ? COLOR_STATUS_RUNNING : COLOR_ACTION_STOP);
        heading.addView(status, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        row.addView(heading, matchWrap());

        TextView detail = mutedText(result.detail, 12f);
        detail.setMaxLines(2);
        detail.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams detailParams = matchWrap();
        detailParams.setMargins(0, dp(4), 0, 0);
        row.addView(detail, detailParams);

        TextView meta = mutedText(
                result.durationMs + " ms · VPN ↓" + formatBytes(result.rxDelta)
                        + " ↑" + formatBytes(result.txDelta),
                11f);
        LinearLayout.LayoutParams metaParams = matchWrap();
        metaParams.setMargins(0, dp(3), 0, 0);
        row.addView(meta, metaParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        if (connectivityResultList.getChildCount() > 0) {
            rowParams.setMargins(0, dp(8), 0, 0);
        }
        connectivityResultList.addView(row, rowParams);
    }

    private void addDnsEmptyRow(String text) {
        TextView empty = mutedText(text, 14f);
        empty.setGravity(Gravity.CENTER);
        empty.setTypeface(Typeface.DEFAULT_BOLD);
        empty.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
        dnsRecordList.addView(empty, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(72)));
    }

    private void addDnsRecordRow(JSONObject record) {
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

    private String dnsAnswerLabel(JSONObject record) {
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
            return "No answer records";
        }
        if ("TIMEOUT".equals(status)) {
            return "Query timeout";
        }
        return record.optString("upstream", "Agent DNS");
    }

    private boolean ensureTrafficDay(long rxBytes, long txBytes) {
        String today = new SimpleDateFormat("yyyyMMdd", Locale.US).format(new Date());
        String storedDay = prefs.getString(PREF_TRAFFIC_DAY, "");
        long storedBase = prefs.getLong(PREF_TRAFFIC_RX_BASE, rxBytes);
        long storedTxBase = prefs.getLong(PREF_TRAFFIC_TX_BASE, txBytes);
        if (today.equals(storedDay) && storedBase <= rxBytes && storedTxBase <= txBytes) {
            return false;
        }

        for (int i = 0; i < hourlyDownloadBytes.length; i++) {
            hourlyDownloadBytes[i] = 0;
            hourlyUploadBytes[i] = 0;
        }
        prefs.edit()
                .putString(PREF_TRAFFIC_DAY, today)
                .putLong(PREF_TRAFFIC_RX_BASE, rxBytes)
                .putLong(PREF_TRAFFIC_TX_BASE, txBytes)
                .putString(PREF_TRAFFIC_HOURLY, serializeHourlyTraffic(hourlyDownloadBytes))
                .putString(PREF_TRAFFIC_TX_HOURLY, serializeHourlyTraffic(hourlyUploadBytes))
                .apply();
        return true;
    }

    private void recordHourlyTraffic(long deltaRx, long deltaTx) {
        int hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
        hourlyDownloadBytes[hour] = Math.max(0, hourlyDownloadBytes[hour] + deltaRx);
        hourlyUploadBytes[hour] = Math.max(0, hourlyUploadBytes[hour] + deltaTx);
        prefs.edit()
                .putString(PREF_TRAFFIC_HOURLY, serializeHourlyTraffic(hourlyDownloadBytes))
                .putString(PREF_TRAFFIC_TX_HOURLY, serializeHourlyTraffic(hourlyUploadBytes))
                .apply();
    }

    private void loadHourlyTrafficState() {
        for (int i = 0; i < hourlyDownloadBytes.length; i++) {
            hourlyDownloadBytes[i] = 0;
            hourlyUploadBytes[i] = 0;
        }
        loadHourlyTraffic(PREF_TRAFFIC_HOURLY, hourlyDownloadBytes);
        loadHourlyTraffic(PREF_TRAFFIC_TX_HOURLY, hourlyUploadBytes);
    }

    private void loadHourlyTraffic(String key, long[] target) {
        String serialized = prefs == null ? "" : prefs.getString(key, "");
        if (serialized == null || serialized.isEmpty()) {
            return;
        }
        String[] parts = serialized.split(",");
        for (int i = 0; i < parts.length && i < target.length; i++) {
            try {
                target[i] = Math.max(0, Long.parseLong(parts[i]));
            } catch (NumberFormatException ignored) {
                target[i] = 0;
            }
        }
    }

    private String serializeHourlyTraffic(long[] values) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                builder.append(',');
            }
            builder.append(values[i]);
        }
        return builder.toString();
    }

    private String formatSpeed(long bytesPerSecond) {
        return formatBytes(bytesPerSecond) + "/s";
    }

    private String formatBytes(long bytes) {
        double value = Math.max(0, bytes);
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        int unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        if (unit == 0) {
            return String.format(Locale.US, "%.0f %s", value, units[unit]);
        }
        return String.format(Locale.US, "%.1f %s", value, units[unit]);
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
        String quicPolicyValue = selectedQuicPolicy();
        prefs.edit()
                .putString("proxy_addrs", proxyAddrs.getText().toString())
                .putString("username", username.getText().toString())
                .putString("private_key_pem", DefaultConfig.normalizePrivateKeyPem(privateKey.getText().toString()))
                .putString("tun_ipv4", DefaultConfig.TUN_IPV4)
                .putString("tun_ipv6", DefaultConfig.TUN_IPV6)
                .putString("mtu", String.valueOf(DefaultConfig.TUN_MTU))
                .putString("quic_policy", quicPolicyValue)
                .putString("runtime_threads", runtimeThreads.getText().toString())
                .putString("tcp_pool_size", tcpPoolSize.getText().toString())
                .putString("udp_pool_size", udpPoolSize.getText().toString())
                .putString("compression_mode", selectedCompressionMode())
                .putString("tcp_mode", selectedTcpMode())
                .putString("udp_mode", selectedUdpMode())
                .putString("direct_access_mode", selectedDirectAccessMode())
                .putString("direct_access_rules", serializeDirectAccessRules())
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

    private void restoreDefaultConfig() {
        if (isVpnRunning()) {
            Toast.makeText(this, "Stop VPN before changing config", Toast.LENGTH_SHORT).show();
            return;
        }

        proxyAddrs.setText(DefaultConfig.PROXY_ADDR);
        username.setText(DefaultConfig.USERNAME);
        privateKey.setText(DefaultConfig.normalizePrivateKeyPem(DefaultConfig.PRIVATE_KEY_PEM));
        setQuicPolicy(quicPolicy, DefaultConfig.QUIC_POLICY);
        runtimeThreads.setText(String.valueOf(DefaultConfig.RUNTIME_THREADS));
        tcpPoolSize.setText(String.valueOf(DefaultConfig.TCP_POOL_SIZE));
        udpPoolSize.setText(String.valueOf(DefaultConfig.UDP_POOL_SIZE));
        setSpinnerValue(compressionMode, DefaultConfig.COMPRESSION_MODE);
        setTransportMode(tcpMode, DefaultConfig.TCP_MODE);
        setTransportMode(udpMode, DefaultConfig.UDP_MODE);
        yamuxTcpSessions.setText(String.valueOf(DefaultConfig.TCP_YAMUX_SESSIONS));
        yamuxTcpMaxStreamsPerSession.setText(String.valueOf(DefaultConfig.TCP_YAMUX_MAX_STREAMS_PER_SESSION));
        yamuxTcpOpenStreamTimeoutSecs.setText(String.valueOf(DefaultConfig.TCP_YAMUX_OPEN_STREAM_TIMEOUT_SECS));
        yamuxTcpKeepaliveIntervalSecs.setText(String.valueOf(DefaultConfig.TCP_YAMUX_KEEPALIVE_INTERVAL_SECS));
        yamuxTcpConnectionWriteTimeoutSecs.setText(String.valueOf(DefaultConfig.TCP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS));
        yamuxTcpStreamWindowSizeKb.setText(String.valueOf(DefaultConfig.TCP_YAMUX_STREAM_WINDOW_SIZE_KB));
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

        updateTransportVisibility();
        updateDirectModeButtons();
        renderDirectRuleList();
        saveConfig();
        prefs.edit().putStringSet("vpn_apps", Collections.emptySet()).apply();
        updateSelectedAppsSummary();
        Toast.makeText(this, "Default config restored", Toast.LENGTH_SHORT).show();
    }

    private void setSpinnerValue(Spinner spinner, String value) {
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

    private void setTransportMode(Spinner spinner, String fallback) {
        if (spinner == null || spinner.getAdapter() == null) {
            return;
        }
        String normalized = normalizeTransportMode(fallback, fallback);
        for (int i = 0; i < spinner.getAdapter().getCount(); i++) {
            Object item = spinner.getAdapter().getItem(i);
            if (item instanceof TransportModeOption
                    && ((TransportModeOption) item).value.equalsIgnoreCase(normalized)) {
                spinner.setSelection(i);
                return;
            }
        }
        spinner.setSelection(0);
    }

    private void setQuicPolicy(Spinner spinner, String fallback) {
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

    private Spinner spinner(LinearLayout root, String title, String[] values, String selected) {
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

    private Spinner transportModeSpinner(LinearLayout root, String title, String selected) {
        root.addView(controlLabel(title), labelParams());
        Spinner spinner = new Spinner(this);
        ArrayAdapter<TransportModeOption> adapter = new ArrayAdapter<>(
                this,
                android.R.layout.simple_spinner_item,
                TRANSPORT_MODE_OPTIONS);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        int selectedIndex = 0;
        String normalized = normalizeTransportMode(selected, "auto");
        for (int i = 0; i < TRANSPORT_MODE_OPTIONS.length; i++) {
            if (TRANSPORT_MODE_OPTIONS[i].value.equalsIgnoreCase(normalized)) {
                selectedIndex = i;
                break;
            }
        }
        spinner.setSelection(selectedIndex);
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateTransportVisibility();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                updateTransportVisibility();
            }
        });
        spinner.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        spinner.setPadding(dp(12), 0, dp(12), 0);
        root.addView(spinner, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));
        trackEditable(spinner);
        return spinner;
    }

    private Spinner quicPolicySpinner(LinearLayout root, String title, String selected) {
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
        return spinner;
    }

    private void updateTransportVisibility() {
        setVisible(tcpPoolConfig, usesStandardPool(selectedTcpMode()));
        setVisible(udpPoolConfig, usesStandardPool(selectedUdpMode()));
        setVisible(tcpYamuxConfig, usesYamux(selectedTcpMode()));
        setVisible(udpYamuxConfig, usesYamux(selectedUdpMode()));
    }

    private void setVisible(View view, boolean visible) {
        if (view != null) {
            view.setVisibility(visible ? View.VISIBLE : View.GONE);
        }
    }

    private boolean usesYamux(String mode) {
        return "yamux".equals(mode) || "auto".equals(mode);
    }

    private boolean usesStandardPool(String mode) {
        return "legacy".equals(mode) || "auto".equals(mode);
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

    private String prefQuicPolicy() {
        String stored = prefs.getString("quic_policy", null);
        if (stored != null) {
            return normalizeQuicPolicy(stored);
        }
        return DefaultConfig.QUIC_POLICY;
    }

    private String selectedQuicPolicy() {
        if (quicPolicy == null || quicPolicy.getSelectedItem() == null) {
            return DefaultConfig.QUIC_POLICY;
        }
        Object selected = quicPolicy.getSelectedItem();
        if (selected instanceof QuicPolicyOption) {
            return normalizeQuicPolicy(((QuicPolicyOption) selected).value);
        }
        return normalizeQuicPolicy(selected.toString());
    }

    private String normalizeQuicPolicy(String value) {
        if (value == null) {
            return DefaultConfig.QUIC_POLICY;
        }
        String normalized = value.trim().toLowerCase();
        if ("allow".equals(normalized) || "block".equals(normalized)) {
            return normalized;
        }
        return DefaultConfig.QUIC_POLICY;
    }

    private String selectedDirectAccessMode() {
        return normalizeDirectAccessMode(directAccessModeValue);
    }

    private String selectedTransportMode(Spinner spinner, String fallback) {
        if (spinner == null || spinner.getSelectedItem() == null) {
            return fallback;
        }
        Object selected = spinner.getSelectedItem();
        if (selected instanceof TransportModeOption) {
            return ((TransportModeOption) selected).value;
        }
        String value = selected.toString().trim().toLowerCase();
        if ("standard channel".equals(value)) {
            return "legacy";
        }
        if ("yamux".equals(value) || "legacy".equals(value) || "auto".equals(value)) {
            return value;
        }
        return fallback;
    }

    private String normalizeTransportMode(String value, String fallback) {
        if (value == null) {
            return fallback;
        }
        String normalized = value.trim().toLowerCase();
        if ("auto".equals(normalized) || "yamux".equals(normalized) || "legacy".equals(normalized)) {
            return normalized;
        }
        if ("standard channel".equals(normalized)) {
            return "legacy";
        }
        return fallback;
    }

    private String prefString(String key, String fallback) {
        String value = prefs.getString(key, fallback);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        return value;
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

    private LinearLayout configSection(LinearLayout root, String title) {
        LinearLayout section = panel(root);
        section.setPadding(dp(18), dp(18), dp(18), dp(20));
        sectionTitle(section, title);
        return section;
    }

    private LinearLayout configGroup(LinearLayout root, String title, String appliesWhen) {
        LinearLayout group = new LinearLayout(this);
        group.setOrientation(LinearLayout.VERTICAL);
        group.setPadding(dp(12), dp(10), dp(12), dp(12));
        group.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        LinearLayout heading = horizontalRow();
        TextView titleView = titleText(title, 13f);
        heading.addView(titleView, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        TextView badge = chip(appliesWhen, COLOR_STATUS_STOPPED);
        heading.addView(badge, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        group.addView(heading, matchWrap());

        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(12), 0, 0);
        root.addView(group, params);
        return group;
    }

    private LinearLayout screenTabBar() {
        LinearLayout row = horizontalRow();
        row.setPadding(dp(4), dp(4), dp(4), dp(4));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        return row;
    }

    private LinearLayout screenPage(LinearLayout root) {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setVisibility(View.GONE);
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(14), 0, 0);
        root.addView(page, params);
        screenPages.add(page);
        return page;
    }

    private void addScreenTab(LinearLayout tabBar, String title, View page) {
        Button button = new Button(this);
        button.setText(title);
        button.setTextSize(14f);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(dp(8), 0, dp(8), 0);
        int index = screenTabButtons.size();
        button.setOnClickListener(view -> selectScreen(index));
        screenTabButtons.add(button);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(44), 1f);
        if (index > 0) {
            params.setMargins(dp(4), 0, 0, 0);
        }
        tabBar.addView(button, params);

        if (!screenPages.contains(page)) {
            screenPages.add(page);
        }
    }

    private void selectScreen(int selectedIndex) {
        for (int i = 0; i < screenPages.size(); i++) {
            screenPages.get(i).setVisibility(i == selectedIndex ? View.VISIBLE : View.GONE);
        }
        for (int i = 0; i < screenTabButtons.size(); i++) {
            Button button = screenTabButtons.get(i);
            boolean selected = i == selectedIndex;
            button.setTextColor(selected ? COLOR_ACCENT_DARK : COLOR_MUTED);
            button.setBackground(rounded(
                    selected ? COLOR_SURFACE : COLOR_CONTROL,
                    selected ? COLOR_SURFACE : COLOR_CONTROL));
            button.setElevation(selected ? dp(1) : 0);
        }
    }

    private TextView statusMetric(LinearLayout root, String label, String value, float valueSize) {
        TextView labelView = mutedText(label, 12f);
        LinearLayout.LayoutParams labelParams = matchWrap();
        labelParams.setMargins(0, dp(8), 0, dp(2));
        root.addView(labelView, labelParams);

        TextView valueView = titleText(value, valueSize);
        valueView.setSingleLine(true);
        valueView.setEllipsize(TextUtils.TruncateAt.END);
        root.addView(valueView, matchWrap());
        return valueView;
    }

    private TextView statusTile(LinearLayout row, String label, String value) {
        LinearLayout tile = new LinearLayout(this);
        tile.setOrientation(LinearLayout.VERTICAL);
        tile.setPadding(dp(12), dp(10), dp(12), dp(10));
        tile.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        TextView labelView = mutedText(label, 12f);
        tile.addView(labelView, matchWrap());

        TextView valueView = titleText(value, 18f);
        valueView.setSingleLine(true);
        valueView.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams valueParams = matchWrap();
        valueParams.setMargins(0, dp(2), 0, 0);
        tile.addView(valueView, valueParams);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(78), 1f);
        if (row.getChildCount() > 0) {
            params.setMargins(dp(10), 0, 0, 0);
        }
        row.addView(tile, params);
        return valueView;
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
        if (appSelectorDialog != null && appSelectorDialog.isShowing()) {
            return;
        }

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
        list.setDivider(null);
        list.setDividerHeight(0);
        list.setCacheColorHint(Color.TRANSPARENT);
        list.setSelector(rounded(COLOR_ACCENT_SOFT, COLOR_ACCENT_SOFT));

        TextView selectionSummary = chip(appSelectionSummary(checked), COLOR_STATUS_STOPPED);
        list.setOnItemClickListener((parent, view, position, id) -> {
            checked[position] = !checked[position];
            selectionSummary.setText(appSelectionSummary(checked));
            adapter.notifyDataSetChanged();
        });

        LinearLayout dialogContent = new LinearLayout(this);
        dialogContent.setOrientation(LinearLayout.VERTICAL);
        dialogContent.setPadding(dp(18), dp(16), dp(18), 0);

        LinearLayout titleRow = horizontalRow();
        TextView dialogTitle = titleText("VPN apps", 20f);
        titleRow.addView(dialogTitle, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        titleRow.addView(selectionSummary, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        dialogContent.addView(titleRow, matchWrap());

        TextView dialogSubtitle = mutedText("Only selected apps use the VPN path", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(4), 0, dp(12));
        dialogContent.addView(dialogSubtitle, subtitleParams);

        LinearLayout listShell = new LinearLayout(this);
        listShell.setOrientation(LinearLayout.VERTICAL);
        listShell.setPadding(dp(4), dp(4), dp(4), dp(4));
        listShell.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        listShell.addView(list, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(460)));
        dialogContent.addView(listShell, matchWrap());

        appSelectorDialog = new AlertDialog.Builder(this)
                .setView(dialogContent)
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
                .setNeutralButton("Clear all", null)
                .create();
        appSelectorDialog.setOnDismissListener(dialog -> appSelectorDialog = null);
        appSelectorDialog.setOnShowListener(dialog -> {
            appSelectorDialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(COLOR_ACCENT_DARK);
            appSelectorDialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(COLOR_MUTED);
            Button clearButton = appSelectorDialog.getButton(AlertDialog.BUTTON_NEUTRAL);
            clearButton.setTextColor(COLOR_ACTION_STOP);
            clearButton.setOnClickListener(view -> {
                for (int i = 0; i < checked.length; i++) {
                    checked[i] = false;
                }
                selectionSummary.setText(appSelectionSummary(checked));
                adapter.notifyDataSetChanged();
            });
        });
        appSelectorDialog.show();
    }

    private String appSelectionSummary(boolean[] checked) {
        int count = 0;
        for (boolean item : checked) {
            if (item) {
                count++;
            }
        }
        return count == 0 ? "All apps" : count + " selected";
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

    private final class SpeedGaugeView extends View {
        private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint progressPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF arcBounds = new RectF();
        private long rxBytesPerSecond;
        private long txBytesPerSecond;
        private boolean active;

        SpeedGaugeView() {
            super(MainActivity.this);
            trackPaint.setStyle(Paint.Style.STROKE);
            trackPaint.setStrokeCap(Paint.Cap.ROUND);
            trackPaint.setColor(COLOR_CONTROL);
            progressPaint.setStyle(Paint.Style.STROKE);
            progressPaint.setStrokeCap(Paint.Cap.ROUND);
            progressPaint.setColor(COLOR_ACCENT);
            textPaint.setTextAlign(Paint.Align.CENTER);
        }

        void setSpeeds(long rxBytesPerSecond, long txBytesPerSecond, boolean active) {
            this.rxBytesPerSecond = Math.max(0, rxBytesPerSecond);
            this.txBytesPerSecond = Math.max(0, txBytesPerSecond);
            this.active = active;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            int width = getWidth();
            int height = getHeight();
            float stroke = dp(16);
            float radius = Math.min(width * 0.38f, height * 0.50f);
            float centerX = width / 2f;
            float centerY = dp(28) + radius;
            arcBounds.set(centerX - radius, centerY - radius, centerX + radius, centerY + radius);

            trackPaint.setStrokeWidth(stroke);
            progressPaint.setStrokeWidth(stroke);
            canvas.drawArc(arcBounds, 150f, 240f, false, trackPaint);

            long totalSpeed = rxBytesPerSecond + txBytesPerSecond;
            long scale = gaugeScale(totalSpeed);
            float sweep = active ? Math.min(240f, totalSpeed * 240f / scale) : 0f;
            canvas.drawArc(arcBounds, 150f, sweep, false, progressPaint);

            textPaint.setTypeface(Typeface.DEFAULT_BOLD);
            textPaint.setColor(COLOR_TEXT);
            textPaint.setTextSize(dp(28));
            canvas.drawText(formatSpeed(totalSpeed), centerX, centerY + dp(4), textPaint);

            textPaint.setTypeface(Typeface.DEFAULT);
            textPaint.setColor(COLOR_MUTED);
            textPaint.setTextSize(dp(12));
            canvas.drawText(active ? "Realtime speed" : "VPN idle", centerX, centerY + dp(30), textPaint);
            canvas.drawText("Scale " + formatSpeed(scale), centerX, Math.min(height - dp(10), centerY + dp(54)), textPaint);
        }

        private long gaugeScale(long speed) {
            long scale = 64L * 1024L;
            while (speed > scale && scale < 1024L * 1024L * 1024L) {
                scale *= 2L;
            }
            return scale;
        }
    }

    private final class TrafficBarView extends View {
        private final Paint barPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF barBounds = new RectF();
        private final long[] downloadValues = new long[24];
        private final long[] uploadValues = new long[24];
        private int currentHour;

        TrafficBarView() {
            super(MainActivity.this);
            gridPaint.setColor(COLOR_BORDER);
            gridPaint.setStrokeWidth(dp(1));
            textPaint.setColor(COLOR_MUTED);
            textPaint.setTextSize(dp(10));
            textPaint.setTextAlign(Paint.Align.CENTER);
        }

        void setHourlyData(long[] hourlyDownloadValues, long[] hourlyUploadValues, int currentHour) {
            for (int i = 0; i < downloadValues.length; i++) {
                downloadValues[i] = i < hourlyDownloadValues.length ? Math.max(0, hourlyDownloadValues[i]) : 0;
                uploadValues[i] = i < hourlyUploadValues.length ? Math.max(0, hourlyUploadValues[i]) : 0;
            }
            this.currentHour = currentHour;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            int width = getWidth();
            int height = getHeight();
            float left = dp(6);
            float right = width - dp(6);
            float top = dp(28);
            float bottom = height - dp(24);
            float chartHeight = Math.max(dp(48), bottom - top);

            drawLegend(canvas, right - dp(146), dp(10), COLOR_ACCENT, "Down");
            drawLegend(canvas, right - dp(76), dp(10), COLOR_ACTION_START, "Up");

            for (int i = 0; i < 3; i++) {
                float y = top + chartHeight * i / 2f;
                canvas.drawLine(left, y, right, y, gridPaint);
            }

            long max = 0;
            for (int i = 0; i < downloadValues.length; i++) {
                max = Math.max(max, downloadValues[i]);
                max = Math.max(max, uploadValues[i]);
            }

            float gap = dp(3);
            float groupWidth = Math.max(dp(5), (right - left - gap * 23) / 24f);
            float barGap = dp(1);
            float barWidth = Math.max(dp(2), (groupWidth - barGap) / 2f);
            for (int i = 0; i < downloadValues.length; i++) {
                boolean highlighted = i == currentHour;
                float x = left + i * (groupWidth + gap);
                drawTrafficBar(canvas, downloadValues[i], max, x, bottom, chartHeight,
                        barWidth,
                        highlighted ? COLOR_ACCENT : Color.rgb(147, 197, 253));
                drawTrafficBar(canvas, uploadValues[i], max, x + barWidth + barGap, bottom, chartHeight,
                        barWidth,
                        highlighted ? COLOR_ACTION_START : Color.rgb(94, 234, 212));
            }

            canvas.drawText("00", left + barWidth / 2f, height - dp(6), textPaint);
            canvas.drawText("12", left + 12 * (groupWidth + gap) + groupWidth / 2f, height - dp(6), textPaint);
            canvas.drawText("23", right - groupWidth / 2f, height - dp(6), textPaint);
        }

        private void drawTrafficBar(
                Canvas canvas,
                long value,
                long max,
                float x,
                float bottom,
                float chartHeight,
                float barWidth,
                int color) {
            boolean hasValue = value > 0;
            float ratio = max == 0 ? 0f : value / (float) max;
            float barHeight = hasValue ? Math.max(dp(4), chartHeight * ratio) : dp(3);
            float y = bottom - barHeight;
            barPaint.setColor(hasValue ? color : COLOR_CONTROL);
            barBounds.set(x, y, x + barWidth, bottom);
            canvas.drawRoundRect(barBounds, dp(3), dp(3), barPaint);
        }

        private void drawLegend(Canvas canvas, float x, float y, int color, String label) {
            barPaint.setColor(color);
            barBounds.set(x, y, x + dp(10), y + dp(10));
            canvas.drawRoundRect(barBounds, dp(3), dp(3), barPaint);
            textPaint.setTextAlign(Paint.Align.LEFT);
            canvas.drawText(label, x + dp(14), y + dp(10), textPaint);
            textPaint.setTextAlign(Paint.Align.CENTER);
        }
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
                LinearLayout outer = new LinearLayout(MainActivity.this);
                outer.setOrientation(LinearLayout.VERTICAL);
                outer.setPadding(0, 0, 0, dp(4));

                LinearLayout container = new LinearLayout(MainActivity.this);
                container.setOrientation(LinearLayout.HORIZONTAL);
                container.setGravity(Gravity.CENTER_VERTICAL);
                container.setMinimumHeight(dp(68));
                container.setPadding(dp(12), dp(10), dp(12), dp(10));

                ImageView icon = new ImageView(MainActivity.this);
                icon.setPadding(dp(4), dp(4), dp(4), dp(4));
                icon.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
                LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(44), dp(44));
                iconParams.setMargins(0, 0, dp(12), 0);
                container.addView(icon, iconParams);

                LinearLayout textColumn = new LinearLayout(MainActivity.this);
                textColumn.setOrientation(LinearLayout.VERTICAL);

                LinearLayout labelRow = horizontalRow();
                TextView label = new TextView(MainActivity.this);
                label.setSingleLine(true);
                label.setEllipsize(TextUtils.TruncateAt.END);
                label.setTextSize(15f);
                label.setTypeface(Typeface.DEFAULT_BOLD);
                labelRow.addView(label, new LinearLayout.LayoutParams(
                        0,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        1f));

                TextView systemBadge = new TextView(MainActivity.this);
                systemBadge.setText("System");
                systemBadge.setTextSize(11f);
                systemBadge.setTextColor(COLOR_MUTED);
                systemBadge.setTypeface(Typeface.DEFAULT_BOLD);
                systemBadge.setPadding(dp(8), dp(2), dp(8), dp(2));
                systemBadge.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
                LinearLayout.LayoutParams badgeParams = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT);
                badgeParams.setMargins(dp(8), 0, 0, 0);
                labelRow.addView(systemBadge, badgeParams);
                textColumn.addView(labelRow, matchWrap());

                TextView packageName = new TextView(MainActivity.this);
                packageName.setSingleLine(true);
                packageName.setEllipsize(TextUtils.TruncateAt.END);
                packageName.setTextSize(12f);
                packageName.setTextColor(COLOR_MUTED);
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

                outer.addView(container, matchWrap());

                row = new AppRow(container, icon, label, packageName, systemBadge, checkBox);
                outer.setTag(row);
                convertView = outer;
            } else {
                row = (AppRow) convertView.getTag();
            }

            AppEntry app = getItem(position);
            boolean selected = checked[position];
            row.icon.setImageDrawable(app.icon);
            row.item.setBackground(rounded(
                    selected ? COLOR_ACCENT_SOFT : COLOR_SURFACE,
                    selected ? COLOR_ACCENT_SOFT : COLOR_BORDER));
            row.label.setText(app.label);
            row.label.setTextColor(selected ? COLOR_ACCENT_DARK : COLOR_TEXT);
            row.packageName.setText(app.packageName);
            row.systemBadge.setVisibility(app.systemApp ? View.VISIBLE : View.GONE);
            row.checkBox.setChecked(selected);
            return convertView;
        }
    }

    private static final class AppRow {
        final View item;
        final ImageView icon;
        final TextView label;
        final TextView packageName;
        final TextView systemBadge;
        final CheckBox checkBox;

        AppRow(
                View item,
                ImageView icon,
                TextView label,
                TextView packageName,
                TextView systemBadge,
                CheckBox checkBox) {
            this.item = item;
            this.icon = icon;
            this.label = label;
            this.packageName = packageName;
            this.systemBadge = systemBadge;
            this.checkBox = checkBox;
        }
    }

    private static final class ConnectivityCheckResult {
        final String target;
        final String protocol;
        final boolean success;
        final String detail;
        final long durationMs;
        final long rxDelta;
        final long txDelta;

        ConnectivityCheckResult(
                String target,
                String protocol,
                boolean success,
                String detail,
                long durationMs,
                long rxDelta,
                long txDelta) {
            this.target = target;
            this.protocol = protocol;
            this.success = success;
            this.detail = detail;
            this.durationMs = durationMs;
            this.rxDelta = rxDelta;
            this.txDelta = txDelta;
        }
    }

    private static final class TransportModeOption {
        final String value;
        final String label;

        TransportModeOption(String value, String label) {
            this.value = value;
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static final class QuicPolicyOption {
        final String value;
        final String label;

        QuicPolicyOption(String value, String label) {
            this.value = value;
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static final class MaxHeightScrollView extends ScrollView {
        private final int maxHeightPx;

        MaxHeightScrollView(Context context, int maxHeightPx) {
            super(context);
            this.maxHeightPx = maxHeightPx;
        }

        @Override
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int cappedHeightSpec = View.MeasureSpec.makeMeasureSpec(
                    maxHeightPx,
                    View.MeasureSpec.AT_MOST);
            super.onMeasure(widthMeasureSpec, cappedHeightSpec);
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
