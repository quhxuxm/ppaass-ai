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
import android.graphics.drawable.Drawable;
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
    private static final int COLOR_STOPPED = Color.rgb(46, 125, 50);
    private static final int COLOR_RUNNING = Color.rgb(211, 47, 47);

    private SharedPreferences prefs;
    private EditText proxyAddrs;
    private EditText username;
    private EditText privateKey;
    private EditText tcpPoolSize;
    private EditText udpPoolSize;
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
        prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
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

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setClipToPadding(false);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int horizontalPadding = dp(20);
        int topPadding = dp(32);
        int bottomPadding = dp(28);
        root.setPadding(horizontalPadding, topPadding, horizontalPadding, bottomPadding);
        applySystemBarPadding(root, horizontalPadding, topPadding, horizontalPadding, bottomPadding);
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText(getString(R.string.app_name));
        title.setTextSize(24f);
        root.addView(title, matchWrap());

        proxyAddrs = field(root, "Proxy addrs", prefs.getString("proxy_addrs", DefaultConfig.PROXY_ADDR));
        username = field(root, "Username", prefs.getString("username", DefaultConfig.USERNAME));
        privateKey = field(
                root,
                "Private key PEM",
                DefaultConfig.normalizePrivateKeyPem(prefs.getString("private_key_pem", DefaultConfig.PRIVATE_KEY_PEM)),
                8,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);

        blockQuic = new Switch(this);
        blockQuic.setText("Block QUIC");
        blockQuic.setChecked(prefs.getBoolean("block_quic", DefaultConfig.BLOCK_QUIC));
        root.addView(blockQuic, matchWrap());

        tcpPoolSize = field(
                root,
                "TCP pool size",
                prefs.getString("tcp_pool_size", String.valueOf(DefaultConfig.TCP_POOL_SIZE)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        udpPoolSize = field(
                root,
                "UDP pool size",
                prefs.getString("udp_pool_size", String.valueOf(DefaultConfig.UDP_POOL_SIZE)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        tcpMode = spinner(
                root,
                "TCP mode",
                new String[]{"auto", "yamux", "legacy"},
                prefs.getString("tcp_mode", DefaultConfig.TCP_MODE));
        udpMode = spinner(
                root,
                "UDP mode",
                new String[]{"auto", "yamux", "legacy"},
                prefs.getString("udp_mode", DefaultConfig.UDP_MODE));
        yamuxTcpSessions = field(
                root,
                "TCP Yamux sessions",
                prefs.getString(
                        "yamux_tcp_sessions",
                        String.valueOf(DefaultConfig.TCP_YAMUX_SESSIONS)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxTcpMaxStreamsPerSession = field(
                root,
                "TCP Yamux max streams/session",
                prefs.getString(
                        "yamux_tcp_max_streams_per_session",
                        String.valueOf(DefaultConfig.TCP_YAMUX_MAX_STREAMS_PER_SESSION)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxTcpOpenStreamTimeoutSecs = field(
                root,
                "TCP Yamux open stream timeout",
                prefs.getString(
                        "yamux_tcp_open_stream_timeout_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxTcpKeepaliveIntervalSecs = field(
                root,
                "TCP Yamux keepalive interval",
                prefs.getString(
                        "yamux_tcp_keepalive_interval_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxTcpConnectionWriteTimeoutSecs = field(
                root,
                "TCP Yamux write timeout",
                prefs.getString(
                        "yamux_tcp_connection_write_timeout_secs",
                        String.valueOf(DefaultConfig.TCP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxTcpStreamWindowSizeKb = field(
                root,
                "TCP Yamux stream window KB",
                prefs.getString(
                        "yamux_tcp_stream_window_size_kb",
                        String.valueOf(DefaultConfig.TCP_YAMUX_STREAM_WINDOW_SIZE_KB)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxUdpSessions = field(
                root,
                "UDP Yamux sessions",
                prefs.getString(
                        "yamux_udp_sessions",
                        String.valueOf(DefaultConfig.UDP_YAMUX_SESSIONS)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxUdpMaxStreamsPerSession = field(
                root,
                "UDP Yamux max streams/session",
                prefs.getString(
                        "yamux_udp_max_streams_per_session",
                        String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxUdpOpenStreamTimeoutSecs = field(
                root,
                "UDP Yamux open stream timeout",
                prefs.getString(
                        "yamux_udp_open_stream_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxUdpKeepaliveIntervalSecs = field(
                root,
                "UDP Yamux keepalive interval",
                prefs.getString(
                        "yamux_udp_keepalive_interval_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxUdpConnectionWriteTimeoutSecs = field(
                root,
                "UDP Yamux write timeout",
                prefs.getString(
                        "yamux_udp_connection_write_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
                1,
                InputType.TYPE_CLASS_NUMBER);
        yamuxUdpStreamWindowSizeKb = field(
                root,
                "UDP Yamux stream window KB",
                prefs.getString(
                        "yamux_udp_stream_window_size_kb",
                        String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB)),
                1,
                InputType.TYPE_CLASS_NUMBER);

        selectAppsButton = new Button(this);
        selectAppsButton.setText("Select VPN apps");
        selectAppsButton.setOnClickListener(view -> showAppSelector());
        selectedAppsSummary = new TextView(this);
        selectedAppsSummary.setTextSize(13f);
        selectedAppsSummary.setPadding(0, dp(4), 0, dp(10));
        updateSelectedAppsSummary();
        root.addView(selectAppsButton, matchWrap());
        root.addView(selectedAppsSummary, matchWrap());

        vpnToggle = new Button(this);
        vpnToggle.setOnClickListener(view -> toggleVpn());
        updateVpnToggle();
        root.addView(vpnToggle, matchWrap());

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
        vpnToggle.setBackgroundColor(running ? COLOR_RUNNING : COLOR_STOPPED);
        vpnToggle.setEnabled(!systemManaged);
        updateConfigEditability(!running);
    }

    private void updateConfigEditability(boolean editable) {
        updateEditTextEditable(proxyAddrs, editable);
        updateEditTextEditable(username, editable);
        updateEditTextEditable(privateKey, editable);
        updateEditTextEditable(tcpPoolSize, editable);
        updateEditTextEditable(udpPoolSize, editable);
        updateEditTextEditable(yamuxTcpSessions, editable);
        updateEditTextEditable(yamuxTcpMaxStreamsPerSession, editable);
        updateEditTextEditable(yamuxTcpOpenStreamTimeoutSecs, editable);
        updateEditTextEditable(yamuxTcpKeepaliveIntervalSecs, editable);
        updateEditTextEditable(yamuxTcpConnectionWriteTimeoutSecs, editable);
        updateEditTextEditable(yamuxTcpStreamWindowSizeKb, editable);
        updateEditTextEditable(yamuxUdpSessions, editable);
        updateEditTextEditable(yamuxUdpMaxStreamsPerSession, editable);
        updateEditTextEditable(yamuxUdpOpenStreamTimeoutSecs, editable);
        updateEditTextEditable(yamuxUdpKeepaliveIntervalSecs, editable);
        updateEditTextEditable(yamuxUdpConnectionWriteTimeoutSecs, editable);
        updateEditTextEditable(yamuxUdpStreamWindowSizeKb, editable);
        if (tcpMode != null) {
            tcpMode.setEnabled(editable);
        }
        if (udpMode != null) {
            udpMode.setEnabled(editable);
        }
        if (blockQuic != null) {
            blockQuic.setEnabled(editable);
        }
        if (selectAppsButton != null) {
            selectAppsButton.setEnabled(editable);
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
        root.addView(label(title), matchWrap());
        root.addView(spinner, matchWrap());
        return spinner;
    }

    private String selectedTcpMode() {
        return selectedTransportMode(tcpMode, DefaultConfig.TCP_MODE);
    }

    private String selectedUdpMode() {
        return selectedTransportMode(udpMode, DefaultConfig.UDP_MODE);
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
        EditText edit = new EditText(this);
        edit.setText(value == null ? "" : value);
        edit.setMinLines(lines);
        edit.setMaxLines(lines == 1 ? 1 : lines + 4);
        edit.setInputType(inputType);
        root.addView(label(title), matchWrap());
        root.addView(edit, matchWrap());
        return edit;
    }

    private TextView label(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(13f);
        view.setPadding(0, dp(14), 0, 0);
        return view;
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
            selectedAppsSummary.setText("No apps selected: all system traffic uses VPN. PPAASS Android Agent is excluded.");
            return;
        }

        selectedAppsSummary.setText(selected.size() + " app(s) selected: only selected apps use VPN.");
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
