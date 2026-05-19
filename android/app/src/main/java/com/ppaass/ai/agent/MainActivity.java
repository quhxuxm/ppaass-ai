package com.ppaass.ai.agent;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {
    private static final int VPN_PERMISSION_REQUEST = 1001;

    private SharedPreferences prefs;
    private EditText proxyAddrs;
    private EditText username;
    private EditText privateKey;
    private EditText tunIpv4;
    private EditText tunIpv6;
    private EditText mtu;
    private Switch blockQuic;
    private TextView selectedAppsSummary;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences("ppaass_agent", MODE_PRIVATE);
        buildUi();
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
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(20), dp(20), dp(28));
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
        tunIpv4 = field(root, "TUN IPv4 CIDR", prefs.getString("tun_ipv4", DefaultConfig.TUN_IPV4));
        tunIpv6 = field(root, "TUN IPv6 CIDR", prefs.getString("tun_ipv6", DefaultConfig.TUN_IPV6));
        mtu = field(root, "MTU", prefs.getString("mtu", "1500"), 1, InputType.TYPE_CLASS_NUMBER);

        blockQuic = new Switch(this);
        blockQuic.setText("Block QUIC");
        blockQuic.setChecked(prefs.getBoolean("block_quic", DefaultConfig.BLOCK_QUIC));
        root.addView(blockQuic, matchWrap());

        Button selectApps = new Button(this);
        selectApps.setText("Select VPN apps");
        selectApps.setOnClickListener(view -> showAppSelector());
        selectedAppsSummary = new TextView(this);
        selectedAppsSummary.setTextSize(13f);
        selectedAppsSummary.setPadding(0, dp(4), 0, dp(10));
        updateSelectedAppsSummary();
        root.addView(selectApps, matchWrap());
        root.addView(selectedAppsSummary, matchWrap());

        Button start = new Button(this);
        start.setText("Start");
        start.setOnClickListener(view -> {
            saveConfig();
            Intent permissionIntent = VpnService.prepare(this);
            if (permissionIntent != null) {
                startActivityForResult(permissionIntent, VPN_PERMISSION_REQUEST);
            } else {
                startVpnService();
            }
        });

        Button stop = new Button(this);
        stop.setText("Stop");
        stop.setOnClickListener(view -> {
            Intent intent = new Intent(this, PpaassVpnService.class);
            intent.setAction(PpaassVpnService.ACTION_STOP);
            startService(intent);
            status.setText("Stopped");
        });

        status = new TextView(this);
        status.setText("Idle");
        status.setTextSize(14f);
        root.addView(start, matchWrap());
        root.addView(stop, matchWrap());
        root.addView(status, matchWrap());

        setContentView(scroll);
    }

    private void startVpnService() {
        Intent intent = new Intent(this, PpaassVpnService.class);
        intent.setAction(PpaassVpnService.ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        status.setText("Starting");
    }

    private void saveConfig() {
        prefs.edit()
                .putString("proxy_addrs", proxyAddrs.getText().toString())
                .putString("username", username.getText().toString())
                .putString("private_key_pem", DefaultConfig.normalizePrivateKeyPem(privateKey.getText().toString()))
                .putString("tun_ipv4", tunIpv4.getText().toString())
                .putString("tun_ipv6", tunIpv6.getText().toString())
                .putString("mtu", mtu.getText().toString())
                .putBoolean("block_quic", blockQuic.isChecked())
                .apply();
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
        List<AppEntry> apps = loadLaunchableApps();
        Set<String> selected = selectedPackages();
        String[] labels = new String[apps.size()];
        boolean[] checked = new boolean[apps.size()];
        for (int i = 0; i < apps.size(); i++) {
            AppEntry app = apps.get(i);
            labels[i] = app.label + "\n" + app.packageName;
            checked[i] = selected.contains(app.packageName);
        }

        new AlertDialog.Builder(this)
                .setTitle("VPN apps")
                .setMultiChoiceItems(labels, checked, (dialog, which, isChecked) -> checked[which] = isChecked)
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

    private List<AppEntry> loadLaunchableApps() {
        PackageManager pm = getPackageManager();
        Intent launcher = new Intent(Intent.ACTION_MAIN);
        launcher.addCategory(Intent.CATEGORY_LAUNCHER);

        List<ResolveInfo> resolved = pm.queryIntentActivities(launcher, 0);
        List<AppEntry> apps = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (ResolveInfo info : resolved) {
            if (info.activityInfo == null || info.activityInfo.packageName == null) {
                continue;
            }
            String packageName = info.activityInfo.packageName;
            if (getPackageName().equals(packageName) || !seen.add(packageName)) {
                continue;
            }
            CharSequence label = info.loadLabel(pm);
            apps.add(new AppEntry(label == null ? packageName : label.toString(), packageName));
        }
        Collections.sort(apps, (left, right) -> left.label.compareToIgnoreCase(right.label));
        return apps;
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
            selectedAppsSummary.setText("All apps use VPN except PPAASS Agent.");
            return;
        }

        selectedAppsSummary.setText(selected.size() + " app(s) selected.");
    }

    private static final class AppEntry {
        final String label;
        final String packageName;

        AppEntry(String label, String packageName) {
            this.label = label;
            this.packageName = packageName;
        }
    }
}
