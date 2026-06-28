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
abstract class MainActivityState extends Activity {
protected static final int VPN_PERMISSION_REQUEST = 1001;
protected static final String PREF_TRAFFIC_DAY = "traffic_day";
protected static final String PREF_TRAFFIC_RX_BASE = "traffic_rx_base";
protected static final String PREF_TRAFFIC_TX_BASE = "traffic_tx_base";
protected static final String PREF_TRAFFIC_HOURLY = "traffic_hourly";
protected static final String PREF_TRAFFIC_TX_HOURLY = "traffic_tx_hourly";
protected static final int COLOR_BACKGROUND = Color.rgb(239, 243, 249);
protected static final int COLOR_SURFACE = Color.WHITE;
protected static final int COLOR_CONTROL = Color.rgb(247, 249, 253);
protected static final int COLOR_TEXT = Color.rgb(35, 41, 53);
protected static final int COLOR_MUTED = Color.rgb(105, 113, 130);
protected static final int COLOR_BORDER = Color.rgb(207, 216, 232);
protected static final int COLOR_ACCENT = Color.rgb(229, 22, 112);
protected static final int COLOR_ACCENT_DARK = Color.rgb(21, 94, 232);
protected static final int COLOR_ACCENT_SOFT = Color.rgb(234, 241, 255);
protected static final int COLOR_ACTION_START = Color.rgb(242, 193, 0);
protected static final int COLOR_ACTION_START_SOFT = Color.rgb(255, 240, 166);
protected static final int COLOR_ACTION_INFO = Color.rgb(21, 94, 232);
protected static final int COLOR_ACTION_INFO_SOFT = Color.rgb(234, 241, 255);
protected static final int COLOR_ACTION_WARN = Color.rgb(229, 22, 112);
protected static final int COLOR_ACTION_WARN_SOFT = Color.rgb(255, 217, 234);
protected static final int COLOR_ACTION_STOP = Color.rgb(181, 17, 88);
protected static final int COLOR_ACTION_STOP_SOFT = Color.rgb(255, 217, 235);
protected static final int COLOR_STATUS_RUNNING = Color.rgb(35, 167, 125);
protected static final int COLOR_STATUS_STOPPED = Color.rgb(100, 116, 139);
protected static final int COLOR_STATUS_STOPPED_SOFT = Color.rgb(240, 243, 248);
protected static final int DIRECT_RULE_LIST_VISIBLE_RULES = 10;
protected static final int DIRECT_RULE_LIST_ROW_HEIGHT_DP = 36;
protected static final int DIRECT_RULE_LIST_CHROME_HEIGHT_DP = 44;
protected static final QuicPolicyOption[] QUIC_POLICY_OPTIONS = {
            new QuicPolicyOption("allow", "按规则处理，未命中走代理"),
            new QuicPolicyOption("block", "阻断 UDP/443")
    };
protected static final SecureRandom SECURE_RANDOM = new SecureRandom();
protected static final int CONNECTIVITY_TIMEOUT_MS = 8_000;
protected static final int QUIC_MIN_INITIAL_PACKET_BYTES = 1200;
protected static final int QUIC_RESERVED_VERSION = 0x0a0a0a0a;
protected SharedPreferences prefs;
protected EditText proxyAddrs;
protected EditText httpProxyPort;
protected EditText httpProxyThreads;
protected EditText httpProxyMaxConcurrentConnects;
protected EditText username;
protected EditText privateKey;
protected EditText runtimeThreads;
protected Spinner compressionMode;
protected LinearLayout udpYamuxConfig;
protected String directAccessModeValue;
protected EditText directRuleDraft;
protected LinearLayout directRuleGroupList;
protected LinearLayout directRulesConfig;
protected TextView directModeSummary;
protected TextView directRuleCountSummary;
protected TextView directRuleGroupSummary;
protected View directRuleCountFact;
protected final List<Button> directModeButtons = new ArrayList<>();
protected final List<String> directRuleValues = new ArrayList<>();
protected EditText yamuxUdpSessions;
protected EditText yamuxUdpMaxStreamsPerSession;
protected EditText yamuxUdpOpenStreamTimeoutSecs;
protected EditText yamuxUdpKeepaliveIntervalSecs;
protected EditText yamuxUdpConnectionWriteTimeoutSecs;
protected EditText yamuxUdpStreamWindowSizeKb;
protected Spinner quicPolicy;
protected TextView selectedAppsSummary;
protected Button selectAppsButton;
protected Button restoreDefaultsButton;
protected AlertDialog appSelectorDialog;
protected Button vpnToggle;
protected TextView vpnStatus;
protected Button httpProxyToggle;
protected Button httpProxyClientsButton;
protected LinearLayout httpProxyEndpointList;
protected LinearLayout httpProxyUsbEndpointList;
protected TextView httpProxyUsbHint;
protected Button httpProxyUsbSettingsButton;
protected Button httpProxyUsbActionButton;
protected LinearLayout httpProxyBluetoothEndpointList;
protected TextView httpProxyBluetoothHint;
protected Button httpProxyBluetoothActionButton;
protected TextView downloadSpeed;
protected TextView uploadSpeed;
protected TextView trafficDownload;
protected TextView trafficUpload;
protected LinearLayout dnsRecordList;
protected Button connectivityTestButton;
protected TextView connectivitySummary;
protected LinearLayout connectivityResultList;
protected SpeedGaugeView speedGauge;
protected TrafficBarView trafficChart;
protected final long[] hourlyDownloadBytes = new long[24];
protected final long[] hourlyUploadBytes = new long[24];
protected String lastVpnToggleLabel;
protected long lastRxBytes = -1;
protected long lastTxBytes = -1;
protected long lastTrafficSampleMs;
protected long lastHttpProxyRestoreAttemptMs;
protected String lastDnsRecordsStateKey = "";
protected boolean connectivityTestsRunning;
protected final List<View> editableControls = new ArrayList<>();
protected final List<Button> screenTabButtons = new ArrayList<>();
protected final List<View> screenPages = new ArrayList<>();
protected final List<Button> configTabButtons = new ArrayList<>();
protected final List<View> configTabPages = new ArrayList<>();
protected int selectedScreenIndex;
protected float screenSwipeStartX;
protected float screenSwipeStartY;
protected boolean screenSwipeTracking;
protected VelocityTracker screenSwipeVelocityTracker;
protected final Handler statusHandler = new Handler(Looper.getMainLooper());
protected final Runnable statusRefresh = new Runnable() {
        @Override
        public void run() {
            updateStatusMetrics();
            statusHandler.postDelayed(this, 1000);
        }
    };

    protected abstract void updateStatusMetrics();

    protected abstract void updateVpnToggle();

    protected abstract void updateHttpProxyToggle();

    protected abstract boolean isVpnRunning();

    protected abstract boolean isHttpProxyRunning();

    protected String formatSpeed(long bytesPerSecond) {
        return formatBytes(bytesPerSecond) + "/s";
    }

    protected String formatBytes(long bytes) {
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

    protected GradientDrawable rounded(int fill, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(16));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    protected void flattenButton(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            view.setStateListAnimator(null);
            view.setElevation(0f);
            view.setTranslationZ(0f);
        }
    }

    protected void trackEditable(View view) {
        editableControls.add(view);
    }

    protected LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    protected int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density);
    }

}
