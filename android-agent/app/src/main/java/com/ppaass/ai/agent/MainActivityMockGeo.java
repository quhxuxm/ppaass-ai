package com.ppaass.ai.agent;

import android.Manifest;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.UUID;

/**
 * UI and permission flow for the device-wide mock-location feature.
 */
abstract class MainActivityMockGeo extends MainActivityAppSelector {
    protected static final int MOCK_GEO_LOCATION_PERMISSION_REQUEST = 1002;
    private static final String STATE_START_GEO_AFTER_LOCATION_PERMISSION =
            "start_geo_after_location_permission";
    private static final String STATE_START_GEO_AFTER_STALE_CLEANUP =
            "start_geo_after_stale_cleanup";

    private TextView mockGeoSummary;
    private TextView mockGeoStatus;
    private TextView mockGeoDetail;
    private Button mockGeoSettingsButton;
    private Button mockGeoToggleButton;
    private AlertDialog mockGeoDialog;
    private AlertDialog mockGeoSetupDialog;
    private boolean startMockGeoAfterLocationPermission;
    private boolean startMockGeoAfterStaleCleanup;
    private boolean mockGeoCleanupInFlight;

    protected void restoreMockGeoInstanceState(Bundle savedInstanceState) {
        if (savedInstanceState != null) {
            startMockGeoAfterLocationPermission = savedInstanceState.getBoolean(
                    STATE_START_GEO_AFTER_LOCATION_PERMISSION,
                    false);
            startMockGeoAfterStaleCleanup = savedInstanceState.getBoolean(
                    STATE_START_GEO_AFTER_STALE_CLEANUP,
                    false);
        }
    }

    protected void saveMockGeoInstanceState(Bundle outState) {
        outState.putBoolean(
                STATE_START_GEO_AFTER_LOCATION_PERMISSION,
                startMockGeoAfterLocationPermission);
        outState.putBoolean(
                STATE_START_GEO_AFTER_STALE_CLEANUP,
                startMockGeoAfterStaleCleanup);
    }

    protected void cleanupStaleMockGeoState() {
        if (prefs == null
                || mockGeoCleanupInFlight
                || PpaassVpnService.isMockGeoRunningInProcess()) {
            return;
        }
        boolean cleanupRequired =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false)
                        || prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false);
        if (!cleanupRequired) {
            if (prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)) {
                prefs.edit()
                        .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                        .apply();
            }
            return;
        }

        mockGeoCleanupInFlight = true;
        boolean googleFusedCleanupRequired = prefs.getBoolean(
                PpaassVpnService.PREF_MOCK_GEO_GOOGLE_FUSED_USED,
                true);
        String cleanupToken = UUID.randomUUID().toString();
        boolean cleanupMarkerStored = prefs.edit()
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false)
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, true)
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, true)
                .putString(PpaassVpnService.PREF_MOCK_GEO_SESSION_TOKEN, cleanupToken)
                .remove(PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND)
                .commit();
        if (!cleanupMarkerStored) {
            mockGeoCleanupInFlight = false;
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                    .putString(
                            PpaassVpnService.PREF_MOCK_GEO_ERROR,
                            "无法持久化模拟定位清理状态，请重试或重启设备")
                    .apply();
            return;
        }
        MockLocationController.cleanupResidualState(
                this,
                true,
                googleFusedCleanupRequired,
                null,
                (success, message) -> {
                    mockGeoCleanupInFlight = false;
                    String currentToken = MockGeoConfig.readString(
                            prefs,
                            PpaassVpnService.PREF_MOCK_GEO_SESSION_TOKEN,
                            "");
                    if (!cleanupToken.equals(currentToken)) {
                        startMockGeoAfterStaleCleanup = false;
                        return;
                    }

                    if (success) {
                        prefs.edit()
                                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false)
                                .remove(PpaassVpnService.PREF_MOCK_GEO_GOOGLE_FUSED_USED)
                                .remove(PpaassVpnService.PREF_MOCK_GEO_SESSION_TOKEN)
                                .remove(PpaassVpnService.PREF_MOCK_GEO_ERROR)
                                .apply();
                        boolean shouldStartGeo = startMockGeoAfterStaleCleanup
                                || prefs.getBoolean(
                                PpaassVpnService.PREF_MOCK_GEO_REQUESTED,
                                false);
                        startMockGeoAfterStaleCleanup = false;
                        if (shouldStartGeo && activityResumed) {
                            continuePendingMockGeoStart();
                        } else if (shouldStartGeo) {
                            prefs.edit()
                                    .putBoolean(
                                            PpaassVpnService
                                                    .PREF_MOCK_GEO_WAITING_FOR_FOREGROUND,
                                            true)
                                    .apply();
                        }
                    } else {
                        startMockGeoAfterStaleCleanup = false;
                        String cleanupMessage = message == null || message.trim().isEmpty()
                                ? "上次模拟定位未能完全清理，请重新授权后重试或重启设备"
                                : message.trim();
                        prefs.edit()
                                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, true)
                                .putString(
                                        PpaassVpnService.PREF_MOCK_GEO_ERROR,
                                        cleanupMessage)
                                .apply();
                    }
                    refreshMockGeoUi();
                });
    }

    protected void buildMockGeoPanel(LinearLayout root) {
        LinearLayout geo = panel(root);
        sectionTitle(geo, "模拟 GEO");

        TextView subtitle = mutedText("独立模拟 Android 系统定位，不依赖 VPN", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(2), 0, dp(10));
        geo.addView(subtitle, subtitleParams);

        LinearLayout summaryRow = horizontalRow();
        summaryRow.setGravity(Gravity.CENTER_VERTICAL);
        mockGeoSummary = new TextView(this);
        mockGeoSummary.setTextSize(16f);
        mockGeoSummary.setTypeface(Typeface.DEFAULT_BOLD);
        mockGeoSummary.setTextColor(COLOR_TEXT);
        mockGeoSummary.setMaxLines(3);
        summaryRow.addView(mockGeoSummary, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        Button selectButton = secondaryButton("选择地点");
        selectButton.setOnClickListener(view -> showMockGeoDialog());
        LinearLayout.LayoutParams selectParams = new LinearLayout.LayoutParams(dp(104), dp(42));
        selectParams.setMargins(dp(10), 0, 0, 0);
        summaryRow.addView(selectButton, selectParams);
        geo.addView(summaryRow, matchWrap());

        LinearLayout stateRow = horizontalRow();
        stateRow.setGravity(Gravity.CENTER_VERTICAL);
        mockGeoStatus = chip("已关闭", COLOR_STATUS_STOPPED);
        stateRow.addView(mockGeoStatus, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        stateRow.addView(new View(this), new LinearLayout.LayoutParams(
                0,
                1,
                1f));

        mockGeoSettingsButton = secondaryButton("开发者选项");
        mockGeoSettingsButton.setOnClickListener(view -> handleMockGeoSetupAction());
        LinearLayout.LayoutParams settingsParams = new LinearLayout.LayoutParams(dp(120), dp(38));
        settingsParams.setMargins(dp(8), 0, 0, 0);
        stateRow.addView(mockGeoSettingsButton, settingsParams);
        LinearLayout.LayoutParams stateRowParams = matchWrap();
        stateRowParams.setMargins(0, dp(10), 0, 0);
        geo.addView(stateRow, stateRowParams);

        mockGeoDetail = mutedText("", 12f);
        LinearLayout.LayoutParams detailParams = matchWrap();
        detailParams.setMargins(0, dp(8), 0, 0);
        geo.addView(mockGeoDetail, detailParams);

        mockGeoToggleButton = actionButton("启动 GEO", COLOR_ACTION_START);
        mockGeoToggleButton.setOnClickListener(view -> toggleMockGeo());
        LinearLayout.LayoutParams toggleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48));
        toggleParams.setMargins(0, dp(12), 0, 0);
        geo.addView(mockGeoToggleButton, toggleParams);

        TextView limitation = mutedText(
                "模拟定位是 Android 设备级能力，无法只限制到 VPN 应用列表，且应用可识别模拟标志。"
                        + "出口 IP 地区仍由所连接的代理节点决定。",
                12f);
        LinearLayout.LayoutParams limitationParams = matchWrap();
        limitationParams.setMargins(0, dp(10), 0, 0);
        geo.addView(limitation, limitationParams);

        refreshMockGeoUi();
    }

    private void toggleMockGeo() {
        boolean stopping =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false);
        if (stopping) {
            return;
        }
        boolean requested =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false);
        boolean active =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false);
        if (requested || active) {
            startMockGeoAfterLocationPermission = false;
            startMockGeoAfterStaleCleanup = false;
            stopMockGeoService();
            return;
        }
        beginMockGeoStart();
    }

    private void beginMockGeoStart() {
        MockGeoConfig.Selection selection = MockGeoConfig.load(prefs);
        if (!selection.enabled()) {
            startMockGeoAfterLocationPermission = false;
            Toast.makeText(this, "请先选择一个模拟地点", Toast.LENGTH_SHORT).show();
            showMockGeoDialog();
            return;
        }

        prefs.edit()
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, true)
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                .remove(PpaassVpnService.PREF_MOCK_GEO_ERROR)
                .remove(PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND)
                .apply();
        startMockGeoAfterLocationPermission = true;

        if (prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false)
                && !PpaassVpnService.isMockGeoRunningInProcess()) {
            startMockGeoAfterStaleCleanup = true;
            cleanupStaleMockGeoState();
            refreshMockGeoUi();
            return;
        }
        if (!MockLocationController.isSystemLocationEnabled(this)) {
            showSystemLocationSetupDialog();
            refreshMockGeoUi();
            return;
        }
        if (!MockLocationController.isSelectedMockLocationApp(this)) {
            showMockLocationSetupDialog();
            refreshMockGeoUi();
            return;
        }
        if (MockLocationController.needsLocationPermission(this)
                && !MockLocationController.hasLocationPermission(this)) {
            requestMockGeoLocationPermission();
            refreshMockGeoUi();
            return;
        }
        startMockGeoAfterLocationPermission = false;
        startMockGeoService();
    }

    private void continuePendingMockGeoStart() {
        if (!prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)) {
            startMockGeoAfterLocationPermission = false;
            return;
        }
        if (!activityResumed) {
            prefs.edit()
                    .putBoolean(
                            PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND,
                            true)
                    .apply();
            return;
        }
        MockGeoConfig.Selection selection = MockGeoConfig.load(prefs);
        if (!selection.enabled()) {
            startMockGeoAfterLocationPermission = false;
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)
                    .apply();
            refreshMockGeoUi();
            return;
        }
        if (prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false)
                && !PpaassVpnService.isMockGeoRunningInProcess()) {
            startMockGeoAfterStaleCleanup = true;
            cleanupStaleMockGeoState();
            return;
        }
        if (!MockLocationController.isSystemLocationEnabled(this)
                || !MockLocationController.isSelectedMockLocationApp(this)) {
            refreshMockGeoUi();
            return;
        }
        if (MockLocationController.needsLocationPermission(this)
                && !MockLocationController.hasLocationPermission(this)) {
            if (startMockGeoAfterLocationPermission) {
                requestMockGeoLocationPermission();
            }
            refreshMockGeoUi();
            return;
        }
        startMockGeoAfterLocationPermission = false;
        startMockGeoService();
    }

    protected boolean handleMockGeoPermissionResult(
            int requestCode,
            int[] grantResults) {
        if (requestCode != MOCK_GEO_LOCATION_PERMISSION_REQUEST) {
            return false;
        }
        boolean granted = false;
        for (int result : grantResults) {
            if (result == PackageManager.PERMISSION_GRANTED) {
                granted = true;
                break;
            }
        }
        if (!granted) {
            startMockGeoAfterLocationPermission = false;
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)
                    .remove(PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND)
                    .apply();
            if (isMockGeoLocationPermissionPermanentlyDenied()) {
                showLocationPermissionSettingsDialog();
            } else {
                Toast.makeText(
                        this,
                        "未获得定位权限，无法持续模拟 Android 定位",
                        Toast.LENGTH_LONG).show();
            }
            refreshMockGeoUi();
            return true;
        }

        boolean shouldStartGeo = startMockGeoAfterLocationPermission
                || prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false);
        startMockGeoAfterLocationPermission = false;
        if (prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false)
                && !PpaassVpnService.isMockGeoRunningInProcess()) {
            startMockGeoAfterStaleCleanup = shouldStartGeo;
            cleanupStaleMockGeoState();
        } else if (shouldStartGeo) {
            startMockGeoService();
        }
        refreshMockGeoUi();
        return true;
    }

    protected void syncMockGeoAfterResume() {
        refreshMockGeoUi();
        boolean requested =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false);
        boolean active =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false);
        boolean stopping =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false);
        if (requested
                && !active
                && !stopping
                && !PpaassVpnService.isMockGeoRunningInProcess()) {
            continuePendingMockGeoStart();
        }
    }

    protected void refreshMockGeoUi() {
        if (prefs == null || mockGeoSummary == null || mockGeoStatus == null) {
            return;
        }
        MockGeoConfig.Selection selection = MockGeoConfig.load(prefs);
        mockGeoSummary.setText(selection.summary());

        String detail;
        String status;
        int statusColor;
        boolean needsAction = false;
        String actionLabel = "";
        boolean requested =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false);
        boolean active =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false);
        boolean stopping =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false);
        boolean waitingForForeground = prefs.getBoolean(
                PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND,
                false);
        boolean dirty = prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false);
        boolean cleanupPending = dirty && !PpaassVpnService.isMockGeoRunningInProcess();
        String error = MockGeoConfig.readString(
                prefs,
                PpaassVpnService.PREF_MOCK_GEO_ERROR,
                "");

        if (stopping || mockGeoCleanupInFlight) {
            status = "停止中";
            statusColor = COLOR_ACTION_INFO;
            detail = "正在移除模拟定位并恢复设备真实定位";
        } else if (cleanupPending) {
            status = "需要清理";
            statusColor = COLOR_ACTION_WARN;
            needsAction = true;
            if (!MockLocationController.isSelectedMockLocationApp(this)) {
                actionLabel = "开发者选项";
            } else if (!MockLocationController.hasLocationPermission(this)) {
                actionLabel = "授予权限";
            } else {
                actionLabel = "重试清理";
            }
            detail = error == null || error.trim().isEmpty()
                    ? "正在清理由异常退出遗留的模拟定位"
                    : error.trim();
        } else if (!selection.enabled()) {
            status = "未选择地点";
            statusColor = COLOR_STATUS_STOPPED;
            detail = "请选择一个地点后再启动模拟 GEO";
        } else if (requested && !MockLocationController.isSystemLocationEnabled(this)) {
            status = "系统定位已关闭";
            statusColor = COLOR_ACTION_WARN;
            needsAction = true;
            actionLabel = "定位设置";
            detail = "需要先开启 Android 系统定位";
        } else if (requested && !MockLocationController.isSelectedMockLocationApp(this)) {
            status = "需要系统授权";
            statusColor = COLOR_ACTION_WARN;
            needsAction = true;
            actionLabel = "开发者选项";
            detail = "开发者选项 → 选择模拟位置信息应用 → PPAASS VPN";
        } else if (requested
                && MockLocationController.needsLocationPermission(this)
                && !MockLocationController.hasLocationPermission(this)) {
            status = "需要定位权限";
            statusColor = COLOR_ACTION_WARN;
            needsAction = true;
            actionLabel = "授予权限";
            detail = "Android 要求定位前台服务持有定位权限";
        } else if (active) {
            status = "模拟中";
            statusColor = COLOR_STATUS_RUNNING;
            detail = "GPS、网络定位和融合定位正在使用所选地点";
        } else if (requested && waitingForForeground) {
            status = "等待恢复";
            statusColor = COLOR_ACTION_INFO;
            detail = "打开应用后正在恢复模拟 GEO";
        } else if (requested) {
            status = "启动中";
            statusColor = COLOR_ACTION_INFO;
            detail = "正在接管 GPS、网络定位和融合定位";
        } else if (error != null && !error.trim().isEmpty()) {
            status = "启动失败";
            statusColor = COLOR_ACTION_STOP;
            detail = error.trim();
        } else {
            status = "已停止";
            statusColor = COLOR_STATUS_STOPPED;
            detail = "当前使用设备真实定位；已保留：" + selection.label;
        }

        mockGeoStatus.setText(status);
        mockGeoStatus.setTextColor(chipText(statusColor));
        mockGeoStatus.setBackground(rounded(
                chipFill(statusColor),
                alphaColor(statusColor, 112)));
        if (mockGeoDetail != null) {
            mockGeoDetail.setText(detail);
        }
        if (mockGeoSettingsButton != null) {
            mockGeoSettingsButton.setText(actionLabel);
            mockGeoSettingsButton.setVisibility(needsAction ? View.VISIBLE : View.GONE);
        }
        if (mockGeoToggleButton != null) {
            if (stopping || mockGeoCleanupInFlight) {
                mockGeoToggleButton.setText("停止中…");
                applyActionButtonStyle(mockGeoToggleButton, COLOR_ACTION_INFO);
                mockGeoToggleButton.setEnabled(false);
            } else if (requested || active) {
                mockGeoToggleButton.setText("停止 GEO");
                applyActionButtonStyle(mockGeoToggleButton, COLOR_ACTION_STOP);
                mockGeoToggleButton.setEnabled(true);
            } else {
                mockGeoToggleButton.setText("启动 GEO");
                applyActionButtonStyle(mockGeoToggleButton, COLOR_ACTION_START);
                mockGeoToggleButton.setEnabled(true);
            }
        }
    }

    protected void dismissMockGeoDialogs() {
        if (mockGeoDialog != null) {
            mockGeoDialog.dismiss();
            mockGeoDialog = null;
        }
        if (mockGeoSetupDialog != null) {
            mockGeoSetupDialog.dismiss();
            mockGeoSetupDialog = null;
        }
    }

    private void startMockGeoService() {
        MockGeoConfig.Selection selection = MockGeoConfig.load(prefs);
        if (!selection.enabled()) {
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)
                    .apply();
            refreshMockGeoUi();
            return;
        }
        if (PpaassVpnService.isMockGeoRunningInProcess()) {
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, true)
                    .apply();
            sendMockGeoUpdate();
            return;
        }
        if (deferMockGeoStartUntilCleanupCompletes()) {
            return;
        }
        if (!activityResumed) {
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, true)
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false)
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                    .putBoolean(
                            PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND,
                            true)
                    .apply();
            refreshMockGeoUi();
            return;
        }
        prefs.edit()
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, true)
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false)
                .remove(PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND)
                .remove(PpaassVpnService.PREF_MOCK_GEO_ERROR)
                .apply();
        Intent intent = new Intent(this, PpaassVpnService.class);
        intent.setAction(PpaassVpnService.ACTION_START_MOCK_GEO);
        intent.putExtra(PpaassVpnService.EXTRA_USER_VISIBLE, true);
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }
        } catch (RuntimeException error) {
            String message = error.getMessage();
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false)
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                    .remove(PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND)
                    .putString(
                            PpaassVpnService.PREF_MOCK_GEO_ERROR,
                            message == null || message.trim().isEmpty()
                                    ? "系统暂时不允许启动模拟 GEO，请重试"
                                    : "模拟 GEO 启动失败：" + message.trim())
                    .apply();
        }
        refreshMockGeoUi();
    }

    protected void stopMockGeoService() {
        prefs.edit()
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, true)
                .remove(PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND)
                .remove(PpaassVpnService.PREF_MOCK_GEO_ERROR)
                .apply();
        Intent intent = new Intent(this, PpaassVpnService.class);
        intent.setAction(PpaassVpnService.ACTION_STOP_MOCK_GEO);
        intent.putExtra(PpaassVpnService.EXTRA_USER_VISIBLE, true);
        startService(intent);
        refreshMockGeoUi();
    }

    protected void requestRunningMockGeoRefresh() {
        if (!prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)) {
            return;
        }
        if (PpaassVpnService.isMockGeoRunningInProcess()) {
            sendMockGeoUpdate();
            return;
        }
        if (deferMockGeoStartUntilCleanupCompletes()) {
            return;
        }
        startMockGeoService();
    }

    private void sendMockGeoUpdate() {
        Intent intent = new Intent(this, PpaassVpnService.class);
        intent.setAction(PpaassVpnService.ACTION_UPDATE_MOCK_GEO);
        intent.putExtra(PpaassVpnService.EXTRA_USER_VISIBLE, true);
        startService(intent);
    }

    private boolean deferMockGeoStartUntilCleanupCompletes() {
        boolean dirty = prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false);
        boolean active = prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false);
        boolean stopping =
                prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false);
        if (!mockGeoCleanupInFlight && stopping && !dirty && !active) {
            // Normalize a marker left by a process which died after cleanup completed.
            prefs.edit()
                    .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                    .apply();
            stopping = false;
        }
        if (!mockGeoCleanupInFlight && !dirty && !active && !stopping) {
            return false;
        }

        startMockGeoAfterStaleCleanup = true;
        prefs.edit()
                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, true)
                .putBoolean(
                        PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND,
                        true)
                .remove(PpaassVpnService.PREF_MOCK_GEO_ERROR)
                .apply();
        if (!mockGeoCleanupInFlight && !PpaassVpnService.isMockGeoRunningInProcess()) {
            cleanupStaleMockGeoState();
        }
        refreshMockGeoUi();
        return true;
    }

    private void showMockGeoDialog() {
        if (mockGeoDialog != null && mockGeoDialog.isShowing()) {
            return;
        }

        MockGeoConfig.Selection saved = MockGeoConfig.load(prefs);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(16), dp(24), dp(16));

        TextView title = titleText("选择模拟 GEO", 20f);
        content.addView(title, matchWrap());
        TextView subtitle = mutedText("可选常用城市，也可以输入自定义经纬度", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(4), 0, dp(8));
        content.addView(subtitle, subtitleParams);

        content.addView(controlLabel("位置"), labelParams());
        Spinner modeSpinner = new Spinner(this);
        modeSpinner.setAdapter(spinnerAdapter(MockGeoConfig.optionLabels()));
        modeSpinner.setBackground(controlFillBackground());
        modeSpinner.setPopupBackgroundDrawable(roundedFill(COLOR_SURFACE));
        modeSpinner.setPadding(dp(12), 0, dp(12), 0);
        content.addView(modeSpinner, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));

        LinearLayout coordinateGroup = new LinearLayout(this);
        coordinateGroup.setOrientation(LinearLayout.VERTICAL);
        EditText latitude = geoInput(
                coordinateGroup,
                "纬度",
                MockGeoConfig.formatCoordinate(saved.enabled()
                        ? saved.latitude
                        : MockGeoConfig.DEFAULT_CUSTOM_LATITUDE));
        EditText longitude = geoInput(
                coordinateGroup,
                "经度",
                MockGeoConfig.formatCoordinate(saved.enabled()
                        ? saved.longitude
                        : MockGeoConfig.DEFAULT_CUSTOM_LONGITUDE));
        EditText accuracy = geoInput(
                coordinateGroup,
                "精度（米）",
                MockGeoConfig.formatAccuracy(saved.accuracyMeters));
        content.addView(coordinateGroup, matchWrap());

        final String[] customLatitude = {
                MockGeoConfig.readString(
                        prefs,
                        MockGeoConfig.PREF_CUSTOM_LATITUDE,
                        MockGeoConfig.formatCoordinate(MockGeoConfig.DEFAULT_CUSTOM_LATITUDE))
        };
        final String[] customLongitude = {
                MockGeoConfig.readString(
                        prefs,
                        MockGeoConfig.PREF_CUSTOM_LONGITUDE,
                        MockGeoConfig.formatCoordinate(MockGeoConfig.DEFAULT_CUSTOM_LONGITUDE))
        };
        final String[] previousMode = {MockGeoConfig.normalizeMode(saved.mode)};

        modeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (MockGeoConfig.MODE_CUSTOM.equals(previousMode[0])) {
                    customLatitude[0] = latitude.getText().toString();
                    customLongitude[0] = longitude.getText().toString();
                }

                String mode = MockGeoConfig.modeForOptionIndex(position);
                boolean enabled = !MockGeoConfig.MODE_OFF.equals(mode);
                boolean custom = MockGeoConfig.MODE_CUSTOM.equals(mode);
                coordinateGroup.setVisibility(enabled ? View.VISIBLE : View.GONE);
                updateGeoInputEditability(latitude, custom);
                updateGeoInputEditability(longitude, custom);
                if (custom) {
                    latitude.setText(customLatitude[0]);
                    longitude.setText(customLongitude[0]);
                } else {
                    MockGeoConfig.Preset preset = MockGeoConfig.presetForMode(mode);
                    if (preset != null) {
                        latitude.setText(MockGeoConfig.formatCoordinate(preset.latitude));
                        longitude.setText(MockGeoConfig.formatCoordinate(preset.longitude));
                    }
                }
                previousMode[0] = mode;
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
        int initialModeIndex = MockGeoConfig.optionIndexForMode(saved.mode);
        modeSpinner.setSelection(initialModeIndex, false);
        String initialMode = MockGeoConfig.modeForOptionIndex(initialModeIndex);
        boolean initialEnabled = !MockGeoConfig.MODE_OFF.equals(initialMode);
        boolean initialCustom = MockGeoConfig.MODE_CUSTOM.equals(initialMode);
        coordinateGroup.setVisibility(initialEnabled ? View.VISIBLE : View.GONE);
        updateGeoInputEditability(latitude, initialCustom);
        updateGeoInputEditability(longitude, initialCustom);

        MaxHeightScrollView scroll = new MaxHeightScrollView(this, dp(560));
        scroll.addView(content);
        mockGeoDialog = new AlertDialog.Builder(this)
                .setView(scroll)
                .setPositiveButton("应用", null)
                .setNegativeButton("取消", null)
                .create();
        mockGeoDialog.setOnDismissListener(dialog -> mockGeoDialog = null);
        mockGeoDialog.setOnShowListener(dialog -> {
            Window window = mockGeoDialog.getWindow();
            if (window != null) {
                // 只勾勒对话框最外层；表单内部保持无额外容器描边。
                window.setBackgroundDrawable(rounded(COLOR_SURFACE, COLOR_BORDER));
            }
            Button positive = mockGeoDialog.getButton(AlertDialog.BUTTON_POSITIVE);
            positive.setTextColor(COLOR_ACCENT_DARK);
            positive.setOnClickListener(view -> {
                String mode = MockGeoConfig.modeForOptionIndex(modeSpinner.getSelectedItemPosition());
                final MockGeoConfig.Selection selection;
                try {
                    selection = MockGeoConfig.selectionForInput(
                            mode,
                            latitude.getText().toString(),
                            longitude.getText().toString(),
                            accuracy.getText().toString());
                } catch (IllegalArgumentException error) {
                    Toast.makeText(this, error.getMessage(), Toast.LENGTH_LONG).show();
                    return;
                }

                MockGeoConfig.save(prefs, selection);
                mockGeoDialog.dismiss();

                if (!selection.enabled()) {
                    startMockGeoAfterLocationPermission = false;
                    startMockGeoAfterStaleCleanup = false;
                    boolean needsStop = prefs.getBoolean(
                            PpaassVpnService.PREF_MOCK_GEO_REQUESTED,
                            false)
                            || prefs.getBoolean(
                            PpaassVpnService.PREF_MOCK_GEO_ACTIVE,
                            false)
                            || prefs.getBoolean(
                            PpaassVpnService.PREF_MOCK_GEO_DIRTY,
                            false);
                    if (needsStop) {
                        if (!prefs.getBoolean(
                                PpaassVpnService.PREF_MOCK_GEO_STOPPING,
                                false)
                                && !mockGeoCleanupInFlight) {
                            stopMockGeoService();
                        } else {
                            refreshMockGeoUi();
                        }
                    } else {
                        prefs.edit()
                                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)
                                .putBoolean(PpaassVpnService.PREF_MOCK_GEO_STOPPING, false)
                                .remove(PpaassVpnService.PREF_MOCK_GEO_ERROR)
                                .remove(PpaassVpnService.PREF_MOCK_GEO_WAITING_FOR_FOREGROUND)
                                .apply();
                        refreshMockGeoUi();
                    }
                    Toast.makeText(this, "已清除模拟地点", Toast.LENGTH_SHORT).show();
                } else if (prefs.getBoolean(
                        PpaassVpnService.PREF_MOCK_GEO_REQUESTED,
                        false)) {
                    requestRunningMockGeoRefresh();
                    Toast.makeText(this, "正在切换模拟地点", Toast.LENGTH_SHORT).show();
                } else {
                    prefs.edit()
                            .remove(PpaassVpnService.PREF_MOCK_GEO_ERROR)
                            .apply();
                    refreshMockGeoUi();
                    Toast.makeText(this, "地点已保存，点击“启动 GEO”后生效", Toast.LENGTH_SHORT)
                            .show();
                }
            });
            mockGeoDialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(COLOR_MUTED);
        });
        mockGeoDialog.show();
    }

    private EditText geoInput(LinearLayout root, String title, String value) {
        root.addView(controlLabel(title), labelParams());
        EditText input = new EditText(this);
        input.setText(value);
        input.setSingleLine(true);
        input.setTextSize(15f);
        input.setPadding(dp(12), 0, dp(12), 0);
        input.setInputType(InputType.TYPE_CLASS_NUMBER
                | InputType.TYPE_NUMBER_FLAG_DECIMAL
                | InputType.TYPE_NUMBER_FLAG_SIGNED);
        styleInput(input);
        input.setBackground(controlFillBackground());
        root.addView(input, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));
        return input;
    }

    private void updateGeoInputEditability(EditText input, boolean editable) {
        input.setEnabled(editable);
        input.setFocusable(editable);
        input.setFocusableInTouchMode(editable);
        input.setCursorVisible(editable);
    }

    private void requestMockGeoLocationPermission() {
        requestPermissions(
                new String[]{
                        Manifest.permission.ACCESS_FINE_LOCATION,
                        Manifest.permission.ACCESS_COARSE_LOCATION
                },
                MOCK_GEO_LOCATION_PERMISSION_REQUEST);
    }

    private boolean isMockGeoLocationPermissionPermanentlyDenied() {
        return !shouldShowRequestPermissionRationale(Manifest.permission.ACCESS_FINE_LOCATION)
                && !shouldShowRequestPermissionRationale(
                Manifest.permission.ACCESS_COARSE_LOCATION);
    }

    private void showLocationPermissionSettingsDialog() {
        if (mockGeoSetupDialog != null && mockGeoSetupDialog.isShowing()) {
            return;
        }
        mockGeoSetupDialog = new AlertDialog.Builder(this)
                .setTitle("允许定位权限")
                .setMessage("定位权限已被系统设为不再询问。请在应用设置的“权限”中允许定位。")
                .setPositiveButton("打开应用设置", (dialog, which) -> openAppSettings())
                .setNegativeButton("稍后", null)
                .create();
        mockGeoSetupDialog.setOnDismissListener(dialog -> mockGeoSetupDialog = null);
        mockGeoSetupDialog.show();
    }

    private void showMockLocationSetupDialog() {
        if (mockGeoSetupDialog != null && mockGeoSetupDialog.isShowing()) {
            return;
        }
        mockGeoSetupDialog = new AlertDialog.Builder(this)
                .setTitle("启用 Android 模拟定位")
                .setMessage(
                        "1. 打开开发者选项\n"
                                + "2. 进入“选择模拟位置信息应用”\n"
                                + "3. 选择 PPAASS VPN\n\n"
                                + "这是 Android 的系统限制，应用不能代替你完成授权。")
                .setPositiveButton("打开开发者选项", (dialog, which) -> openDeveloperOptions())
                .setNegativeButton("稍后", null)
                .create();
        mockGeoSetupDialog.setOnDismissListener(dialog -> mockGeoSetupDialog = null);
        mockGeoSetupDialog.show();
    }

    private void showSystemLocationSetupDialog() {
        if (mockGeoSetupDialog != null && mockGeoSetupDialog.isShowing()) {
            return;
        }
        mockGeoSetupDialog = new AlertDialog.Builder(this)
                .setTitle("开启系统定位")
                .setMessage("Android 的系统定位当前已关闭，开启后才能向应用提供模拟坐标。")
                .setPositiveButton("打开定位设置", (dialog, which) -> openLocationSettings())
                .setNegativeButton("稍后", null)
                .create();
        mockGeoSetupDialog.setOnDismissListener(dialog -> mockGeoSetupDialog = null);
        mockGeoSetupDialog.show();
    }

    private void handleMockGeoSetupAction() {
        if (prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false)) {
            if (!MockLocationController.isSelectedMockLocationApp(this)) {
                showMockLocationSetupDialog();
            } else if (!MockLocationController.hasLocationPermission(this)) {
                startMockGeoAfterLocationPermission = prefs.getBoolean(
                        PpaassVpnService.PREF_MOCK_GEO_REQUESTED,
                        false);
                requestMockGeoLocationPermission();
            } else {
                cleanupStaleMockGeoState();
            }
            return;
        }
        if (!MockLocationController.isSystemLocationEnabled(this)) {
            openLocationSettings();
        } else if (!MockLocationController.isSelectedMockLocationApp(this)) {
            showMockLocationSetupDialog();
        } else if (MockLocationController.needsLocationPermission(this)
                && !MockLocationController.hasLocationPermission(this)) {
            startMockGeoAfterLocationPermission = prefs.getBoolean(
                    PpaassVpnService.PREF_MOCK_GEO_REQUESTED,
                    false);
            requestMockGeoLocationPermission();
        }
    }

    private void openLocationSettings() {
        try {
            startActivity(new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS));
        } catch (RuntimeException error) {
            try {
                startActivity(new Intent(Settings.ACTION_SETTINGS));
            } catch (RuntimeException ignored) {
                Toast.makeText(this, "无法打开定位设置", Toast.LENGTH_LONG).show();
            }
        }
    }

    private void openDeveloperOptions() {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS);
        try {
            startActivity(intent);
        } catch (RuntimeException error) {
            try {
                startActivity(new Intent(Settings.ACTION_SETTINGS));
            } catch (RuntimeException ignored) {
                Toast.makeText(this, "无法打开系统设置", Toast.LENGTH_LONG).show();
            }
        }
    }

    private void openAppSettings() {
        Intent intent = new Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", getPackageName(), null));
        try {
            startActivity(intent);
        } catch (RuntimeException error) {
            try {
                startActivity(new Intent(Settings.ACTION_SETTINGS));
            } catch (RuntimeException ignored) {
                Toast.makeText(this, "无法打开应用设置", Toast.LENGTH_LONG).show();
            }
        }
    }
}
