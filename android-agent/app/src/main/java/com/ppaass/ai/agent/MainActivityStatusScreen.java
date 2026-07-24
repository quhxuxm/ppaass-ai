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
abstract class MainActivityStatusScreen extends MainActivityRuntime {

protected void buildStatusScreen(LinearLayout root) {
        LinearLayout header = panel(root);
        header.setPadding(dp(18), dp(18), dp(18), dp(18));
        LinearLayout headerRow = horizontalRow();

        ImageView appIcon = new ImageView(this);
        appIcon.setImageResource(R.drawable.ic_vpn);
        appIcon.setColorFilter(COLOR_ACCENT);
        appIcon.setBackground(iconPlateBackground(COLOR_ACCENT));
        appIcon.setPadding(dp(10), dp(10), dp(10), dp(10));
        appIcon.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(48), dp(48));
        iconParams.setMargins(0, 0, dp(12), 0);
        headerRow.addView(appIcon, iconParams);

        LinearLayout titleColumn = new LinearLayout(this);
        titleColumn.setOrientation(LinearLayout.VERTICAL);
        TextView title = titleText(getString(R.string.app_name), 24f);
        titleColumn.addView(title, matchWrap());

        TextView subtitle = mutedText("系统状态", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(2), 0, 0);
        titleColumn.addView(subtitle, subtitleParams);

        vpnStatus = chip("未连接", COLOR_STATUS_STOPPED);
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        statusParams.setMargins(0, dp(10), 0, 0);
        titleColumn.addView(vpnStatus, statusParams);
        headerRow.addView(titleColumn, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        vpnToggle = actionButton("启动", COLOR_ACTION_START);
        vpnToggle.setOnClickListener(view -> toggleVpn());
        LinearLayout.LayoutParams toggleParams = new LinearLayout.LayoutParams(dp(112), dp(48));
        headerRow.addView(vpnToggle, toggleParams);
        header.addView(headerRow, matchWrap());

        LinearLayout apps = panel(root);
        sectionTitle(apps, "VPN 应用");

        selectAppsButton = new Button(this);
        selectAppsButton.setText("选择");
        selectAppsButton.setAllCaps(false);
        selectAppsButton.setTextSize(14f);
        selectAppsButton.setTypeface(Typeface.DEFAULT_BOLD);
        selectAppsButton.setTextColor(interactiveTextColors(
                COLOR_ACCENT_DARK,
                Color.rgb(245, 246, 255)));
        selectAppsButton.setSingleLine(true);
        selectAppsButton.setMinHeight(0);
        selectAppsButton.setMinWidth(0);
        selectAppsButton.setPadding(dp(14), 0, dp(14), 0);
        selectAppsButton.setBackground(interactiveRounded(
                COLOR_ACCENT_SOFT,
                alphaColor(COLOR_ACCENT, 112),
                COLOR_ACCENT));
        flattenButton(selectAppsButton);
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

        buildHttpProxyPanel(root);
        buildConnectivityPanel(root);

        LinearLayout dashboard = panel(root);
        sectionTitle(dashboard, "实时状态");
        speedGauge = new SpeedGaugeView(this);
        LinearLayout.LayoutParams gaugeParams = matchWrap();
        gaugeParams.height = dp(210);
        gaugeParams.setMargins(0, dp(6), 0, dp(12));
        dashboard.addView(speedGauge, gaugeParams);

        LinearLayout speedRow = horizontalRow();
        downloadSpeed = statusTile(speedRow, "下载", "0 B/s");
        uploadSpeed = statusTile(speedRow, "上传", "0 B/s");
        dashboard.addView(speedRow, matchWrap());

        LinearLayout dailyPanel = panel(root);
        sectionTitle(dailyPanel, "今日流量");
        trafficChart = new TrafficBarView(this);
        LinearLayout.LayoutParams chartParams = matchWrap();
        chartParams.height = dp(150);
        chartParams.setMargins(0, dp(8), 0, dp(10));
        dailyPanel.addView(trafficChart, chartParams);
        LinearLayout trafficRow = horizontalRow();
        trafficDownload = statusTile(trafficRow, "下载", "0 B");
        trafficUpload = statusTile(trafficRow, "上传", "0 B");
        dailyPanel.addView(trafficRow, matchWrap());

        LinearLayout dnsPanel = panel(root);
        dnsPanel.setPadding(dp(10), dp(16), dp(10), dp(12));
        sectionTitle(dnsPanel, "代理 DNS 记录");
        TextView dnsSubtitle = mutedText("最近 80 条 DNS", 13f);
        LinearLayout.LayoutParams dnsSubtitleParams = matchWrap();
        dnsSubtitleParams.setMargins(0, dp(2), 0, dp(10));
        dnsPanel.addView(dnsSubtitle, dnsSubtitleParams);

        dnsSelectionToolbar = horizontalRow();
        dnsSelectionToolbar.setGravity(Gravity.CENTER_VERTICAL);
        dnsSelectionToolbar.setPadding(dp(5), dp(5), dp(5), dp(5));
        dnsSelectionToolbar.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
        dnsSelectionToolbar.setVisibility(View.GONE);
        LinearLayout.LayoutParams dnsToolbarParams = matchWrap();
        dnsToolbarParams.setMargins(0, 0, 0, dp(7));
        dnsPanel.addView(dnsSelectionToolbar, dnsToolbarParams);

        MaxHeightScrollView dnsScroll = new MaxHeightScrollView(this, dp(440));
        dnsScroll.setVerticalScrollBarEnabled(false);
        dnsScroll.setPadding(0, 0, 0, 0);
        dnsScroll.setClipToPadding(true);
        dnsScroll.setClipToOutline(false);
        dnsScroll.setFillViewport(false);
        // 状态页本身位于外层 ScrollView 中。拖动 DNS 记录时由内层列表接管手势，
        // 到达列表边界或内容不足时再把手势交还外层页面，避免页面卡住。
        final float[] lastDnsTouchY = {0f};
        dnsScroll.setOnTouchListener((view, event) -> {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    lastDnsTouchY[0] = event.getY();
                    view.getParent().requestDisallowInterceptTouchEvent(
                            view.canScrollVertically(-1) || view.canScrollVertically(1));
                    break;
                case MotionEvent.ACTION_MOVE:
                    float currentY = event.getY();
                    int direction = currentY < lastDnsTouchY[0] ? 1 : -1;
                    view.getParent().requestDisallowInterceptTouchEvent(
                            view.canScrollVertically(direction));
                    lastDnsTouchY[0] = currentY;
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    view.getParent().requestDisallowInterceptTouchEvent(false);
                    break;
                default:
                    break;
            }
            return false;
        });
        FrameLayout dnsListContainer = new FrameLayout(this);
        dnsListContainer.setClipChildren(true);
        dnsListContainer.setClipToOutline(true);
        GradientDrawable dnsListSurface = new GradientDrawable();
        dnsListSurface.setColor(COLOR_SURFACE);
        dnsListSurface.setCornerRadius(dp(10));
        dnsListContainer.setBackground(dnsListSurface);
        GradientDrawable dnsListFrame = new GradientDrawable();
        dnsListFrame.setColor(Color.TRANSPARENT);
        dnsListFrame.setCornerRadius(dp(10));
        dnsListFrame.setStroke(dp(1), alphaColor(COLOR_BORDER, 112));
        dnsListContainer.setForegroundGravity(Gravity.FILL);
        dnsListContainer.setForeground(dnsListFrame);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            dnsScroll.setNestedScrollingEnabled(true);
        }
        dnsRecordList = new LinearLayout(this);
        dnsRecordList.setOrientation(LinearLayout.VERTICAL);
        dnsRecordList.setPadding(0, 0, 0, 0);
        dnsRecordList.setBackgroundColor(alphaColor(COLOR_BORDER, 72));
        dnsScroll.addView(dnsRecordList, matchWrap());
        dnsListContainer.addView(dnsScroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        dnsPanel.addView(dnsListContainer, matchWrap());
    }

protected void buildHttpProxyPanel(LinearLayout root) {
        LinearLayout panel = panel(root);
        sectionTitle(panel, "HTTP / SOCKS5 代理");
        TextView subtitle = mutedText("同端口支持 HTTP 与 SOCKS5", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(2), 0, dp(10));
        panel.addView(subtitle, subtitleParams);

        TextView wifiTitle = controlLabel("Wi-Fi / 热点共享入口");
        panel.addView(wifiTitle, labelParams());

        LinearLayout endpointBox = new LinearLayout(this);
        endpointBox.setOrientation(LinearLayout.VERTICAL);
        endpointBox.setPadding(dp(12), dp(10), dp(12), dp(10));
        endpointBox.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        httpProxyEndpointList = new LinearLayout(this);
        httpProxyEndpointList.setOrientation(LinearLayout.VERTICAL);
        MaxHeightScrollView endpointScroll = new MaxHeightScrollView(this, dp(138));
        endpointScroll.setVerticalScrollBarEnabled(true);
        endpointScroll.setScrollbarFadingEnabled(true);
        endpointScroll.setScrollBarStyle(View.SCROLLBARS_INSIDE_INSET);
        endpointScroll.setOnTouchListener((view, event) -> {
            view.getParent().requestDisallowInterceptTouchEvent(true);
            if (event.getAction() == MotionEvent.ACTION_UP
                    || event.getAction() == MotionEvent.ACTION_CANCEL) {
                view.getParent().requestDisallowInterceptTouchEvent(false);
            }
            return false;
        });
        endpointScroll.addView(httpProxyEndpointList, matchWrap());
        endpointBox.addView(endpointScroll, matchWrap());
        panel.addView(endpointBox, matchWrap());
        updateHttpProxyEndpoint();

        TextView hint = mutedText("同一网络使用上方地址", 12f);
        LinearLayout.LayoutParams hintParams = matchWrap();
        hintParams.setMargins(0, dp(6), 0, 0);
        panel.addView(hint, hintParams);

        TextView usbTitle = controlLabel("USB 电脑访问");
        panel.addView(usbTitle, labelParams());

        LinearLayout usbBox = new LinearLayout(this);
        usbBox.setOrientation(LinearLayout.VERTICAL);
        usbBox.setPadding(dp(12), dp(10), dp(12), dp(10));
        usbBox.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        httpProxyUsbEndpointList = new LinearLayout(this);
        httpProxyUsbEndpointList.setOrientation(LinearLayout.VERTICAL);
        MaxHeightScrollView usbScroll = new MaxHeightScrollView(this, dp(112));
        usbScroll.setVerticalScrollBarEnabled(true);
        usbScroll.setScrollbarFadingEnabled(true);
        usbScroll.setScrollBarStyle(View.SCROLLBARS_INSIDE_INSET);
        usbScroll.setOnTouchListener((view, event) -> {
            view.getParent().requestDisallowInterceptTouchEvent(true);
            if (event.getAction() == MotionEvent.ACTION_UP
                    || event.getAction() == MotionEvent.ACTION_CANCEL) {
                view.getParent().requestDisallowInterceptTouchEvent(false);
            }
            return false;
        });
        usbScroll.addView(httpProxyUsbEndpointList, matchWrap());
        usbBox.addView(usbScroll, matchWrap());
        panel.addView(usbBox, matchWrap());

        LinearLayout usbActionBlock = new LinearLayout(this);
        usbActionBlock.setOrientation(LinearLayout.VERTICAL);
        httpProxyUsbHint = mutedText("", 12f);
        usbActionBlock.addView(httpProxyUsbHint, matchWrap());

        LinearLayout usbButtonRow = horizontalRow();
        usbButtonRow.setGravity(Gravity.END);
        httpProxyUsbSettingsButton = secondaryButton("打开设置");
        httpProxyUsbSettingsButton.setOnClickListener(view -> openUsbTetherSettings());
        LinearLayout.LayoutParams usbSettingsParams = new LinearLayout.LayoutParams(dp(96), dp(38));
        usbButtonRow.addView(httpProxyUsbSettingsButton, usbSettingsParams);
        httpProxyUsbActionButton = secondaryButton("复制命令");
        httpProxyUsbActionButton.setOnClickListener(view -> handleHttpProxyUsbAction());
        LinearLayout.LayoutParams copyParams = new LinearLayout.LayoutParams(dp(96), dp(38));
        copyParams.setMargins(dp(6), 0, 0, 0);
        usbButtonRow.addView(httpProxyUsbActionButton, copyParams);
        LinearLayout.LayoutParams usbButtonParams = matchWrap();
        usbButtonParams.setMargins(0, dp(6), 0, 0);
        usbActionBlock.addView(usbButtonRow, usbButtonParams);
        LinearLayout.LayoutParams usbActionParams = matchWrap();
        usbActionParams.setMargins(0, dp(6), 0, 0);
        panel.addView(usbActionBlock, usbActionParams);
        updateHttpProxyUsbAccess();

        TextView bluetoothTitle = controlLabel("蓝牙电脑访问");
        panel.addView(bluetoothTitle, labelParams());

        LinearLayout bluetoothBox = new LinearLayout(this);
        bluetoothBox.setOrientation(LinearLayout.VERTICAL);
        bluetoothBox.setPadding(dp(12), dp(10), dp(12), dp(10));
        bluetoothBox.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        httpProxyBluetoothEndpointList = new LinearLayout(this);
        httpProxyBluetoothEndpointList.setOrientation(LinearLayout.VERTICAL);
        MaxHeightScrollView bluetoothScroll = new MaxHeightScrollView(this, dp(112));
        bluetoothScroll.setVerticalScrollBarEnabled(true);
        bluetoothScroll.setScrollbarFadingEnabled(true);
        bluetoothScroll.setScrollBarStyle(View.SCROLLBARS_INSIDE_INSET);
        bluetoothScroll.setOnTouchListener((view, event) -> {
            view.getParent().requestDisallowInterceptTouchEvent(true);
            if (event.getAction() == MotionEvent.ACTION_UP
                    || event.getAction() == MotionEvent.ACTION_CANCEL) {
                view.getParent().requestDisallowInterceptTouchEvent(false);
            }
            return false;
        });
        bluetoothScroll.addView(httpProxyBluetoothEndpointList, matchWrap());
        bluetoothBox.addView(bluetoothScroll, matchWrap());
        panel.addView(bluetoothBox, matchWrap());

        LinearLayout bluetoothActionBlock = new LinearLayout(this);
        bluetoothActionBlock.setOrientation(LinearLayout.VERTICAL);
        httpProxyBluetoothHint = mutedText("", 12f);
        bluetoothActionBlock.addView(httpProxyBluetoothHint, matchWrap());

        LinearLayout bluetoothButtonRow = horizontalRow();
        bluetoothButtonRow.setGravity(Gravity.END);
        httpProxyBluetoothActionButton = secondaryButton("打开设置");
        httpProxyBluetoothActionButton.setOnClickListener(view -> handleHttpProxyBluetoothAction());
        LinearLayout.LayoutParams bluetoothCopyParams = new LinearLayout.LayoutParams(dp(104), dp(38));
        bluetoothButtonRow.addView(httpProxyBluetoothActionButton, bluetoothCopyParams);
        LinearLayout.LayoutParams bluetoothButtonParams = matchWrap();
        bluetoothButtonParams.setMargins(0, dp(6), 0, 0);
        bluetoothActionBlock.addView(bluetoothButtonRow, bluetoothButtonParams);
        LinearLayout.LayoutParams bluetoothActionParams = matchWrap();
        bluetoothActionParams.setMargins(0, dp(6), 0, 0);
        panel.addView(bluetoothActionBlock, bluetoothActionParams);
        updateHttpProxyBluetoothAccess();

        LinearLayout buttonRow = horizontalRow();
        httpProxyToggle = actionButton("启动", COLOR_ACTION_START);
        httpProxyToggle.setOnClickListener(view -> toggleHttpProxy());
        buttonRow.addView(httpProxyToggle, new LinearLayout.LayoutParams(
                0,
                dp(48),
                1f));

        httpProxyClientsButton = actionButton("客户端", COLOR_ACTION_INFO);
        httpProxyClientsButton.setOnClickListener(view -> showHttpProxyClientsDialog());
        LinearLayout.LayoutParams clientsButtonParams = new LinearLayout.LayoutParams(
                0,
                dp(48),
                1f);
        clientsButtonParams.setMargins(dp(8), 0, 0, 0);
        buttonRow.addView(httpProxyClientsButton, clientsButtonParams);

        LinearLayout.LayoutParams buttonRowParams = matchWrap();
        buttonRowParams.setMargins(0, dp(12), 0, 0);
        panel.addView(buttonRow, buttonRowParams);
    }

protected void buildConnectivityPanel(LinearLayout root) {
        LinearLayout panel = panel(root);
        sectionTitle(panel, "VPN 连通性");
        TextView subtitle = mutedText("测试 VPN 的 HTTPS 与 QUIC", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(2), 0, dp(10));
        panel.addView(subtitle, subtitleParams);

        LinearLayout actionRow = horizontalRow();
        connectivitySummary = mutedText("启动 VPN 后运行测试", 13f);
        connectivitySummary.setTypeface(Typeface.DEFAULT_BOLD);
        actionRow.addView(connectivitySummary, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        connectivityTestButton = actionButton("测试", COLOR_ACTION_INFO);
        connectivityTestButton.setOnClickListener(view -> runConnectivityTests());
        actionRow.addView(connectivityTestButton, new LinearLayout.LayoutParams(dp(104), dp(42)));
        panel.addView(actionRow, matchWrap());

        connectivityResultList = new LinearLayout(this);
        connectivityResultList.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams resultParams = matchWrap();
        resultParams.setMargins(0, dp(10), 0, 0);
        panel.addView(connectivityResultList, resultParams);
        addConnectivityEmptyRow("尚未运行测试");
    }

}
