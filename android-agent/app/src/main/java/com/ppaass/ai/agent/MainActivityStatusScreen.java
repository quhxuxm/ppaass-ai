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
        appIcon.setColorFilter(COLOR_ACTION_INFO);
        appIcon.setBackground(iconPlateBackground(COLOR_ACTION_INFO));
        appIcon.setPadding(dp(10), dp(10), dp(10), dp(10));
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
        selectAppsButton.setTextColor(COLOR_ACCENT_DARK);
        selectAppsButton.setSingleLine(true);
        selectAppsButton.setMinHeight(0);
        selectAppsButton.setMinWidth(0);
        selectAppsButton.setPadding(dp(14), 0, dp(14), 0);
        selectAppsButton.setBackground(rounded(COLOR_ACCENT_SOFT, COLOR_ACCENT_SOFT));
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
        sectionTitle(dnsPanel, "代理 DNS 记录");
        TextView dnsSubtitle = mutedText("最近 80 条由代理处理的 DNS 解析", 13f);
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

protected void buildHttpProxyPanel(LinearLayout root) {
        LinearLayout panel = panel(root);
        sectionTitle(panel, "HTTP / SOCKS5 代理");
        TextView subtitle = mutedText("HTTP 与 SOCKS5 共享同一个地址和端口，协议由客户端自动握手区分", 13f);
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

        TextView hint = mutedText("同一 Wi-Fi 或手机热点下，HTTP 与 SOCKS5 都填上方同一个地址", 12f);
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

        LinearLayout usbActionRow = horizontalRow();
        httpProxyUsbHint = mutedText("", 12f);
        usbActionRow.addView(httpProxyUsbHint, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        httpProxyUsbActionButton = secondaryButton("打开设置");
        httpProxyUsbActionButton.setOnClickListener(view -> handleHttpProxyUsbAction());
        LinearLayout.LayoutParams copyParams = new LinearLayout.LayoutParams(dp(104), dp(38));
        copyParams.setMargins(dp(8), 0, 0, 0);
        usbActionRow.addView(httpProxyUsbActionButton, copyParams);
        LinearLayout.LayoutParams usbActionParams = matchWrap();
        usbActionParams.setMargins(0, dp(6), 0, 0);
        panel.addView(usbActionRow, usbActionParams);
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

        LinearLayout bluetoothActionRow = horizontalRow();
        httpProxyBluetoothHint = mutedText("", 12f);
        bluetoothActionRow.addView(httpProxyBluetoothHint, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        httpProxyBluetoothActionButton = secondaryButton("打开设置");
        httpProxyBluetoothActionButton.setOnClickListener(view -> handleHttpProxyBluetoothAction());
        LinearLayout.LayoutParams bluetoothCopyParams = new LinearLayout.LayoutParams(dp(104), dp(38));
        bluetoothCopyParams.setMargins(dp(8), 0, 0, 0);
        bluetoothActionRow.addView(httpProxyBluetoothActionButton, bluetoothCopyParams);
        LinearLayout.LayoutParams bluetoothActionParams = matchWrap();
        bluetoothActionParams.setMargins(0, dp(6), 0, 0);
        panel.addView(bluetoothActionRow, bluetoothActionParams);
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
        TextView subtitle = mutedText("通过 VPN 路径测试 HTTPS 与 QUIC", 13f);
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
