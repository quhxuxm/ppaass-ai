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
abstract class MainActivityScreens extends MainActivityPacketCapture {

protected void buildUi() {
        preparePacketCaptureUiForBuild();
        editableControls.clear();
        screenTabButtons.clear();
        screenPages.clear();
        screenPageHost = null;
        screenSwitchAnimating = false;
        configTabButtons.clear();
        configTabPages.clear();
        captureScreenIndex = -1;
        transportModeButtons.clear();
        udpSessionPoolConfig = null;
        udpYamuxConfig = null;
        directModeButtons.clear();
        directRuleTypeButtons.clear();
        directRuleValues.clear();
        directRulesConfig = null;
        directRuleCountFact = null;
        lastRxBytes = -1;
        lastTxBytes = -1;
        lastTrafficSampleMs = 0;
        loadHourlyTrafficState();

        ScrollView scroll = new ScrollView(this);
        mainScrollView = scroll;
        scroll.setClipToPadding(false);
        scroll.setFillViewport(true);
        scroll.setFocusable(true);
        scroll.setFocusableInTouchMode(true);
        scroll.setBackground(appBackground());

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

        FrameLayout pages = screenPageHost(root);
        LinearLayout statusScreen = screenPage(pages);
        addScreenTab(screenTabs, "状态", statusScreen);
        buildStatusScreen(statusScreen);

        if (hasAgentPermission(AgentPermissions.PACKET_CAPTURE)) {
            LinearLayout captureScreen = screenPage(pages);
            captureScreenIndex = screenPages.size() - 1;
            addScreenTab(screenTabs, "抓包", captureScreen);
            buildPacketCaptureScreen(captureScreen);
        } else {
            disablePacketCaptureForRevokedPermission();
        }

        LinearLayout configScreen = screenPage(pages);
        addScreenTab(screenTabs, "配置", configScreen);
        buildConfigScreen(configScreen);

        if (screenTabButtons.size() == 1) {
            screenTabs.setVisibility(View.GONE);
            ViewGroup.LayoutParams pageHostParams = pages.getLayoutParams();
            if (pageHostParams instanceof LinearLayout.LayoutParams) {
                ((LinearLayout.LayoutParams) pageHostParams).topMargin = 0;
                pages.setLayoutParams(pageHostParams);
            }
        }

        appliedAgentPermissionFingerprint = agentPermissionFingerprint();
        selectScreen(0);
        updateVpnToggle();
        updateHttpProxyToggle();
        updateStatusMetrics();

        setContentView(scroll);
        scroll.requestFocus();
        scroll.scrollTo(0, 0);
        root.requestApplyInsets();
    }

}
