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
abstract class MainActivityScreens extends MainActivityConfigScreen {

protected void buildUi() {
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
        GradientDrawable background = new GradientDrawable(
                GradientDrawable.Orientation.TL_BR,
                new int[]{
                        Color.WHITE,
                        Color.rgb(252, 254, 253),
                        Color.WHITE
                });
        scroll.setBackground(background);

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
        addScreenTab(screenTabs, "状态", statusScreen);
        addScreenTab(screenTabs, "配置", configScreen);

        buildStatusScreen(statusScreen);
        buildConfigScreen(configScreen);

        selectScreen(0);
        updateVpnToggle();
        updateHttpProxyToggle();
        updateStatusMetrics();

        setContentView(scroll);
        root.requestApplyInsets();
    }

}
