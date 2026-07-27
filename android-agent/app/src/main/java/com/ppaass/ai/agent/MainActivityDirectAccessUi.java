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
abstract class MainActivityDirectAccessUi extends MainActivityDirectRules {

protected void buildDirectAccessSection(LinearLayout root) {
        directAccessModeValue = normalizeDirectAccessMode(
                prefs.getString("direct_access_mode", DefaultConfig.DIRECT_ACCESS_MODE));
        directRuleValues.clear();
        directRuleValues.addAll(normalizeDirectRules(parseDirectRuleInput(
                prefs.getString("direct_access_rules", DefaultConfig.DIRECT_ACCESS_RULES))));

        LinearLayout section = configSection(root, "直连策略");
        TextView subtitle = mutedText("HTTP/SOCKS5 与 TUN 共用", 13f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, 0, 0, dp(8));
        section.addView(subtitle, subtitleParams);

        addDirectModeControl(section);
        addDirectPolicyFacts(section);
        addForwardingMethodRows(section);
        addDirectRuleUsageGuide(section);
        directRulesConfig = new LinearLayout(this);
        directRulesConfig.setOrientation(LinearLayout.VERTICAL);
        section.addView(directRulesConfig, matchWrap());
        addDirectRulePresets(directRulesConfig);
        addDirectRuleManager(directRulesConfig);
        updateDirectModeButtons();
        renderDirectRuleList();
    }

protected void addDirectModeControl(LinearLayout root) {
        root.addView(controlLabel("模式"), labelParams());
        LinearLayout row = horizontalRow();
        row.setPadding(dp(4), dp(4), dp(4), dp(4));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        addDirectModeButton(row, "全走代理", "proxy_all");
        addDirectModeButton(row, "全量直连", "direct_all");
        addDirectModeButton(row, "按规则", "rules");
        root.addView(row, matchWrap());
    }

protected void addDirectModeButton(LinearLayout row, String label, String value) {
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
        flattenButton(button);
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

protected void addDirectPolicyFacts(LinearLayout root) {
        LinearLayout row = horizontalRow();
        LinearLayout.LayoutParams rowParams = matchWrap();
        rowParams.setMargins(0, dp(12), 0, 0);
        directModeSummary = addPolicyFact(row, "当前模式", directModeLabel(directAccessModeValue));
        directRuleCountSummary = addPolicyFact(row, "规则数量", directRuleCountLabel());
        directRuleCountFact = directRuleCountSummary == null ? null : (View) directRuleCountSummary.getParent();
        root.addView(row, rowParams);
    }

protected TextView addPolicyFact(LinearLayout row, String label, String value) {
        LinearLayout tile = new LinearLayout(this);
        tile.setOrientation(LinearLayout.VERTICAL);
        tile.setPadding(dp(9), dp(8), dp(9), dp(8));
        tile.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        TextView labelView = mutedText(label, 10f);
        labelView.setSingleLine(false);
        labelView.setMaxLines(2);
        labelView.setEllipsize(null);
        tile.addView(labelView, matchWrap());

        TextView valueView = titleText(value, 12f);
        valueView.setSingleLine(false);
        valueView.setMaxLines(2);
        valueView.setEllipsize(null);
        LinearLayout.LayoutParams valueParams = matchWrap();
        valueParams.setMargins(0, dp(3), 0, 0);
        tile.addView(valueView, valueParams);

        LinearLayout.LayoutParams tileParams = new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f);
        tile.setMinimumHeight(dp(70));
        if (row.getChildCount() > 0) {
            tileParams.setMargins(dp(8), 0, 0, 0);
        }
        row.addView(tile, tileParams);
        return valueView;
    }

protected void addForwardingMethodRows(LinearLayout root) {
        LinearLayout methods = new LinearLayout(this);
        methods.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams methodsParams = matchWrap();
        methodsParams.setMargins(0, dp(12), 0, 0);
        addForwardingMethod(methods, "Android VPN", "TUN 流量策略");
        addForwardingMethod(methods, "Android HTTP / SOCKS5 代理", "同端口显式代理流量");
        addForwardingMethod(methods, "策略路由", "使用当前直连模式");
        root.addView(methods, methodsParams);
    }

protected void addForwardingMethod(LinearLayout root, String title, String detail) {
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

protected void addDirectRuleUsageGuide(LinearLayout root) {
        LinearLayout.LayoutParams headingParams = matchWrap();
        headingParams.setMargins(0, dp(12), 0, dp(5));
        root.addView(controlLabel("规则类型"), headingParams);

        LinearLayout guide = new LinearLayout(this);
        guide.setOrientation(LinearLayout.VERTICAL);
        guide.setPadding(dp(10), dp(6), dp(10), dp(6));
        guide.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));

        addDirectRuleUsageRow(
                guide,
                "HTTP / SOCKS5 域名",
                "使用 example.com 或 *.example.com 匹配显式代理目标。",
                new String[]{"HTTP", "SOCKS5"});
        addDirectRuleUsageRow(
                guide,
                "TUN IP / CIDR",
                "优先使用固定 IP 或 192.168.0.0/16 这样的网段。",
                new String[]{"TUN", "IP/CIDR"});
        addDirectRuleUsageRow(
                guide,
                "TUN 域名规则",
                "需要先启用代理 DNS；命中 DNS 缓存后规则才会生效。",
                new String[]{"TUN", "代理 DNS"});

        root.addView(guide, matchWrap());
    }

protected void addDirectRuleUsageRow(LinearLayout root, String title, String detail, String[] modes) {
        LinearLayout row = horizontalRow();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(5), 0, dp(5));

        LinearLayout textColumn = new LinearLayout(this);
        textColumn.setOrientation(LinearLayout.VERTICAL);
        TextView titleView = titleText(title, 12f);
        titleView.setSingleLine(true);
        titleView.setEllipsize(TextUtils.TruncateAt.END);
        textColumn.addView(titleView, matchWrap());

        TextView detailView = mutedText(detail, 10.5f);
        detailView.setSingleLine(true);
        detailView.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams detailParams = matchWrap();
        detailParams.setMargins(0, dp(2), 0, 0);
        textColumn.addView(detailView, detailParams);
        row.addView(textColumn, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));

        LinearLayout modeRow = new LinearLayout(this);
        modeRow.setOrientation(LinearLayout.HORIZONTAL);
        modeRow.setGravity(Gravity.END);
        addModeChips(modeRow, modes);
        LinearLayout.LayoutParams modeParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        modeParams.setMargins(dp(8), 0, 0, 0);
        row.addView(modeRow, modeParams);

        root.addView(row, matchWrap());
    }

protected void addDirectRulePresets(LinearLayout root) {
        LinearLayout.LayoutParams headingParams = matchWrap();
        headingParams.setMargins(0, dp(16), 0, dp(6));
        root.addView(controlLabel("快捷预设"), headingParams);

        LinearLayout firstRow = horizontalRow();
        addPresetButton(firstRow, "本机", new String[]{"localhost", "127.0.0.0/8", "::1"});
        addPresetButton(firstRow, "私网", new String[]{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"});
        root.addView(firstRow, matchWrap());

        LinearLayout secondRow = horizontalRow();
        LinearLayout.LayoutParams secondRowParams = matchWrap();
        secondRowParams.setMargins(0, dp(8), 0, 0);
        addPresetButton(secondRow, "中国", new String[]{"*.cn"});
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

protected void addPresetButton(LinearLayout row, String label, String[] rules) {
        Button button = secondaryButton(label);
        button.setOnClickListener(view -> addDirectRules(rules));
        trackEditable(button);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(44), 1f);
        if (row.getChildCount() > 0) {
            params.setMargins(dp(8), 0, 0, 0);
        }
        row.addView(button, params);
    }

protected void addDirectRuleManager(LinearLayout root) {
        LinearLayout heading = horizontalRow();
        LinearLayout.LayoutParams headingParams = matchWrap();
        headingParams.setMargins(0, dp(16), 0, dp(6));
        TextView title = controlLabel("规则管理");
        heading.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        directRuleGroupSummary = chip("0 组", COLOR_ACCENT);
        heading.addView(directRuleGroupSummary, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(heading, headingParams);

        LinearLayout compose = horizontalRow();
        directRuleDraft = new EditText(this);
        directRuleDraft.setHint("example.com / *.example.com / 10.0.0.0/8");
        directRuleDraft.setSingleLine(true);
        directRuleDraft.setImeOptions(EditorInfo.IME_ACTION_DONE);
        directRuleDraft.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        directRuleDraft.setTextSize(15f);
        styleInput(directRuleDraft);
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

        Button addButton = actionButton("添加", COLOR_ACCENT);
        addButton.setOnClickListener(view -> addDraftDirectRules());
        trackEditable(addButton);
        LinearLayout.LayoutParams addParams = new LinearLayout.LayoutParams(dp(92), dp(48));
        addParams.setMargins(dp(8), 0, 0, 0);
        compose.addView(addButton, addParams);
        root.addView(compose, matchWrap());

        TextView inventoryLabel = controlLabel("当前规则");
        LinearLayout.LayoutParams inventoryParams = labelParams();
        inventoryParams.setMargins(0, dp(14), 0, dp(6));
        root.addView(inventoryLabel, inventoryParams);

        LinearLayout ruleBrowser = new LinearLayout(this);
        ruleBrowser.setOrientation(LinearLayout.VERTICAL);
        ruleBrowser.setPadding(dp(8), dp(8), dp(8), dp(8));
        ruleBrowser.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        LinearLayout firstTypeRow = horizontalRow();
        addDirectRuleTypeButton(firstTypeRow, "通配符", "wildcard");
        addDirectRuleTypeButton(firstTypeRow, "IP / CIDR", "network");
        ruleBrowser.addView(firstTypeRow, matchWrap());

        LinearLayout secondTypeRow = horizontalRow();
        addDirectRuleTypeButton(secondTypeRow, "域名", "domain");
        addDirectRuleTypeButton(secondTypeRow, "其他", "other");
        LinearLayout.LayoutParams secondTypeParams = matchWrap();
        secondTypeParams.setMargins(0, dp(7), 0, 0);
        ruleBrowser.addView(secondTypeRow, secondTypeParams);

        directRuleGroupList = new LinearLayout(this);
        directRuleGroupList.setOrientation(LinearLayout.VERTICAL);
        directRuleGroupList.setBackgroundColor(alphaColor(COLOR_BORDER, 72));

        MaxHeightScrollView ruleScroll = new MaxHeightScrollView(this, dp(340));
        ruleScroll.setPadding(0, 0, 0, 0);
        ruleScroll.setVerticalScrollBarEnabled(true);
        ruleScroll.setScrollbarFadingEnabled(true);
        ruleScroll.setScrollBarFadeDuration(450);
        ruleScroll.setScrollBarDefaultDelayBeforeFade(700);
        ruleScroll.setScrollBarStyle(View.SCROLLBARS_INSIDE_OVERLAY);
        ruleScroll.setClipToPadding(true);
        ruleScroll.setFillViewport(false);
        final float[] lastRuleTouchY = {0f};
        ruleScroll.setOnTouchListener((view, event) -> {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    lastRuleTouchY[0] = event.getY();
                    view.getParent().requestDisallowInterceptTouchEvent(
                            view.canScrollVertically(-1) || view.canScrollVertically(1));
                    break;
                case MotionEvent.ACTION_MOVE:
                    float currentY = event.getY();
                    int direction = currentY < lastRuleTouchY[0] ? 1 : -1;
                    view.getParent().requestDisallowInterceptTouchEvent(
                            view.canScrollVertically(direction));
                    lastRuleTouchY[0] = currentY;
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            ruleScroll.setNestedScrollingEnabled(true);
        }
        ruleScroll.addView(directRuleGroupList, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        FrameLayout ruleListContainer = new FrameLayout(this);
        ruleListContainer.setClipChildren(true);
        ruleListContainer.setClipToOutline(true);
        GradientDrawable ruleListSurface = new GradientDrawable();
        ruleListSurface.setColor(COLOR_SURFACE);
        ruleListSurface.setCornerRadius(dp(10));
        ruleListContainer.setBackground(ruleListSurface);
        GradientDrawable ruleListFrame = new GradientDrawable();
        ruleListFrame.setColor(Color.TRANSPARENT);
        ruleListFrame.setCornerRadius(dp(10));
        ruleListFrame.setStroke(dp(1), alphaColor(COLOR_BORDER, 112));
        ruleListContainer.setForegroundGravity(Gravity.FILL);
        ruleListContainer.setForeground(ruleListFrame);
        ruleListContainer.addView(ruleScroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams listContainerParams = matchWrap();
        listContainerParams.setMargins(0, dp(8), 0, 0);
        ruleBrowser.addView(ruleListContainer, listContainerParams);
        root.addView(ruleBrowser, matchWrap());
    }

}
