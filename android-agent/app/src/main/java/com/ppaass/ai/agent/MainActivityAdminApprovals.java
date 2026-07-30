package com.ppaass.ai.agent;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Build;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

abstract class MainActivityAdminApprovals extends MainActivityPacketCapture {
    static final int ADMIN_NOTIFICATION_PERMISSION_REQUEST = 1004;
    private static final String PREF_NOTIFICATION_PERMISSION_ASKED =
            "admin_key_request_notification_permission_asked";

    private Button adminApprovalTab;
    private TextView adminApprovalBadge;
    private Button adminRefreshButton;
    private TextView adminApprovalSummary;
    private LinearLayout adminApprovalList;
    private int adminApprovalScreenIndex = -1;
    private final AgentAdminOperationController adminOperations =
            new AgentAdminOperationController();
    private String activeRequestId = "";
    private boolean adminDashboardLoading;
    private List<AgentAdminModels.ProxyAddress> adminProxyAddresses =
            Collections.emptyList();

    protected void addAdminApprovalScreenIfNeeded(
            LinearLayout tabBar,
            FrameLayout pages) {
        cancelAdminOperation();
        resetAdminApprovalViews();
        if (!AgentAuthSession.isAdmin(this)) {
            return;
        }
        LinearLayout page = screenPage(pages);
        adminApprovalScreenIndex = screenPages.size() - 1;
        addScreenTab(tabBar, "审批", page);
        adminApprovalTab = screenTabButtons.get(screenTabButtons.size() - 1);
        addAdminApprovalBadge(tabBar);
        buildAdminApprovalScreen(page);
        loadAdminDashboard(false);
    }

    protected int initialScreenIndex() {
        Intent intent = getIntent();
        if (intent != null
                && intent.getBooleanExtra(
                AgentAdminRequestNotifier.EXTRA_OPEN_ADMIN_APPROVALS,
                false)
                && adminApprovalScreenIndex >= 0) {
            intent.removeExtra(
                    AgentAdminRequestNotifier.EXTRA_OPEN_ADMIN_APPROVALS);
            return adminApprovalScreenIndex;
        }
        return 0;
    }

    protected void openAdminApprovalScreenFromIntent() {
        int target = initialScreenIndex();
        if (target <= 0 || adminApprovalScreenIndex < 0) {
            return;
        }
        selectScreen(target);
        loadAdminDashboard(false);
    }

    protected void onAdminRequestStateChanged() {
        if (!AgentAuthSession.isAdmin(this)) {
            cancelAdminOperation();
            resetAdminApprovalViews();
            return;
        }
        updateAdminTabTitle();
        renderAdminRequests();
        maybeRequestAdminNotificationPermission();
    }

    protected void maybeRequestAdminNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU
                || !activityResumed
                || !AgentAuthSession.isAdmin(this)
                || AgentAdminRequestStore.pendingCount(this) < 1
                || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED
                || prefs.getBoolean(PREF_NOTIFICATION_PERMISSION_ASKED, false)) {
            return;
        }
        prefs.edit()
                .putBoolean(PREF_NOTIFICATION_PERMISSION_ASKED, true)
                .apply();
        requestPermissions(
                new String[]{Manifest.permission.POST_NOTIFICATIONS},
                ADMIN_NOTIFICATION_PERMISSION_REQUEST);
    }

    protected void onAdminNotificationPermissionResult(int[] grantResults) {
        if (grantResults.length > 0
                && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            AgentAdminRequestNotifier.update(
                    this,
                    AgentAdminRequestStore.pendingCount(this),
                    false);
        }
    }

    private void buildAdminApprovalScreen(LinearLayout root) {
        LinearLayout heading = panel(root);
        LinearLayout headingRow = horizontalRow();
        LinearLayout titleColumn = new LinearLayout(this);
        titleColumn.setOrientation(LinearLayout.VERTICAL);
        titleColumn.addView(titleText("密钥申请审批", 22f), matchWrap());
        titleColumn.addView(
                mutedText("管理员可以在 Agent 中直接批准或拒绝用户申请。", 13f),
                matchWrap());
        headingRow.addView(titleColumn, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        adminRefreshButton = secondaryButton("刷新");
        adminRefreshButton.setOnClickListener(view -> loadAdminDashboard(true));
        LinearLayout.LayoutParams refreshParams =
                new LinearLayout.LayoutParams(dp(86), dp(42));
        refreshParams.setMargins(dp(10), 0, 0, 0);
        headingRow.addView(adminRefreshButton, refreshParams);
        heading.addView(headingRow, matchWrap());

        adminApprovalSummary = mutedText("", 13f);
        LinearLayout.LayoutParams summaryParams = matchWrap();
        summaryParams.setMargins(0, dp(12), 0, 0);
        heading.addView(adminApprovalSummary, summaryParams);

        adminApprovalList = new LinearLayout(this);
        adminApprovalList.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams listParams = matchWrap();
        listParams.setMargins(0, dp(16), 0, 0);
        root.addView(adminApprovalList, listParams);
        renderAdminRequests();
    }

    private void renderAdminRequests() {
        if (adminApprovalList == null || !AgentAuthSession.isAdmin(this)) {
            return;
        }
        List<AgentAdminModels.KeyRequest> requests =
                AgentAdminRequestStore.currentRequests(
                        AgentAuthSession.username());
        int count = AgentAdminRequestStore.pendingCount(this);
        if (adminApprovalSummary != null) {
            adminApprovalSummary.setText(adminDashboardLoading
                    ? "正在同步待审批申请…"
                    : count + " 项待处理 · SSE 实时同步");
        }
        if (adminRefreshButton != null) {
            adminRefreshButton.setEnabled(
                    !adminDashboardLoading && activeRequestId.isEmpty());
        }
        adminApprovalList.removeAllViews();
        if (requests.isEmpty()) {
            LinearLayout empty = panel(adminApprovalList);
            TextView title = titleText(
                    adminDashboardLoading ? "正在读取申请…" : "没有待审批申请",
                    17f);
            title.setGravity(Gravity.CENTER);
            empty.addView(title, matchWrap());
            TextView detail = mutedText(
                    "普通用户提交的首次申请和密钥轮换申请会显示在这里。",
                    13f);
            detail.setGravity(Gravity.CENTER);
            empty.addView(detail, matchWrap());
            return;
        }
        for (AgentAdminModels.KeyRequest request : requests) {
            AgentAdminRequestViews.addCard(
                    this,
                    adminApprovalList,
                    request,
                    activeRequestId,
                    adminProxyAddresses,
                    new AgentAdminRequestViews.Callbacks() {
                        @Override
                        public void onReject(
                                AgentAdminModels.KeyRequest selected) {
                            confirmReject(selected);
                        }

                        @Override
                        public void onApprove(
                                AgentAdminModels.KeyRequest selected,
                                long expiresAt,
                                List<String> proxyAddressIds,
                                String reason) {
                            approveRequest(
                                    selected,
                                    expiresAt,
                                    proxyAddressIds,
                                    reason);
                        }
                    });
        }
    }

    private void confirmReject(AgentAdminModels.KeyRequest request) {
        AgentAdminRejectionDialog.show(
                this,
                request,
                (target, reason) -> performDecision(
                        target,
                        0,
                        Collections.emptyList(),
                        reason,
                        false));
    }

    private void approveRequest(
            AgentAdminModels.KeyRequest request,
            long expiresAt,
            List<String> proxyAddressIds,
            String reason) {
        performDecision(request, expiresAt, proxyAddressIds, reason, true);
    }

    private void performDecision(
            AgentAdminModels.KeyRequest request,
            long expiresAt,
            List<String> proxyAddressIds,
            String reason,
            boolean approve) {
        if (!activeRequestId.isEmpty() || !AgentAuthSession.isAdmin(this)) {
            return;
        }
        AgentSessionStore.StoredSession session = AgentSessionStore.load(this);
        if (session.needsRelogin || session.accessToken.isEmpty()) {
            showAdminMessage("管理员登录凭据已失效，请重新登录 Agent");
            return;
        }
        final String baseUrl;
        try {
            baseUrl = AgentAuthConfig.proxyWebUrl(this);
        } catch (IOException error) {
            showAdminMessage("无法连接管理员服务");
            return;
        }
        activeRequestId = request.id;
        renderAdminRequests();
        adminOperations.decide(
                this,
                baseUrl,
                session.accessToken,
                request,
                expiresAt,
                proxyAddressIds,
                reason,
                approve,
                new AgentAdminOperationController.Callback() {
                    @Override
                    public void onDashboard(AgentAdminModels.Dashboard dashboard) {
                        if (!acceptAdminCallback()) {
                            return;
                        }
                        activeRequestId = "";
                        applyDashboard(dashboard);
                        showAdminMessage(
                                approve ? "密钥申请已批准" : "密钥申请已拒绝");
                    }

                    @Override
                    public void onFailure(AgentAdminClient.AdminException error) {
                        if (!acceptAdminCallback()) {
                            return;
                        }
                        activeRequestId = "";
                        renderAdminRequests();
                        showAdminMessage(error.isConflict()
                                ? "申请已由其他管理员处理，正在刷新"
                                : error.getMessage());
                        loadAdminDashboard(false);
                    }
                });
    }

    private void loadAdminDashboard(boolean showErrors) {
        if (adminDashboardLoading
                || !activeRequestId.isEmpty()
                || !AgentAuthSession.isAdmin(this)) {
            return;
        }
        AgentSessionStore.StoredSession session = AgentSessionStore.load(this);
        if (session.needsRelogin || session.accessToken.isEmpty()) {
            return;
        }
        final String baseUrl;
        try {
            baseUrl = AgentAuthConfig.proxyWebUrl(this);
        } catch (IOException error) {
            if (showErrors) {
                showAdminMessage("无法连接管理员服务");
            }
            return;
        }
        adminDashboardLoading = true;
        renderAdminRequests();
        adminOperations.loadDashboard(
                this,
                baseUrl,
                session.accessToken,
                new AgentAdminOperationController.Callback() {
                    @Override
                    public void onDashboard(AgentAdminModels.Dashboard dashboard) {
                        if (!acceptAdminCallback()) {
                            return;
                        }
                        adminDashboardLoading = false;
                        applyDashboard(dashboard);
                    }

                    @Override
                    public void onFailure(AgentAdminClient.AdminException error) {
                        if (!acceptAdminCallback()) {
                            return;
                        }
                        adminDashboardLoading = false;
                        renderAdminRequests();
                        if (showErrors) {
                            showAdminMessage(error.getMessage());
                        }
                    }
                });
    }

    private void applyDashboard(AgentAdminModels.Dashboard dashboard) {
        adminProxyAddresses = dashboard.proxyAddresses;
        AgentAdminRequestStore.Update update = AgentAdminRequestStore.replace(
                this,
                AgentAuthSession.username(),
                dashboard.requests);
        if (update.changed()) {
            AgentAdminRequestNotifier.update(this, update.pendingCount, false);
        }
        updateAdminTabTitle();
        renderAdminRequests();
    }

    private boolean acceptAdminCallback() {
        return !isFinishing()
                && !isDestroyed()
                && AgentAuthSession.isAdmin(this);
    }

    private void cancelAdminOperation() {
        adminOperations.cancel();
        activeRequestId = "";
        adminDashboardLoading = false;
    }

    private void resetAdminApprovalViews() {
        adminApprovalTab = null;
        adminApprovalBadge = null;
        adminRefreshButton = null;
        adminApprovalSummary = null;
        adminApprovalList = null;
        adminApprovalScreenIndex = -1;
        adminProxyAddresses = Collections.emptyList();
    }

    private void addAdminApprovalBadge(LinearLayout tabBar) {
        int tabIndex = tabBar.indexOfChild(adminApprovalTab);
        if (tabIndex < 0) {
            return;
        }
        ViewGroup.LayoutParams originalParams = adminApprovalTab.getLayoutParams();
        tabBar.removeViewAt(tabIndex);

        FrameLayout badgeHost = new FrameLayout(this);
        badgeHost.addView(adminApprovalTab, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));

        adminApprovalBadge = new TextView(this);
        adminApprovalBadge.setGravity(Gravity.CENTER);
        adminApprovalBadge.setTextSize(9f);
        adminApprovalBadge.setTypeface(Typeface.DEFAULT_BOLD);
        adminApprovalBadge.setTextColor(UiPalette.ON_BRIGHT);
        adminApprovalBadge.setMinWidth(dp(20));
        adminApprovalBadge.setPadding(dp(5), 0, dp(5), 0);
        adminApprovalBadge.setBackground(rounded(
                COLOR_ACTION_WARN,
                alphaColor(COLOR_ACTION_WARN, 150)));
        adminApprovalBadge.setImportantForAccessibility(
                View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        FrameLayout.LayoutParams badgeParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                dp(20),
                Gravity.TOP | Gravity.END);
        badgeParams.setMargins(0, dp(2), dp(4), 0);
        badgeHost.addView(adminApprovalBadge, badgeParams);

        tabBar.addView(badgeHost, tabIndex, originalParams);
        updateAdminTabTitle();
    }

    private void updateAdminTabTitle() {
        if (adminApprovalTab == null) {
            return;
        }
        int count = AgentAdminRequestStore.pendingCount(this);
        adminApprovalTab.setText("审批");
        adminApprovalTab.setContentDescription(count > 0
                ? "审批，" + count + " 项待处理"
                : "审批，没有待处理申请");
        if (adminApprovalBadge != null) {
            adminApprovalBadge.setText(count > 99 ? "99+" : String.valueOf(count));
            adminApprovalBadge.setVisibility(count > 0 ? View.VISIBLE : View.GONE);
        }
    }

    private void showAdminMessage(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onDestroy() {
        cancelAdminOperation();
        super.onDestroy();
    }
}
