package com.ppaass.ai.agent;

import android.app.*;
import android.graphics.*;
import android.graphics.drawable.*;
import android.os.*;
import android.text.*;
import android.view.*;
import android.widget.*;

import org.json.*;

import java.io.*;
import java.lang.ref.WeakReference;
import java.text.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

abstract class MainActivityPacketCapture extends MainActivityConfigScreen {
    private static final int CAPTURE_LIMIT = 500;
    private static final int CAPTURE_LIST_MIN_HEIGHT_DP = 360;
    private static final int PAYLOAD_PREVIEW_BYTES = 4 * 1024;
    private static final long CAPTURE_REFRESH_MS = 5000L;
    private static final long CAPTURE_FILTER_DEBOUNCE_MS = 150L;
    private static final ExecutorService CAPTURE_REPORT_EXECUTOR =
            Executors.newSingleThreadExecutor(task -> {
                Thread thread = new Thread(task, "ppaass-capture-report");
                thread.setDaemon(true);
                return thread;
            });
    private static final String ALL_PROTOCOLS = "全部协议";
    private static final String HTTP_PROXY_PROTOCOL = "HTTP 代理";
    private static final String SOCKS5_PROXY_PROTOCOL = "SOCKS5 代理";

    private TextView captureStatus;
    private TextView captureSummary;
    private Button captureToggle;
    private Button captureClear;
    private Button captureRefresh;
    private EditText captureSearch;
    private EditText captureMinimumKb;
    private Spinner captureDirection;
    private Spinner captureProtocol;
    private Spinner captureSort;
    private LinearLayout capturePacketList;
    private LinearLayout capturePageRoot;
    private LinearLayout capturePacketsPanel;
    private FrameLayout captureListContainer;
    private JSONArray capturePackets = new JSONArray();
    private ArrayList<String> captureSearchIndexes = new ArrayList<>();
    private CaptureOperation captureOperation = CaptureOperation.NONE;
    private long captureOperationToken;
    private volatile boolean captureUiDestroyed;
    private boolean captureClearConfirmationVisible;
    private long lastCaptureRefreshMs;
    private Future<?> captureReportFuture;
    private final Handler captureFilterHandler = new Handler(Looper.getMainLooper());
    private final Runnable captureFilterRender = () -> {
        if (!captureUiDestroyed && !isDestroyed()) {
            renderPacketList();
        }
    };

    private enum CaptureOperation {
        NONE(""),
        REFRESHING("●  正在读取抓包…"),
        ENABLING("●  正在开启抓包…"),
        DISABLING("●  正在关闭抓包…"),
        CLEARING("●  正在清空抓包…");

        private final String statusText;

        CaptureOperation(String statusText) {
            this.statusText = statusText;
        }
    }

    private interface CaptureBooleanOperation {
        boolean run();
    }

    private static final class CaptureReportData {
        final int totalPackets;
        final long fileSize;
        final JSONArray packets;
        final ArrayList<String> searchIndexes;

        CaptureReportData(
                int totalPackets,
                long fileSize,
                JSONArray packets,
                ArrayList<String> searchIndexes) {
            this.totalPackets = totalPackets;
            this.fileSize = fileSize;
            this.packets = packets;
            this.searchIndexes = searchIndexes;
        }
    }

    protected void buildPacketCaptureScreen(LinearLayout root) {
        capturePageRoot = root;
        LinearLayout header = panel(root);
        sectionTitle(header, "明文抓包结果");
        TextView path = mutedText(captureFile().getAbsolutePath(), 12f);
        path.setTextIsSelectable(true);
        header.addView(path, matchWrap());

        LinearLayout statusRow = horizontalRow();
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        captureStatus = mutedText("●  抓包已关闭", 13f);
        captureStatus.setTypeface(Typeface.DEFAULT_BOLD);
        captureStatus.setGravity(Gravity.CENTER_VERTICAL);
        captureStatus.setPadding(dp(2), 0, dp(10), 0);
        statusRow.addView(captureStatus, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        captureToggle = actionButton("开启抓包", COLOR_ACTION_START);
        captureToggle.setOnClickListener(view -> togglePacketCapture());
        statusRow.addView(captureToggle, new LinearLayout.LayoutParams(dp(112), dp(44)));
        LinearLayout.LayoutParams statusRowParams = matchWrap();
        statusRowParams.setMargins(0, dp(12), 0, 0);
        header.addView(statusRow, statusRowParams);

        LinearLayout actionRow = horizontalRow();
        captureClear = secondaryButton("清空");
        captureClear.setOnClickListener(view -> confirmClearPacketCapture());
        actionRow.addView(captureClear, new LinearLayout.LayoutParams(0, dp(42), 1f));
        captureRefresh = secondaryButton("刷新");
        captureRefresh.setOnClickListener(view -> refreshPacketCapture(true));
        LinearLayout.LayoutParams refreshParams = new LinearLayout.LayoutParams(0, dp(42), 1f);
        refreshParams.setMargins(dp(8), 0, 0, 0);
        actionRow.addView(captureRefresh, refreshParams);
        LinearLayout.LayoutParams actionParams = matchWrap();
        actionParams.setMargins(0, dp(8), 0, 0);
        header.addView(actionRow, actionParams);

        LinearLayout filters = panel(root);
        sectionTitle(filters, "筛选与排序");
        captureSearch = captureEditText("搜索 IP、端口、协议或预览内容", false);
        captureSearch.addTextChangedListener(filterWatcher());
        filters.addView(filterField("搜索", captureSearch), matchWrap());

        LinearLayout filterRow = horizontalRow();
        captureDirection = spinner(new String[]{
                "全部方向",
                "Client → Agent / 目标",
                "Agent / 目标 → Client"
        });
        captureDirection.setOnItemSelectedListener(filterListener());
        filterRow.addView(
                filterField("方向", captureDirection),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        captureProtocol = spinner(new String[]{ALL_PROTOCOLS});
        captureProtocol.setOnItemSelectedListener(filterListener());
        LinearLayout.LayoutParams protocolFieldParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        protocolFieldParams.setMargins(dp(10), 0, 0, 0);
        filterRow.addView(filterField("协议", captureProtocol), protocolFieldParams);
        LinearLayout.LayoutParams filterRowParams = matchWrap();
        filterRowParams.setMargins(0, dp(10), 0, 0);
        filters.addView(filterRow, filterRowParams);

        LinearLayout sortRow = horizontalRow();
        captureMinimumKb = captureEditText("例如 1.5", true);
        captureMinimumKb.setInputType(android.text.InputType.TYPE_CLASS_NUMBER
                | android.text.InputType.TYPE_NUMBER_FLAG_DECIMAL);
        captureMinimumKb.addTextChangedListener(filterWatcher());
        sortRow.addView(
                filterField("最小包大小 · KB", captureMinimumKb),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        captureSort = spinner(new String[]{
                "最新优先", "最早优先", "包大小：大到小", "包大小：小到大",
                "协议 A → Z", "源地址 A → Z", "目标地址 A → Z"
        });
        captureSort.setOnItemSelectedListener(filterListener());
        LinearLayout.LayoutParams sortFieldParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        sortFieldParams.setMargins(dp(10), 0, 0, 0);
        sortRow.addView(filterField("排序", captureSort), sortFieldParams);
        LinearLayout.LayoutParams sortRowParams = matchWrap();
        sortRowParams.setMargins(0, dp(10), 0, 0);
        filters.addView(sortRow, sortRowParams);

        LinearLayout resetRow = horizontalRow();
        TextView filterHint = mutedText(
                "筛选立即应用 · 内容搜索仅覆盖 Payload 预览",
                11f);
        resetRow.addView(filterHint, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button resetFilters = new Button(this);
        resetFilters.setText(tr("重置"));
        resetFilters.setTextSize(12f);
        resetFilters.setTextColor(COLOR_ACCENT_DARK);
        resetFilters.setAllCaps(false);
        resetFilters.setMinWidth(0);
        resetFilters.setMinHeight(0);
        resetFilters.setPadding(dp(12), 0, dp(12), 0);
        flattenButton(resetFilters);
        resetFilters.setBackground(interactiveRounded(
                COLOR_SURFACE, alphaColor(COLOR_ACCENT, 92), COLOR_ACCENT));
        resetFilters.setOnClickListener(view -> resetPacketFilters());
        resetRow.addView(resetFilters, new LinearLayout.LayoutParams(dp(72), dp(34)));
        LinearLayout.LayoutParams resetRowParams = matchWrap();
        resetRowParams.setMargins(0, dp(10), 0, 0);
        filters.addView(resetRow, resetRowParams);

        LinearLayout packets = panel(root);
        capturePacketsPanel = packets;
        packets.setPadding(dp(10), dp(16), dp(10), dp(12));
        sectionTitle(packets, "数据包列表");
        captureSummary = mutedText("尚未读取抓包文件", 12f);
        LinearLayout.LayoutParams summaryParams = matchWrap();
        summaryParams.setMargins(0, dp(2), 0, dp(10));
        packets.addView(captureSummary, summaryParams);
        ScrollView scroll = new ScrollView(this);
        scroll.setVerticalScrollBarEnabled(false);
        scroll.setNestedScrollingEnabled(true);
        scroll.setClipToPadding(true);
        scroll.setFillViewport(true);
        final float[] lastCaptureTouchY = {0f};
        scroll.setOnTouchListener((view, event) -> {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    lastCaptureTouchY[0] = event.getY();
                    view.getParent().requestDisallowInterceptTouchEvent(
                            view.canScrollVertically(-1) || view.canScrollVertically(1));
                    break;
                case MotionEvent.ACTION_MOVE:
                    float currentY = event.getY();
                    int direction = currentY < lastCaptureTouchY[0] ? 1 : -1;
                    view.getParent().requestDisallowInterceptTouchEvent(
                            view.canScrollVertically(direction));
                    lastCaptureTouchY[0] = currentY;
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
        capturePacketList = new LinearLayout(this);
        capturePacketList.setOrientation(LinearLayout.VERTICAL);
        capturePacketList.setBackgroundColor(alphaColor(COLOR_BORDER, 72));
        scroll.addView(capturePacketList, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        captureListContainer = new FrameLayout(this);
        captureListContainer.setClipChildren(true);
        captureListContainer.setClipToOutline(true);
        GradientDrawable listSurface = new GradientDrawable();
        listSurface.setColor(COLOR_SURFACE);
        listSurface.setCornerRadius(dp(10));
        captureListContainer.setBackground(listSurface);
        GradientDrawable listFrame = new GradientDrawable();
        listFrame.setColor(Color.TRANSPARENT);
        listFrame.setCornerRadius(dp(10));
        listFrame.setStroke(dp(1), alphaColor(COLOR_BORDER, 112));
        captureListContainer.setForegroundGravity(Gravity.FILL);
        captureListContainer.setForeground(listFrame);
        captureListContainer.addView(scroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        packets.addView(captureListContainer, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(CAPTURE_LIST_MIN_HEIGHT_DP)));
        root.addOnLayoutChangeListener((view, left, top, right, bottom,
                                        oldLeft, oldTop, oldRight, oldBottom) ->
                updateCaptureListHeight());
        root.post(this::updateCaptureListHeight);

        updatePacketCaptureControls();
        refreshPacketCapture(true);
    }

    protected void preparePacketCaptureUiForBuild() {
        captureOperationToken++;
        captureFilterHandler.removeCallbacks(captureFilterRender);
        Future<?> reportFuture = captureReportFuture;
        captureReportFuture = null;
        if (reportFuture != null) {
            reportFuture.cancel(true);
        }
        captureOperation = CaptureOperation.NONE;
        captureClearConfirmationVisible = false;
        capturePackets = new JSONArray();
        captureSearchIndexes = new ArrayList<>();
        captureStatus = null;
        captureSummary = null;
        captureToggle = null;
        captureClear = null;
        captureRefresh = null;
        captureSearch = null;
        captureMinimumKb = null;
        captureDirection = null;
        captureProtocol = null;
        captureSort = null;
        capturePacketList = null;
        capturePageRoot = null;
        capturePacketsPanel = null;
        captureListContainer = null;
        captureUiDestroyed = false;
    }

    protected void disablePacketCaptureForRevokedPermission() {
        try {
            NativeAgent.setPacketCaptureEnabled(captureFile().getAbsolutePath(), false);
        } catch (RuntimeException ignored) {
            // A later native start also receives no packet-capture UI entry.
        }
    }

    @Override
    protected void updateStatusMetrics() {
        super.updateStatusMetrics();
        updatePacketCaptureControls();
        if (captureScreenIndex >= 0
                && selectedScreenIndex == captureScreenIndex
                && SystemClock.elapsedRealtime() - lastCaptureRefreshMs >= CAPTURE_REFRESH_MS) {
            refreshPacketCapture(false);
        }
    }

    protected void updatePacketCaptureControls() {
        if (captureToggle == null) {
            return;
        }
        if (!hasPacketCapturePermission()) {
            captureToggle.setEnabled(false);
            captureClear.setEnabled(false);
            captureRefresh.setEnabled(false);
            captureStatus.setText(tr("●  当前账户无抓包权限"));
            captureStatus.setTextColor(COLOR_ACTION_STOP);
            return;
        }
        boolean busy = captureOperation != CaptureOperation.NONE;
        captureToggle.setEnabled(!busy);
        captureClear.setEnabled(!busy && captureFile().exists());
        captureRefresh.setEnabled(!busy);
        if (busy) {
            captureStatus.setText(tr(captureOperation.statusText));
            captureStatus.setTextColor(COLOR_ACTION_INFO);
            return;
        }

        boolean running = isVpnRunning() || isHttpProxyRunning();
        boolean enabled;
        try {
            enabled = NativeAgent.packetCaptureEnabled();
        } catch (RuntimeException error) {
            captureStatus.setText(tr("●  抓包状态不可用"));
            captureStatus.setTextColor(COLOR_ACTION_STOP);
            return;
        }
        captureToggle.setText(tr(enabled ? "关闭抓包" : "开启抓包"));
        applyActionButtonStyle(
                captureToggle,
                enabled ? COLOR_ACTION_STOP : COLOR_ACTION_START);
        captureStatus.setText(tr(enabled
                ? running
                    ? "●  正在抓包"
                    : "●  已开启，等待 VPN 或 HTTP / SOCKS5 代理"
                : "●  抓包已关闭"));
        captureStatus.setTextColor(enabled ? COLOR_STATUS_RUNNING : COLOR_ACTION_WARN);
    }

    private void updateCaptureListHeight() {
        if (mainScrollView == null
                || capturePageRoot == null
                || captureListContainer == null
                || mainScrollView.getHeight() <= 0
                || !capturePageRoot.isLaidOut()
                || !captureListContainer.isLaidOut()) {
            return;
        }

        int[] scrollLocation = new int[2];
        int[] pageLocation = new int[2];
        int[] listLocation = new int[2];
        mainScrollView.getLocationInWindow(scrollLocation);
        capturePageRoot.getLocationInWindow(pageLocation);
        captureListContainer.getLocationInWindow(listLocation);

        int pageTopInScrollContent =
                pageLocation[1] - scrollLocation[1] + mainScrollView.getScrollY();
        int listTopInPage = listLocation[1] - pageLocation[1];
        View scrollContent = mainScrollView.getChildCount() == 0
                ? null : mainScrollView.getChildAt(0);
        int bottomPadding = scrollContent == null ? 0 : scrollContent.getPaddingBottom();
        int occupiedHeight = Math.max(0, pageTopInScrollContent)
                + Math.max(0, listTopInPage)
                + Math.max(0, bottomPadding);
        int trailingPanelPadding = capturePacketsPanel == null
                ? 0 : capturePacketsPanel.getPaddingBottom();
        int targetHeight = calculateCaptureListHeightPx(
                mainScrollView.getHeight(),
                occupiedHeight,
                trailingPanelPadding,
                dp(CAPTURE_LIST_MIN_HEIGHT_DP));

        ViewGroup.LayoutParams params = captureListContainer.getLayoutParams();
        if (params != null && params.height != targetHeight) {
            params.height = targetHeight;
            captureListContainer.setLayoutParams(params);
        }
    }

    static int calculateCaptureListHeightPx(
            int viewportHeight,
            int occupiedHeight,
            int trailingHeight,
            int minimumHeight) {
        int safeViewportHeight = Math.max(0, viewportHeight);
        int safeOccupiedHeight = Math.max(0, occupiedHeight);
        int safeTrailingHeight = Math.max(0, trailingHeight);
        int availableHeight = Math.max(
                0,
                safeViewportHeight - safeOccupiedHeight - safeTrailingHeight);
        return Math.max(Math.max(0, minimumHeight), availableHeight);
    }

    private File captureFile() {
        return new File(new File(getFilesDir(), "captures"), "ppaass-tun.pcap");
    }

    private void togglePacketCapture() {
        if (!requirePacketCapturePermission()) {
            return;
        }
        if (!canStartCaptureOperation()) {
            return;
        }
        boolean enabled;
        try {
            enabled = !NativeAgent.packetCaptureEnabled();
        } catch (RuntimeException error) {
            showCaptureError("切换抓包失败：", captureFailureDetail(error));
            updatePacketCaptureControls();
            return;
        }
        CaptureOperation operation = enabled
                ? CaptureOperation.ENABLING
                : CaptureOperation.DISABLING;
        runCaptureBooleanOperation(
                operation,
                enabled ? "开启抓包失败：" : "关闭抓包失败：",
                () -> NativeAgent.setPacketCaptureEnabled(
                        captureFile().getAbsolutePath(),
                        enabled),
                () -> {
                    updatePacketCaptureControls();
                    refreshPacketCapture(true);
                });
    }

    private void confirmClearPacketCapture() {
        if (!requirePacketCapturePermission()) {
            return;
        }
        if (!canStartCaptureOperation()) {
            return;
        }
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(tr("清空抓包文件"))
                .setMessage(tr("将永久删除当前全部抓包记录。抓包若已开启，清空后会继续记录。"))
                .setNegativeButton(tr("取消"), null)
                .setPositiveButton(
                        tr("确认清空"),
                        (dialogInterface, which) -> clearPacketCapture())
                .create();
        captureClearConfirmationVisible = true;
        dialog.setOnDismissListener(ignored -> captureClearConfirmationVisible = false);
        dialog.show();
    }

    private void clearPacketCapture() {
        if (!requirePacketCapturePermission()) {
            return;
        }
        runCaptureBooleanOperation(
                CaptureOperation.CLEARING,
                "清空抓包失败：",
                () -> NativeAgent.clearPacketCapture(captureFile().getAbsolutePath()),
                () -> {
                    capturePackets = new JSONArray();
                    captureSearchIndexes = new ArrayList<>();
                    renderPacketList();
                    updatePacketCaptureControls();
                    refreshPacketCapture(true);
                });
    }

    private void runCaptureBooleanOperation(
            CaptureOperation operation,
            String failurePrefix,
            CaptureBooleanOperation nativeOperation,
            Runnable onSuccess) {
        long token = beginCaptureOperation(operation);
        if (token < 0) {
            return;
        }
        new Thread(() -> {
            String failure = null;
            try {
                if (!hasPacketCapturePermission()) {
                    failure = "当前账户没有使用此功能的权限";
                } else if (!nativeOperation.run()) {
                    failure = "原生抓包服务未完成请求";
                }
            } catch (RuntimeException error) {
                failure = captureFailureDetail(error);
            }
            String finalFailure = failure;
            postCaptureOperationResult(token, operation, () -> {
                if (finalFailure == null) {
                    onSuccess.run();
                } else {
                    updatePacketCaptureControls();
                    showCaptureError(failurePrefix, finalFailure);
                }
            });
        }, "ppaass-capture-" + operation.name().toLowerCase(Locale.ROOT)).start();
    }

    private void refreshPacketCapture(boolean showProgress) {
        if (!hasPacketCapturePermission()) {
            if (showProgress) {
                showAgentPermissionDenied();
            }
            return;
        }
        if (captureClearConfirmationVisible) {
            return;
        }
        long token = beginCaptureOperation(CaptureOperation.REFRESHING);
        if (token < 0) {
            return;
        }
        lastCaptureRefreshMs = SystemClock.elapsedRealtime();
        if (showProgress) {
            captureSummary.setText(tr("正在读取抓包结果…"));
        }
        String file = captureFile().getAbsolutePath();
        int proxyListenPort = httpProxyListenPort();
        WeakReference<MainActivityPacketCapture> activityRef = new WeakReference<>(this);
        try {
            captureReportFuture = CAPTURE_REPORT_EXECUTOR.submit(() ->
                    runCaptureReportTask(
                            activityRef,
                            token,
                            file,
                            proxyListenPort,
                            showProgress));
        } catch (RuntimeException error) {
            captureOperation = CaptureOperation.NONE;
            captureReportFuture = null;
            updatePacketCaptureControls();
            showCaptureError(
                    "读取抓包失败：",
                    captureFailureDetail(error),
                    showProgress);
        }
    }

    private static void runCaptureReportTask(
            WeakReference<MainActivityPacketCapture> activityRef,
            long token,
            String file,
            int proxyListenPort,
            boolean showProgress) {
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
        MainActivityPacketCapture activity = activityRef.get();
        if (activity == null || !activity.hasPacketCapturePermission()) {
            return;
        }
        CaptureReportData report = null;
        String failure = null;
        try {
            String json = NativeAgent.packetCaptureReportJson(
                    file,
                    CAPTURE_LIMIT,
                    proxyListenPort);
            if (Thread.currentThread().isInterrupted()) {
                return;
            }
            report = parseCaptureReport(json);
        } catch (Exception error) {
            failure = captureFailureDetail(error);
        }
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
        CaptureReportData result = report;
        String finalFailure = failure;
        MainActivityPacketCapture currentActivity = activityRef.get();
        if (currentActivity == null || !currentActivity.hasPacketCapturePermission()) {
            return;
        }
        currentActivity.runOnUiThread(() -> {
            MainActivityPacketCapture current = activityRef.get();
            if (current != null) {
                current.finishCaptureReport(
                        token,
                        result,
                        finalFailure,
                        showProgress);
            }
        });
    }

    private void finishCaptureReport(
            long token,
            CaptureReportData report,
            String failure,
            boolean showProgress) {
        if (captureUiDestroyed
                || isDestroyed()
                || !hasPacketCapturePermission()
                || token != captureOperationToken
                || captureOperation != CaptureOperation.REFRESHING) {
            return;
        }
        captureOperation = CaptureOperation.NONE;
        captureReportFuture = null;
        updatePacketCaptureControls();
        if (failure == null) {
            applyCaptureReport(report);
        } else {
            showCaptureError("读取抓包失败：", failure, showProgress);
        }
    }

    private boolean canStartCaptureOperation() {
        return AgentUiPermissionPolicy.captureOperationAllowed(
                hasPacketCapturePermission(),
                captureUiDestroyed || isDestroyed(),
                captureOperation != CaptureOperation.NONE,
                capturePacketList != null);
    }

    static boolean captureOperationCanStart(
            boolean hasPermission,
            boolean destroyed,
            boolean operationInFlight,
            boolean uiReady) {
        return AgentUiPermissionPolicy.captureOperationAllowed(
                hasPermission,
                destroyed,
                operationInFlight,
                uiReady);
    }

    private boolean hasPacketCapturePermission() {
        return hasAgentPermission(AgentPermissions.PACKET_CAPTURE);
    }

    private boolean requirePacketCapturePermission() {
        if (hasPacketCapturePermission()) {
            return true;
        }
        showAgentPermissionDenied();
        return false;
    }

    private long beginCaptureOperation(CaptureOperation operation) {
        if (!canStartCaptureOperation() || operation == CaptureOperation.NONE) {
            return -1;
        }
        captureOperation = operation;
        long token = ++captureOperationToken;
        updatePacketCaptureControls();
        return token;
    }

    private void postCaptureOperationResult(
            long token,
            CaptureOperation operation,
            Runnable result) {
        if (captureUiDestroyed) {
            return;
        }
        runOnUiThread(() -> {
            if (captureUiDestroyed
                    || isDestroyed()
                    || token != captureOperationToken
                    || captureOperation != operation) {
                return;
            }
            captureOperation = CaptureOperation.NONE;
            result.run();
        });
    }

    static String captureFailureDetail(Throwable error) {
        if (error == null) {
            return "未知错误";
        }
        String message = error.getMessage();
        if (message != null && !message.trim().isEmpty()) {
            return message.trim();
        }
        String type = error.getClass().getSimpleName();
        return type.isEmpty() ? "未知错误" : type;
    }

    private void showCaptureError(String prefix, String detail) {
        showCaptureError(prefix, detail, true);
    }

    private void showCaptureError(String prefix, String detail, boolean showToast) {
        if (captureUiDestroyed || isDestroyed()) {
            return;
        }
        String message = tr(prefix) + tr(detail);
        captureSummary.setText(message);
        if (showToast) {
            Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        }
    }

    private void applyCaptureReport(CaptureReportData report) {
        if (!hasPacketCapturePermission()) {
            capturePackets = new JSONArray();
            captureSearchIndexes = new ArrayList<>();
            return;
        }
        capturePackets = report.packets;
        captureSearchIndexes = report.searchIndexes;
        updateProtocolOptions();
        renderPacketList();
        captureSummary.setText(tr(String.format(
                Locale.US,
                "共 %d 包 · 显示最近 %d 包 · PCAP %s · 点击查看详情",
                report.totalPackets,
                capturePackets.length(),
                formatBytes(report.fileSize))));
        updatePacketCaptureControls();
    }

    private static CaptureReportData parseCaptureReport(String json) throws JSONException {
        if (json == null || json.trim().isEmpty()) {
            throw new JSONException("原生抓包服务返回空结果");
        }
        JSONObject report = new JSONObject(json);
        if (report.has("error")) {
            String error = report.optString("error", "").trim();
            throw new JSONException(error.isEmpty() ? "未知错误" : error);
        }

        JSONArray rawPackets = report.optJSONArray("packets");
        if (rawPackets == null) {
            rawPackets = new JSONArray();
        }
        int start = Math.max(0, rawPackets.length() - CAPTURE_LIMIT);
        JSONArray packets = new JSONArray();
        ArrayList<String> searchIndexes = new ArrayList<>(
                Math.min(CAPTURE_LIMIT, rawPackets.length()));
        for (int index = start; index < rawPackets.length(); index++) {
            JSONObject packet = rawPackets.optJSONObject(index);
            if (packet == null) {
                continue;
            }
            normalizePayloadPreview(packet);
            packets.put(packet);
            searchIndexes.add(packetSearchIndex(packet));
        }
        return new CaptureReportData(
                Math.max(report.optInt("total_packets"), packets.length()),
                Math.max(0L, report.optLong("file_size")),
                packets,
                searchIndexes);
    }

    private static void normalizePayloadPreview(JSONObject packet) throws JSONException {
        String payloadText = optionalStringValue(packet, "payload_text");
        String payloadHex = optionalStringValue(packet, "payload_hex");
        int availableBytes = Math.max(payloadText.length(), hexByteCount(payloadHex));
        int totalBytes = Math.max(0, packet.optInt("payload_length", availableBytes));
        if (totalBytes == 0 && availableBytes > 0) {
            totalBytes = availableBytes;
        }
        int declaredPreviewBytes = packet.has("payload_preview_length")
                ? packet.optInt("payload_preview_length", availableBytes)
                : -1;
        int previewBytes = boundedPayloadPreviewLength(
                totalBytes,
                declaredPreviewBytes,
                availableBytes);
        boolean truncated = payloadPreviewIsTruncated(
                totalBytes,
                availableBytes,
                previewBytes,
                packet.optBoolean("payload_truncated", false));

        packet.put("payload_length", totalBytes);
        packet.put("payload_preview_length", previewBytes);
        packet.put("payload_truncated", truncated);
        packet.put("payload_text", truncatePayloadText(payloadText, previewBytes));
        packet.put("payload_hex", truncatePayloadHex(payloadHex, previewBytes));
    }

    static int boundedPayloadPreviewLength(
            int totalBytes,
            int declaredPreviewBytes,
            int availableBytes) {
        int safeAvailable = Math.max(0, availableBytes);
        int safeTotal = totalBytes > 0 ? totalBytes : safeAvailable;
        int safeDeclared = declaredPreviewBytes >= 0
                ? declaredPreviewBytes : safeAvailable;
        return Math.max(
                0,
                Math.min(
                        PAYLOAD_PREVIEW_BYTES,
                        Math.min(safeTotal, Math.min(safeDeclared, safeAvailable))));
    }

    static boolean payloadPreviewIsTruncated(
            int totalBytes,
            int availableBytes,
            int previewBytes,
            boolean nativeTruncated) {
        int safeTotal = Math.max(0, totalBytes);
        int safeAvailable = Math.max(0, availableBytes);
        int safePreview = Math.max(0, previewBytes);
        return nativeTruncated || safeTotal > safePreview || safeAvailable > safePreview;
    }

    static String payloadPreviewSummary(int previewBytes, int totalBytes) {
        int safePreview = Math.max(0, previewBytes);
        int safeTotal = Math.max(safePreview, totalBytes);
        return "预览前 " + safePreview + " / 共 " + safeTotal + " 字节";
    }

    static String truncatePayloadText(String value, int previewBytes) {
        String safeValue = value == null ? "" : value;
        int end = Math.min(safeValue.length(), Math.max(0, previewBytes));
        return safeValue.substring(0, end);
    }

    static String truncatePayloadHex(String value, int previewBytes) {
        String safeValue = value == null ? "" : value;
        int targetDigits = Math.max(0, previewBytes) * 2;
        if (targetDigits == 0 || safeValue.isEmpty()) {
            return "";
        }
        int digits = 0;
        int end = 0;
        while (end < safeValue.length() && digits < targetDigits) {
            if (Character.digit(safeValue.charAt(end), 16) >= 0) {
                digits++;
            }
            end++;
        }
        return safeValue.substring(0, end).trim();
    }

    private static int hexByteCount(String value) {
        int digits = 0;
        for (int index = 0; index < value.length(); index++) {
            if (Character.digit(value.charAt(index), 16) >= 0) {
                digits++;
            }
        }
        return digits / 2;
    }

    private static String packetSearchIndex(JSONObject packet) {
        String proxyProtocol = optionalStringValue(packet, "proxy_protocol");
        StringBuilder searchable = new StringBuilder()
                .append(optionalStringValue(packet, "source")).append(' ')
                .append(optionalStringValue(packet, "destination")).append(' ')
                .append(optionalStringValue(packet, "source_port")).append(' ')
                .append(optionalStringValue(packet, "destination_port")).append(' ')
                .append(optionalStringValue(packet, "protocol")).append(' ')
                .append(optionalStringValue(packet, "sub_protocol")).append(' ')
                .append(proxyProtocol).append(' ')
                .append(proxyProtocolLabelValue(proxyProtocol)).append(' ')
                .append(optionalStringValue(packet, "summary")).append(' ')
                .append(optionalStringValue(packet, "payload_text")).append(' ')
                .append(optionalStringValue(packet, "payload_hex"));
        if ("HTTP".equals(proxyProtocol)) {
            searchable.append(" http proxy http 代理");
        } else if ("SOCKS5".equals(proxyProtocol)) {
            searchable.append(" socks5 proxy socks5 代理");
        }
        if (packet.optBoolean("payload_truncated", false)) {
            searchable.append(" payload preview 内容预览");
        }
        return searchable.toString().toLowerCase(Locale.ROOT);
    }

    private static String optionalStringValue(JSONObject object, String key) {
        return object == null || object.isNull(key) ? "" : object.optString(key, "");
    }

    private static String proxyProtocolLabelValue(String protocol) {
        return protocol == null || protocol.isEmpty() ? "" : protocol + " 代理";
    }

    @Override
    protected void onDestroy() {
        captureUiDestroyed = true;
        captureOperationToken++;
        captureFilterHandler.removeCallbacks(captureFilterRender);
        Future<?> reportFuture = captureReportFuture;
        captureReportFuture = null;
        if (reportFuture != null) {
            reportFuture.cancel(true);
        }
        super.onDestroy();
    }

    private void updateProtocolOptions() {
        String previous = String.valueOf(captureProtocol.getSelectedItem());
        TreeSet<String> protocols = new TreeSet<>();
        for (int index = 0; index < capturePackets.length(); index++) {
            JSONObject packet = capturePackets.optJSONObject(index);
            if (packet == null) continue;
            protocols.add(packet.optString("protocol"));
            String child = optionalString(packet, "sub_protocol");
            if (!child.isEmpty()) protocols.add(child);
        }
        ArrayList<String> values = new ArrayList<>();
        values.add(ALL_PROTOCOLS);
        values.add(HTTP_PROXY_PROTOCOL);
        values.add(SOCKS5_PROXY_PROTOCOL);
        values.addAll(protocols);
        captureProtocol.setAdapter(spinnerAdapter(values.toArray(new String[0])));
        int selected = values.indexOf(previous);
        captureProtocol.setSelection(Math.max(0, selected));
    }

    private void renderPacketList() {
        if (capturePacketList == null) {
            return;
        }
        capturePacketList.removeAllViews();
        if (!hasPacketCapturePermission()) {
            capturePackets = new JSONArray();
            captureSearchIndexes = new ArrayList<>();
            return;
        }
        ArrayList<JSONObject> visible = filteredPackets();
        if (visible.isEmpty()) {
            capturePacketList.setGravity(Gravity.CENTER);
            TextView empty = mutedText("没有符合条件的数据包", 14f);
            empty.setGravity(Gravity.CENTER);
            empty.setPadding(dp(8), dp(30), dp(8), dp(30));
            capturePacketList.addView(empty, matchWrap());
            return;
        }
        capturePacketList.setGravity(Gravity.TOP | Gravity.START);
        for (JSONObject packet : visible) {
            capturePacketList.addView(packetRow(packet));
        }
    }

    private ArrayList<JSONObject> filteredPackets() {
        String query = captureSearch == null
                ? "" : captureSearch.getText().toString().trim().toLowerCase(Locale.ROOT);
        String direction = captureDirection == null
                ? "全部方向" : String.valueOf(captureDirection.getSelectedItem());
        String protocol = captureProtocol == null
                ? ALL_PROTOCOLS : String.valueOf(captureProtocol.getSelectedItem());
        double minimumBytes = 0;
        try {
            String value = captureMinimumKb == null
                    ? "" : captureMinimumKb.getText().toString().trim();
            if (!value.isEmpty()) minimumBytes = Double.parseDouble(value) * 1024d;
        } catch (NumberFormatException ignored) {
        }
        ArrayList<JSONObject> result = new ArrayList<>();
        for (int index = 0; index < capturePackets.length(); index++) {
            JSONObject packet = capturePackets.optJSONObject(index);
            if (packet == null
                    || !packetMeetsMinimumSize(packet.optLong("length"), minimumBytes)) continue;
            String packetDirection = packet.optString("direction");
            if ("Client → Agent / 目标".equals(direction)
                    && !"upload".equals(packetDirection)) continue;
            if ("Agent / 目标 → Client".equals(direction)
                    && !"download".equals(packetDirection)) continue;
            if (!matchesProtocolFilter(packet, protocol)) continue;
            String haystack = index < captureSearchIndexes.size()
                    ? captureSearchIndexes.get(index)
                    : packetSearchIndex(packet);
            if (query.isEmpty() || haystack.contains(query)) result.add(packet);
        }
        Comparator<JSONObject> comparator;
        switch (captureSort == null ? 0 : captureSort.getSelectedItemPosition()) {
            case 1:
                comparator = Comparator.comparingLong(packet -> packet.optLong("timestamp_ms"));
                break;
            case 2:
                comparator = (left, right) -> Long.compare(
                        right.optLong("length"), left.optLong("length"));
                break;
            case 3:
                comparator = Comparator.comparingLong(packet -> packet.optLong("length"));
                break;
            case 4:
                comparator = Comparator.comparing(this::packetProtocol);
                break;
            case 5:
                comparator = Comparator.comparing(packet -> endpoint(packet, true));
                break;
            case 6:
                comparator = Comparator.comparing(packet -> endpoint(packet, false));
                break;
            default:
                comparator = (left, right) -> Long.compare(
                        right.optLong("timestamp_ms"), left.optLong("timestamp_ms"));
                break;
        }
        result.sort(comparator);
        return result;
    }

    static boolean packetMeetsMinimumSize(long packetBytes, double minimumBytes) {
        double safeMinimum = Double.isFinite(minimumBytes)
                ? Math.max(0d, minimumBytes)
                : 0d;
        return packetBytes >= safeMinimum;
    }

    private View packetRow(JSONObject packet) {
        boolean upload = "upload".equals(packet.optString("direction"));
        LinearLayout row = horizontalRow();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(7), dp(6), dp(7), dp(6));
        row.setMinimumHeight(dp(54));
        row.setBackgroundColor(COLOR_SURFACE);
        row.setClickable(true);
        row.setFocusable(true);
        row.setContentDescription(tr(
                (upload ? "Client 到 Agent 或目标" : "Agent 或目标到 Client")
                        + "，数据包 " + packet.optInt("number")
                        + "，" + packetProtocol(packet)));
        row.setOnClickListener(view -> showPacketDetail(packet));

        TextView direction = new TextView(this);
        direction.setText(upload ? "↑" : "↓");
        direction.setTextSize(13f);
        direction.setTypeface(Typeface.DEFAULT_BOLD);
        direction.setGravity(Gravity.CENTER);
        direction.setTextColor(upload ? COLOR_STATUS_RUNNING : COLOR_ACTION_INFO);
        direction.setBackground(rounded(
                upload ? COLOR_ACTION_START_SOFT : COLOR_ACTION_INFO_SOFT,
                upload ? COLOR_STATUS_RUNNING : COLOR_ACTION_INFO));
        LinearLayout.LayoutParams directionParams = new LinearLayout.LayoutParams(dp(24), dp(24));
        directionParams.setMargins(0, 0, dp(7), 0);
        row.addView(direction, directionParams);

        LinearLayout textColumn = new LinearLayout(this);
        textColumn.setOrientation(LinearLayout.VERTICAL);
        TextView endpoints = titleText(
                endpoint(packet, true) + "  →  " + endpoint(packet, false), 12f);
        endpoints.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        endpoints.setSingleLine(true);
        endpoints.setEllipsize(TextUtils.TruncateAt.END);
        textColumn.addView(endpoints, matchWrap());

        TextView summary = mutedText(
                "#" + packet.optInt("number") + " · " + packet.optString("summary"), 10f);
        summary.setSingleLine(true);
        summary.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams summaryRowParams = matchWrap();
        summaryRowParams.setMargins(0, dp(3), 0, 0);
        textColumn.addView(summary, summaryRowParams);
        row.addView(textColumn, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        LinearLayout metaColumn = new LinearLayout(this);
        metaColumn.setOrientation(LinearLayout.VERTICAL);
        metaColumn.setGravity(Gravity.END);
        TextView protocol = chip(packetProtocol(packet), COLOR_ACTION_INFO);
        protocol.setTextSize(9f);
        LinearLayout.LayoutParams protocolParams = wrapWrap();
        protocolParams.gravity = Gravity.END;
        metaColumn.addView(protocol, protocolParams);
        TextView meta = mutedText(
                packet.optInt("length") + " B · "
                        + packetTime(packet.optLong("timestamp_ms")), 9f);
        meta.setSingleLine(true);
        LinearLayout.LayoutParams metaTextParams = wrapWrap();
        metaTextParams.gravity = Gravity.END;
        metaTextParams.setMargins(0, dp(3), 0, 0);
        metaColumn.addView(meta, metaTextParams);
        LinearLayout.LayoutParams metaParams = wrapWrap();
        metaParams.setMargins(dp(6), 0, 0, 0);
        row.addView(metaColumn, metaParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        if (capturePacketList.getChildCount() > 0) {
            rowParams.setMargins(0, dp(1), 0, 0);
        }
        row.setLayoutParams(rowParams);
        return row;
    }

    private void showPacketDetail(JSONObject packet) {
        if (!requirePacketCapturePermission()) {
            return;
        }
        boolean upload = "upload".equals(packet.optString("direction"));
        Dialog dialog = new Dialog(this);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);

        LinearLayout dialogRoot = new LinearLayout(this);
        dialogRoot.setOrientation(LinearLayout.VERTICAL);
        dialogRoot.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));

        LinearLayout header = horizontalRow();
        header.setPadding(dp(16), dp(12), dp(10), dp(11));
        LinearLayout heading = new LinearLayout(this);
        heading.setOrientation(LinearLayout.VERTICAL);
        TextView title = titleText("数据包 #" + packet.optInt("number"), 18f);
        heading.addView(title, matchWrap());
        TextView subtitle = mutedText(
                (upload ? "Client → Agent / 目标" : "Agent / 目标 → Client")
                        + "  ·  IPv" + packet.optInt("ip_version")
                        + "  ·  " + packetProtocol(packet), 11f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(2), 0, 0);
        heading.addView(subtitle, subtitleParams);
        header.addView(heading, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button close = new Button(this);
        close.setText("×");
        close.setTextSize(22f);
        close.setTextColor(COLOR_MUTED);
        close.setAllCaps(false);
        close.setMinWidth(0);
        close.setMinHeight(0);
        close.setPadding(0, 0, 0, 0);
        flattenButton(close);
        close.setBackgroundColor(Color.TRANSPARENT);
        close.setOnClickListener(view -> dialog.dismiss());
        header.addView(close, new LinearLayout.LayoutParams(dp(36), dp(36)));
        dialogRoot.addView(header, matchWrap());
        View headerDivider = new View(this);
        headerDivider.setBackgroundColor(alphaColor(COLOR_BORDER, 112));
        dialogRoot.addView(headerDivider, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(14), dp(12), dp(14), dp(16));

        TextView routeTitle = detailSectionTitle("数据流");
        content.addView(routeTitle, matchWrap());
        LinearLayout route = new LinearLayout(this);
        route.setOrientation(LinearLayout.VERTICAL);
        route.setPadding(dp(11), dp(8), dp(11), dp(8));
        route.setBackground(rounded(COLOR_BACKGROUND, alphaColor(COLOR_BORDER, 128)));
        TextView source = bodyText(endpoint(packet, true), 12f);
        source.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        source.setTextIsSelectable(true);
        route.addView(source, matchWrap());
        TextView arrow = mutedText(
                upload ? "↓  Client → Agent / 目标" : "↓  Agent / 目标 → Client",
                10f);
        LinearLayout.LayoutParams arrowParams = matchWrap();
        arrowParams.setMargins(0, dp(2), 0, dp(2));
        route.addView(arrow, arrowParams);
        TextView destination = bodyText(endpoint(packet, false), 12f);
        destination.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        destination.setTextIsSelectable(true);
        route.addView(destination, matchWrap());
        LinearLayout facts = horizontalRow();
        TextView time = mutedText(packetTime(packet.optLong("timestamp_ms")), 10f);
        facts.addView(time, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView length = mutedText(packet.optInt("length") + " B", 10f);
        length.setTypeface(Typeface.DEFAULT_BOLD);
        facts.addView(length, wrapWrap());
        LinearLayout.LayoutParams factsParams = matchWrap();
        factsParams.setMargins(0, dp(7), 0, 0);
        route.addView(facts, factsParams);
        LinearLayout.LayoutParams routeParams = matchWrap();
        routeParams.setMargins(0, dp(5), 0, 0);
        content.addView(route, routeParams);

        TextView analysisTitle = detailSectionTitle("协议分析");
        LinearLayout.LayoutParams analysisParams = matchWrap();
        analysisParams.setMargins(0, dp(14), 0, dp(5));
        content.addView(analysisTitle, analysisParams);
        LinearLayout layersView = new LinearLayout(this);
        layersView.setOrientation(LinearLayout.VERTICAL);
        layersView.setBackgroundColor(alphaColor(COLOR_BORDER, 72));
        JSONArray layers = packet.optJSONArray("protocol_layers");
        if (layers != null) {
            for (int index = 0; index < layers.length(); index++) {
                JSONObject layer = layers.optJSONObject(index);
                if (layer != null) layersView.addView(protocolLayerView(layer));
            }
        }
        FrameLayout layersFrame = framedContainer(layersView);
        content.addView(layersFrame, matchWrap());

        TextView rawTitle = detailSectionTitle("原始数据");
        LinearLayout.LayoutParams rawTitleParams = matchWrap();
        rawTitleParams.setMargins(0, dp(14), 0, dp(5));
        content.addView(rawTitle, rawTitleParams);
        int totalPayloadBytes = Math.max(0, packet.optInt("payload_length", 0));
        int previewPayloadBytes = Math.max(
                0,
                packet.optInt(
                        "payload_preview_length",
                        Math.min(totalPayloadBytes, PAYLOAD_PREVIEW_BYTES)));
        String previewSummary = payloadPreviewSummary(
                previewPayloadBytes,
                totalPayloadBytes);
        View hexPayload = payloadView(
                "Payload Hex（" + previewSummary + "）",
                packet.optString("payload_hex", "无 Payload"));
        content.addView(hexPayload, matchWrap());
        View asciiPayload = payloadView(
                "ASCII（" + previewSummary + "）",
                packet.optString("payload_text", "无 Payload"));
        LinearLayout.LayoutParams asciiPayloadParams = matchWrap();
        asciiPayloadParams.setMargins(0, dp(12), 0, 0);
        content.addView(asciiPayload, asciiPayloadParams);
        if (packet.optBoolean("payload_truncated", false)) {
            TextView previewNote = mutedText(
                    "仅显示 Payload 预览，内容搜索也只覆盖这部分数据",
                    10.5f);
            LinearLayout.LayoutParams previewNoteParams = matchWrap();
            previewNoteParams.setMargins(0, dp(7), 0, 0);
            content.addView(previewNote, previewNoteParams);
        }

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(false);
        scroll.setVerticalScrollBarEnabled(true);
        scroll.addView(content, matchWrap());
        dialogRoot.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        dialog.setContentView(dialogRoot);
        dialog.show();
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            WindowManager.LayoutParams attributes = window.getAttributes();
            attributes.dimAmount = 0.36f;
            window.setAttributes(attributes);
            window.setLayout(
                    (int) (getResources().getDisplayMetrics().widthPixels * 0.94f),
                    (int) (getResources().getDisplayMetrics().heightPixels * 0.88f));
        }
    }

    private View detailFact(String label, String value) {
        LinearLayout row = horizontalRow();
        row.setPadding(0, dp(4), 0, 0);
        TextView name = mutedText(label, 11f);
        row.addView(name, new LinearLayout.LayoutParams(dp(108), ViewGroup.LayoutParams.WRAP_CONTENT));
        TextView text = bodyText(value, 12f);
        text.setTextIsSelectable(true);
        row.addView(text, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private View protocolLayerView(JSONObject layer) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(10), dp(7), dp(10), dp(7));
        box.setBackgroundColor(COLOR_SURFACE);
        TextView title = bodyText(
                layer.optString("name") + "  " + layer.optString("summary"), 12f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setSingleLine(false);
        box.addView(title, matchWrap());
        JSONArray fields = layer.optJSONArray("fields");
        if (fields != null) {
            for (int index = 0; index < fields.length(); index++) {
                JSONObject field = fields.optJSONObject(index);
                if (field != null) {
                    box.addView(detailFact(
                            field.optString("name"),
                            field.optString("value")), matchWrap());
                }
            }
        }
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, dp(1), 0, 0);
        box.setLayoutParams(params);
        return box;
    }

    private View payloadView(String title, String value) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(10), dp(8), dp(10), dp(9));
        box.setBackground(rounded(COLOR_BACKGROUND, alphaColor(COLOR_BORDER, 128)));
        TextView label = mutedText(title, 11f);
        label.setTypeface(Typeface.DEFAULT_BOLD);
        box.addView(label, matchWrap());
        boolean ascii = title.startsWith("ASCII");
        String displayValue = value.isEmpty() || "无 Payload".equals(value)
                ? tr("无 Payload") : value;
        TextView text = bodyText(displayValue, ascii ? 12f : 10.5f);
        text.setTypeface(Typeface.MONOSPACE);
        text.setTextIsSelectable(true);
        text.setHorizontallyScrolling(false);
        text.setGravity(Gravity.TOP | Gravity.START);
        if (ascii) text.setMinHeight(dp(96));
        LinearLayout.LayoutParams textParams = matchWrap();
        textParams.setMargins(0, dp(6), 0, 0);
        box.addView(text, textParams);
        return box;
    }

    private TextView detailSectionTitle(String text) {
        TextView title = mutedText(text, 11f);
        title.setTextColor(COLOR_ACCENT_DARK);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        return title;
    }

    private FrameLayout framedContainer(View content) {
        FrameLayout frame = new FrameLayout(this);
        frame.setClipChildren(true);
        frame.setClipToOutline(true);
        GradientDrawable surface = new GradientDrawable();
        surface.setColor(COLOR_SURFACE);
        surface.setCornerRadius(dp(9));
        frame.setBackground(surface);
        GradientDrawable border = new GradientDrawable();
        border.setColor(Color.TRANSPARENT);
        border.setCornerRadius(dp(9));
        border.setStroke(dp(1), alphaColor(COLOR_BORDER, 112));
        frame.setForeground(border);
        frame.addView(content, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        return frame;
    }

    private boolean matchesProtocolFilter(JSONObject packet, String selectedProtocol) {
        if (ALL_PROTOCOLS.equals(selectedProtocol)) {
            return true;
        }
        if (selectedProtocol.equals(packet.optString("protocol"))
                || selectedProtocol.equals(optionalString(packet, "sub_protocol"))) {
            return true;
        }
        return selectedProtocol.equals(
                proxyProtocolLabel(optionalString(packet, "proxy_protocol")));
    }

    private String packetProtocol(JSONObject packet) {
        LinkedHashSet<String> labels = new LinkedHashSet<>();
        String base = packet.optString("protocol");
        String proxy = optionalString(packet, "proxy_protocol");
        String child = optionalString(packet, "sub_protocol");
        if (!base.isEmpty()) {
            labels.add(base);
        }
        if (!proxy.isEmpty()) {
            labels.add(proxyProtocolLabel(proxy));
        }
        if (!child.isEmpty() && !child.equals(proxy)) {
            labels.add(child);
        }
        return String.join(" / ", labels);
    }

    private String proxyProtocolLabel(String protocol) {
        return proxyProtocolLabelValue(protocol);
    }

    private String optionalString(JSONObject object, String key) {
        return object.isNull(key) ? "" : object.optString(key);
    }

    private String endpoint(JSONObject packet, boolean source) {
        String address = packet.optString(source ? "source" : "destination");
        if (address.contains(":")) address = "[" + address + "]";
        String portKey = source ? "source_port" : "destination_port";
        return packet.isNull(portKey) ? address : address + ":" + packet.optInt(portKey);
    }

    private String packetTime(long timestampMs) {
        return new SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(new Date(timestampMs));
    }

    private Spinner spinner(String[] values) {
        Spinner spinner = new Spinner(this);
        spinner.setAdapter(spinnerAdapter(values));
        spinner.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
        spinner.setPadding(dp(10), 0, dp(8), 0);
        return spinner;
    }

    private ArrayAdapter<String> spinnerAdapter(String[] values) {
        return new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, values) {
            private TextView style(View view, boolean dropdown) {
                TextView text = (TextView) view;
                text.setText(tr(text.getText().toString()));
                text.setTextColor(COLOR_TEXT);
                text.setTextSize(dropdown ? 13f : 12f);
                text.setGravity(Gravity.CENTER_VERTICAL);
                text.setSingleLine(true);
                text.setPadding(dp(10), dropdown ? dp(10) : 0, dp(10), dropdown ? dp(10) : 0);
                if (dropdown) {
                    text.setBackgroundColor(COLOR_SURFACE);
                }
                return text;
            }

            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                return style(super.getView(position, convertView, parent), false);
            }

            @Override
            public View getDropDownView(int position, View convertView, ViewGroup parent) {
                return style(super.getDropDownView(position, convertView, parent), true);
            }
        };
    }

    private LinearLayout filterField(String label, View control) {
        LinearLayout field = new LinearLayout(this);
        field.setOrientation(LinearLayout.VERTICAL);
        TextView labelView = mutedText(label, 11f);
        labelView.setTypeface(Typeface.DEFAULT_BOLD);
        field.addView(labelView, matchWrap());
        LinearLayout.LayoutParams controlParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(42));
        controlParams.setMargins(0, dp(4), 0, 0);
        field.addView(control, controlParams);
        return field;
    }

    private void resetPacketFilters() {
        if (!requirePacketCapturePermission()) {
            return;
        }
        captureSearch.setText("");
        captureMinimumKb.setText("");
        captureDirection.setSelection(0);
        captureProtocol.setSelection(0);
        captureSort.setSelection(0);
        renderPacketListImmediately();
    }

    private void schedulePacketFilterRender() {
        captureFilterHandler.removeCallbacks(captureFilterRender);
        captureFilterHandler.postDelayed(
                captureFilterRender,
                CAPTURE_FILTER_DEBOUNCE_MS);
    }

    private void renderPacketListImmediately() {
        captureFilterHandler.removeCallbacks(captureFilterRender);
        renderPacketList();
    }

    private TextView bodyText(String value, float size) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextColor(COLOR_TEXT);
        view.setTextSize(size);
        return view;
    }

    private EditText captureEditText(String hint, boolean numeric) {
        EditText edit = new EditText(this);
        edit.setHint(tr(hint));
        edit.setTextColor(COLOR_TEXT);
        edit.setHintTextColor(COLOR_MUTED);
        edit.setTextSize(13f);
        edit.setSingleLine(true);
        edit.setPadding(dp(12), 0, dp(12), 0);
        edit.setBackground(rounded(COLOR_SURFACE, COLOR_BORDER));
        if (numeric) {
            edit.setInputType(android.text.InputType.TYPE_CLASS_NUMBER
                    | android.text.InputType.TYPE_NUMBER_FLAG_DECIMAL);
        }
        return edit;
    }

    private LinearLayout.LayoutParams wrapWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private AdapterView.OnItemSelectedListener filterListener() {
        return new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                renderPacketListImmediately();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        };
    }

    private TextWatcher filterWatcher() {
        return new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                schedulePacketFilterRender();
            }
            @Override public void afterTextChanged(Editable s) {}
        };
    }
}
