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
import java.text.*;
import java.util.*;

abstract class MainActivityPacketCapture extends MainActivityConfigScreen {
    private static final int CAPTURE_LIMIT = 2000;
    private static final long CAPTURE_REFRESH_MS = 5000L;

    private TextView captureStatus;
    private TextView captureSummary;
    private Button captureToggle;
    private Button captureClear;
    private EditText captureSearch;
    private EditText captureMinimumKb;
    private Spinner captureDirection;
    private Spinner captureProtocol;
    private Spinner captureSort;
    private LinearLayout capturePacketList;
    private JSONArray capturePackets = new JSONArray();
    private boolean captureRefreshInFlight;
    private long lastCaptureRefreshMs;

    protected void buildPacketCaptureScreen(LinearLayout root) {
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
        Button refresh = secondaryButton("刷新");
        refresh.setOnClickListener(view -> refreshPacketCapture(true));
        LinearLayout.LayoutParams refreshParams = new LinearLayout.LayoutParams(0, dp(42), 1f);
        refreshParams.setMargins(dp(8), 0, 0, 0);
        actionRow.addView(refresh, refreshParams);
        LinearLayout.LayoutParams actionParams = matchWrap();
        actionParams.setMargins(0, dp(8), 0, 0);
        header.addView(actionRow, actionParams);

        LinearLayout filters = panel(root);
        sectionTitle(filters, "筛选与排序");
        captureSearch = captureEditText("搜索 IP、端口、协议或内容", false);
        captureSearch.addTextChangedListener(filterWatcher());
        filters.addView(filterField("搜索", captureSearch), matchWrap());

        LinearLayout filterRow = horizontalRow();
        captureDirection = spinner(new String[]{"全部方向", "Client → 目标", "目标 → Client"});
        captureDirection.setOnItemSelectedListener(filterListener());
        filterRow.addView(
                filterField("方向", captureDirection),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        captureProtocol = spinner(new String[]{"全部协议"});
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
        TextView filterHint = mutedText("筛选条件会立即应用", 11f);
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
        packets.setPadding(dp(10), dp(16), dp(10), dp(12));
        sectionTitle(packets, "数据包列表");
        captureSummary = mutedText("尚未读取抓包文件", 12f);
        LinearLayout.LayoutParams summaryParams = matchWrap();
        summaryParams.setMargins(0, dp(2), 0, dp(10));
        packets.addView(captureSummary, summaryParams);
        MaxHeightScrollView scroll = new MaxHeightScrollView(this, dp(560));
        scroll.setVerticalScrollBarEnabled(false);
        scroll.setNestedScrollingEnabled(true);
        scroll.setClipToPadding(true);
        scroll.setFillViewport(false);
        capturePacketList = new LinearLayout(this);
        capturePacketList.setOrientation(LinearLayout.VERTICAL);
        capturePacketList.setBackgroundColor(alphaColor(COLOR_BORDER, 72));
        scroll.addView(capturePacketList, matchWrap());

        FrameLayout listContainer = new FrameLayout(this);
        listContainer.setClipChildren(true);
        listContainer.setClipToOutline(true);
        GradientDrawable listSurface = new GradientDrawable();
        listSurface.setColor(COLOR_SURFACE);
        listSurface.setCornerRadius(dp(10));
        listContainer.setBackground(listSurface);
        GradientDrawable listFrame = new GradientDrawable();
        listFrame.setColor(Color.TRANSPARENT);
        listFrame.setCornerRadius(dp(10));
        listFrame.setStroke(dp(1), alphaColor(COLOR_BORDER, 112));
        listContainer.setForegroundGravity(Gravity.FILL);
        listContainer.setForeground(listFrame);
        listContainer.addView(scroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        packets.addView(listContainer, matchWrap());

        updatePacketCaptureControls();
        refreshPacketCapture(true);
    }

    @Override
    protected void updateStatusMetrics() {
        super.updateStatusMetrics();
        updatePacketCaptureControls();
        if (selectedScreenIndex == 1
                && SystemClock.elapsedRealtime() - lastCaptureRefreshMs >= CAPTURE_REFRESH_MS) {
            refreshPacketCapture(false);
        }
    }

    protected void updatePacketCaptureControls() {
        if (captureToggle == null) {
            return;
        }
        boolean running = isVpnRunning();
        boolean enabled = NativeAgent.packetCaptureEnabled();
        captureToggle.setEnabled(true);
        captureToggle.setText(tr(enabled ? "关闭抓包" : "开启抓包"));
        applyActionButtonStyle(
                captureToggle,
                enabled ? COLOR_ACTION_STOP : COLOR_ACTION_START);
        captureStatus.setText(tr(enabled
                ? running ? "●  正在抓包" : "●  已开启，等待 VPN"
                : "●  抓包已关闭"));
        captureStatus.setTextColor(enabled ? COLOR_STATUS_RUNNING : COLOR_ACTION_WARN);
        captureClear.setEnabled(captureFile().exists());
    }

    private File captureFile() {
        return new File(new File(getFilesDir(), "captures"), "ppaass-tun.pcap");
    }

    private void togglePacketCapture() {
        boolean enabled = !NativeAgent.packetCaptureEnabled();
        if (NativeAgent.setPacketCaptureEnabled(captureFile().getAbsolutePath(), enabled)) {
            updatePacketCaptureControls();
            refreshPacketCapture(true);
        }
    }

    private void confirmClearPacketCapture() {
        new AlertDialog.Builder(this)
                .setTitle(tr("清空抓包文件"))
                .setMessage(tr("将永久删除当前全部抓包记录。抓包若已开启，清空后会继续记录。"))
                .setNegativeButton(tr("取消"), null)
                .setPositiveButton(tr("确认清空"), (dialog, which) -> {
                    if (NativeAgent.clearPacketCapture(captureFile().getAbsolutePath())) {
                        refreshPacketCapture(true);
                    }
                })
                .show();
    }

    private void refreshPacketCapture(boolean showProgress) {
        if (captureRefreshInFlight || capturePacketList == null) {
            return;
        }
        captureRefreshInFlight = true;
        lastCaptureRefreshMs = SystemClock.elapsedRealtime();
        if (showProgress) {
            captureSummary.setText(tr("正在读取抓包结果…"));
        }
        String file = captureFile().getAbsolutePath();
        new Thread(() -> {
            String json;
            try {
                json = NativeAgent.packetCaptureReportJson(file, CAPTURE_LIMIT);
            } catch (RuntimeException error) {
                json = "{\"error\":" + JSONObject.quote(String.valueOf(error)) + "}";
            }
            final String result = json;
            runOnUiThread(() -> {
                captureRefreshInFlight = false;
                applyCaptureReport(result);
            });
        }, "ppaass-capture-reader").start();
    }

    private void applyCaptureReport(String json) {
        try {
            JSONObject report = new JSONObject(json);
            if (report.has("error")) {
                throw new JSONException(report.optString("error"));
            }
            capturePackets = report.optJSONArray("packets");
            if (capturePackets == null) {
                capturePackets = new JSONArray();
            }
            updateProtocolOptions();
            renderPacketList();
            captureSummary.setText(tr(String.format(
                    Locale.US,
                    "共 %d 包 · 显示最近 %d 包 · PCAP %s · 点击查看详情",
                    report.optInt("total_packets"),
                    capturePackets.length(),
                    formatBytes(report.optLong("file_size")))));
            updatePacketCaptureControls();
        } catch (JSONException error) {
            captureSummary.setText(tr("读取抓包失败：" + error.getMessage()));
        }
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
        values.add("全部协议");
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
        ArrayList<JSONObject> visible = filteredPackets();
        if (visible.isEmpty()) {
            TextView empty = mutedText("没有符合条件的数据包", 14f);
            empty.setGravity(Gravity.CENTER);
            empty.setPadding(dp(8), dp(30), dp(8), dp(30));
            capturePacketList.addView(empty, matchWrap());
            return;
        }
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
                ? "全部协议" : String.valueOf(captureProtocol.getSelectedItem());
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
            if (packet == null || packet.optLong("length") <= minimumBytes) continue;
            String packetDirection = packet.optString("direction");
            if ("Client → 目标".equals(direction) && !"upload".equals(packetDirection)) continue;
            if ("目标 → Client".equals(direction) && !"download".equals(packetDirection)) continue;
            if (!"全部协议".equals(protocol)
                    && !protocol.equals(packet.optString("protocol"))
                    && !protocol.equals(optionalString(packet, "sub_protocol"))) continue;
            String haystack = (
                    packet.optString("source") + " "
                            + packet.optString("destination") + " "
                            + packet.optString("source_port") + " "
                            + packet.optString("destination_port") + " "
                            + packet.optString("protocol") + " "
                            + optionalString(packet, "sub_protocol") + " "
                            + packet.optString("summary") + " "
                            + packet.optString("payload_text") + " "
                            + packet.optString("payload_hex")).toLowerCase(Locale.ROOT);
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

    private View packetRow(JSONObject packet) {
        boolean upload = "upload".equals(packet.optString("direction"));
        LinearLayout row = horizontalRow();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(7), dp(6), dp(7), dp(6));
        row.setMinimumHeight(dp(54));
        row.setBackgroundColor(COLOR_SURFACE);
        row.setClickable(true);
        row.setFocusable(true);
        row.setContentDescription(
                (upload ? "Client 到目标" : "目标到 Client")
                        + "，数据包 " + packet.optInt("number")
                        + "，" + packetProtocol(packet));
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
                (upload ? "Client → 目标" : "目标 → Client")
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
        TextView arrow = mutedText(upload ? "↓  Client → 目标" : "↓  目标 → Client", 10f);
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
        View hexPayload = payloadView(
                "Payload Hex（完整 " + packet.optInt("payload_length") + " 字节）",
                packet.optString("payload_hex", "无 Payload"));
        content.addView(hexPayload, matchWrap());
        View asciiPayload = payloadView(
                "ASCII",
                packet.optString("payload_text", "无 Payload"));
        LinearLayout.LayoutParams asciiPayloadParams = matchWrap();
        asciiPayloadParams.setMargins(0, dp(12), 0, 0);
        content.addView(asciiPayload, asciiPayloadParams);

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
        boolean ascii = "ASCII".equals(title);
        TextView text = bodyText(value.isEmpty() ? "无 Payload" : value, ascii ? 12f : 10.5f);
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

    private String packetProtocol(JSONObject packet) {
        String base = packet.optString("protocol");
        String child = optionalString(packet, "sub_protocol");
        return child.isEmpty() ? base : base + " / " + child;
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
        captureSearch.setText("");
        captureMinimumKb.setText("");
        captureDirection.setSelection(0);
        captureProtocol.setSelection(0);
        captureSort.setSelection(0);
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
                renderPacketList();
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
                renderPacketList();
            }
            @Override public void afterTextChanged(Editable s) {}
        };
    }
}
