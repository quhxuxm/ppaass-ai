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
abstract class MainActivityConnectivity extends MainActivityServiceState {

protected void updateConnectivityButton() {
        if (connectivityTestButton == null) {
            return;
        }
        boolean running = isVpnRunning();
        connectivityTestButton.setEnabled(running && !connectivityTestsRunning);
        connectivityTestButton.setText(connectivityTestsRunning ? "测试中" : "测试");
        applyActionButtonStyle(
                connectivityTestButton,
                running ? COLOR_ACTION_INFO : COLOR_STATUS_STOPPED);
        if (connectivitySummary != null && !running && !connectivityTestsRunning) {
            connectivitySummary.setText("启动 VPN 后运行测试");
        }
    }

protected void runConnectivityTests() {
        if (connectivityTestsRunning) {
            return;
        }
        if (!isVpnRunning()) {
            Toast.makeText(this, "请先启动 VPN 再运行测试", Toast.LENGTH_SHORT).show();
            updateConnectivityButton();
            return;
        }

        connectivityTestsRunning = true;
        updateConnectivityButton();
        if (connectivitySummary != null) {
            connectivitySummary.setText("正在测试 Google 和 YouTube");
        }
        if (connectivityResultList != null) {
            connectivityResultList.removeAllViews();
            addConnectivityEmptyRow("正在运行 HTTPS 和 QUIC 检查");
        }

        new Thread(() -> {
            List<ConnectivityCheckResult> results = new ArrayList<>();
            results.add(runHttpsConnectivityCheck(
                    "Google",
                    "https://www.google.com/generate_204"));
            results.add(runHttpsConnectivityCheck(
                    "YouTube",
                    "https://www.youtube.com/generate_204"));
            results.add(runQuicConnectivityCheck("Google", "www.google.com"));
            results.add(runQuicConnectivityCheck("YouTube", "www.youtube.com"));

            runOnUiThread(() -> {
                connectivityTestsRunning = false;
                renderConnectivityResults(results);
                updateConnectivityButton();
            });
        }, "ppaass-connectivity-tests").start();
    }

protected ConnectivityCheckResult runHttpsConnectivityCheck(String target, String urlString) {
        long started = SystemClock.elapsedRealtime();
        long rxBefore = currentVpnDownloadBytes();
        long txBefore = currentVpnUploadBytes();
        HttpURLConnection connection = null;
        boolean networkOk = false;
        String detail;
        try {
            URL url = new URL(urlString);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTIVITY_TIMEOUT_MS);
            connection.setReadTimeout(CONNECTIVITY_TIMEOUT_MS);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "PPAASS-Android-Agent/diagnostic");

            int code = connection.getResponseCode();
            networkOk = code >= 200 && code < 400;
            drainSmallResponse(code >= 400 ? connection.getErrorStream() : connection.getInputStream());
            detail = "HTTP " + code;
        } catch (IOException | RuntimeException error) {
            detail = compactError(error);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return finishConnectivityResult(target, "HTTPS", networkOk, detail, started, rxBefore, txBefore);
    }

protected ConnectivityCheckResult runQuicConnectivityCheck(String target, String host) {
        long started = SystemClock.elapsedRealtime();
        long rxBefore = currentVpnDownloadBytes();
        long txBefore = currentVpnUploadBytes();
        boolean networkOk = false;
        String detail;

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(CONNECTIVITY_TIMEOUT_MS);
            InetAddress address = resolveIpv4(host);
            byte[] dcid = randomConnectionId();
            byte[] scid = randomConnectionId();
            byte[] probe = quicVersionNegotiationProbe(dcid, scid);
            DatagramPacket outbound = new DatagramPacket(probe, probe.length, address, 443);
            socket.send(outbound);

            byte[] response = new byte[1500];
            DatagramPacket inbound = new DatagramPacket(response, response.length);
            socket.receive(inbound);
            networkOk = isQuicVersionNegotiationResponse(response, inbound.getLength());
            detail = networkOk
                    ? "收到 QUIC 版本协商包：" + inbound.getLength() + " B，来源 " + inbound.getAddress().getHostAddress()
                    : "UDP/443 有响应，但不是 QUIC 版本协商包";
        } catch (SocketTimeoutException error) {
            detail = "UDP/443 超时";
        } catch (IOException | RuntimeException error) {
            detail = compactError(error);
        }

        return finishConnectivityResult(target, "QUIC", networkOk, detail, started, rxBefore, txBefore);
    }

protected InetAddress resolveIpv4(String host) throws IOException {
        InetAddress[] addresses = InetAddress.getAllByName(host);
        for (InetAddress address : addresses) {
            if (address instanceof Inet4Address) {
                return address;
            }
        }
        if (addresses.length > 0) {
            return addresses[0];
        }
        throw new IOException("没有可用地址：" + host);
    }

protected ConnectivityCheckResult finishConnectivityResult(
            String target,
            String protocol,
            boolean networkOk,
            String detail,
            long started,
            long rxBefore,
            long txBefore) {
        long durationMs = Math.max(0, SystemClock.elapsedRealtime() - started);
        long rxDelta = Math.max(0, currentVpnDownloadBytes() - rxBefore);
        long txDelta = Math.max(0, currentVpnUploadBytes() - txBefore);
        boolean vpnObserved = rxDelta > 0 || txDelta > 0;
        boolean success = networkOk && vpnObserved;
        String resultDetail = networkOk && !vpnObserved
                ? detail + " · no VPN byte delta"
                : detail;
        return new ConnectivityCheckResult(
                target,
                protocol,
                success,
                resultDetail,
                durationMs,
                rxDelta,
                txDelta);
    }

protected void drainSmallResponse(InputStream stream) throws IOException {
        if (stream == null) {
            return;
        }
        try (InputStream input = stream) {
            byte[] buffer = new byte[256];
            input.read(buffer);
        }
    }

protected byte[] randomConnectionId() {
        byte[] value = new byte[8];
        SECURE_RANDOM.nextBytes(value);
        return value;
    }

protected byte[] quicVersionNegotiationProbe(byte[] dcid, byte[] scid) {
        byte[] packet = new byte[QUIC_MIN_INITIAL_PACKET_BYTES];
        SECURE_RANDOM.nextBytes(packet);
        int offset = 0;
        packet[offset++] = (byte) 0xc0;
        packet[offset++] = (byte) ((QUIC_RESERVED_VERSION >>> 24) & 0xff);
        packet[offset++] = (byte) ((QUIC_RESERVED_VERSION >>> 16) & 0xff);
        packet[offset++] = (byte) ((QUIC_RESERVED_VERSION >>> 8) & 0xff);
        packet[offset++] = (byte) (QUIC_RESERVED_VERSION & 0xff);
        packet[offset++] = (byte) dcid.length;
        System.arraycopy(dcid, 0, packet, offset, dcid.length);
        offset += dcid.length;
        packet[offset++] = (byte) scid.length;
        System.arraycopy(scid, 0, packet, offset, scid.length);
        return packet;
    }

protected boolean isQuicVersionNegotiationResponse(byte[] data, int length) {
        return length >= 7
                && (data[0] & 0x80) != 0
                && data[1] == 0
                && data[2] == 0
                && data[3] == 0
                && data[4] == 0;
    }

protected String compactError(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return error.getClass().getSimpleName();
        }
        return message.length() > 120 ? message.substring(0, 117) + "..." : message;
    }

protected void renderConnectivityResults(List<ConnectivityCheckResult> results) {
        if (connectivityResultList == null) {
            return;
        }
        connectivityResultList.removeAllViews();
        int passed = 0;
        for (ConnectivityCheckResult result : results) {
            if (result.success) {
                passed++;
            }
            addConnectivityResultRow(result);
        }
        if (connectivitySummary != null) {
            connectivitySummary.setText(passed + "/" + results.size() + " checks passed");
        }
    }

protected void addConnectivityEmptyRow(String text) {
        if (connectivityResultList == null) {
            return;
        }
        TextView empty = mutedText(text, 14f);
        empty.setGravity(Gravity.CENTER);
        empty.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));
        connectivityResultList.addView(empty, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(54)));
    }

protected void addConnectivityResultRow(ConnectivityCheckResult result) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(dp(10), dp(9), dp(10), dp(9));
        row.setMinimumHeight(dp(76));
        row.setBackground(rounded(COLOR_CONTROL, COLOR_BORDER));

        LinearLayout heading = horizontalRow();
        TextView name = titleText(result.target + " " + result.protocol, 14f);
        name.setSingleLine(false);
        name.setMaxLines(2);
        name.setEllipsize(null);
        heading.addView(name, new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f));
        TextView status = chip(result.success ? "通过" : "失败",
                result.success ? COLOR_STATUS_RUNNING : COLOR_ACTION_STOP);
        heading.addView(status, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        row.addView(heading, matchWrap());

        TextView detail = mutedText(result.detail, 12f);
        detail.setMaxLines(4);
        detail.setEllipsize(null);
        LinearLayout.LayoutParams detailParams = matchWrap();
        detailParams.setMargins(0, dp(4), 0, 0);
        row.addView(detail, detailParams);

        TextView meta = mutedText(
                result.durationMs + " ms · VPN ↓" + formatBytes(result.rxDelta)
                        + " ↑" + formatBytes(result.txDelta),
                11f);
        LinearLayout.LayoutParams metaParams = matchWrap();
        metaParams.setMargins(0, dp(3), 0, 0);
        row.addView(meta, metaParams);

        LinearLayout.LayoutParams rowParams = matchWrap();
        if (connectivityResultList.getChildCount() > 0) {
            rowParams.setMargins(0, dp(8), 0, 0);
        }
        connectivityResultList.addView(row, rowParams);
    }

}
