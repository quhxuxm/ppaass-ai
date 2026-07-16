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
abstract class MainActivityConfigScreen extends MainActivityStatusScreen {

protected void buildConfigScreen(LinearLayout root) {
        LinearLayout actions = configSection(root, "配置");
        TextView actionsSubtitle = mutedText("恢复内置默认值", 13f);
        LinearLayout.LayoutParams actionsSubtitleParams = matchWrap();
        actionsSubtitleParams.setMargins(0, 0, 0, dp(10));
        actions.addView(actionsSubtitle, actionsSubtitleParams);
        restoreDefaultsButton = actionButton("恢复默认", COLOR_ACTION_WARN);
        restoreDefaultsButton.setOnClickListener(view -> restoreDefaultConfig());
        trackEditable(restoreDefaultsButton);
        actions.addView(restoreDefaultsButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(48)));

        LinearLayout connection = configSection(root, "连接");
        proxyAddrs = field(connection, "代理地址", prefString("proxy_addrs", DefaultConfig.PROXY_ADDR), 2,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        addFieldHelp(connection, "TCP / UDP 共用远端出口。");
        transportModeControl(
                connection,
                prefString("transport_mode", DefaultConfig.TRANSPORT_MODE));
        addFieldHelp(connection, "自动：原生 UDP 超时后仅该 session 转 TCP/Yamux；TCP 始终走 TCP。");
        udpSessionPoolConfig = new LinearLayout(this);
        udpSessionPoolConfig.setOrientation(LinearLayout.VERTICAL);
        connection.addView(udpSessionPoolConfig, matchWrap());
        udpSessionPoolSize = numberControl(
                udpSessionPoolConfig,
                "UDP 会话数",
                boundedIntString(
                        prefString(
                                "udp_session_pool_size",
                                String.valueOf(DefaultConfig.UDP_SESSION_POOL_SIZE)),
                        DefaultConfig.UDP_SESSION_POOL_SIZE,
                        DefaultConfig.MIN_UDP_SESSION_POOL_SIZE,
                        DefaultConfig.MAX_UDP_SESSION_POOL_SIZE),
                1,
                DefaultConfig.MIN_UDP_SESSION_POOL_SIZE,
                DefaultConfig.MAX_UDP_SESSION_POOL_SIZE);
        addFieldHelp(udpSessionPoolConfig, "Auto/原生 UDP 使用；范围 1–8，运行中不可修改。");
        connectTimeoutSecs = numberControl(
                connection,
                "控制连接超时（秒）",
                prefString(
                        "connect_timeout_secs",
                        String.valueOf(DefaultConfig.CONNECT_TIMEOUT_SECS)),
                1,
                1);
        addFieldHelp(connection, "原生 UDP 握手与 TCP 连接共用。");
        username = field(connection, "用户名", prefString("username", DefaultConfig.USERNAME));
        privateKey = field(
                connection,
                "私钥 PEM",
                DefaultConfig.normalizePrivateKeyPem(prefString("private_key_pem", DefaultConfig.PRIVATE_KEY_PEM)),
                5,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);

        LinearLayout httpProxy = configSection(root, "HTTP / SOCKS5 代理");
        httpProxyPort = numberControl(
                httpProxy,
                "共享监听端口",
                prefString("http_proxy_port", String.valueOf(DefaultConfig.HTTP_PROXY_PORT)),
                1,
                1);
        addFieldHelp(httpProxy, "同端口支持 HTTP 与 SOCKS5。");
        httpProxyThreads = numberControl(
                httpProxy,
                "代理线程",
                prefString("http_proxy_threads", String.valueOf(DefaultConfig.HTTP_PROXY_THREADS)),
                1,
                1);
        addFieldHelp(httpProxy, "HTTP/SOCKS5 工作线程，重启后生效。");
        httpProxyMaxConcurrentConnects = numberControl(
                httpProxy,
                "并发建连",
                prefString(
                        "http_proxy_max_concurrent_connects",
                        String.valueOf(DefaultConfig.HTTP_PROXY_MAX_CONCURRENT_CONNECTS)),
                1,
                1);
        addFieldHelp(httpProxy, "HTTP/SOCKS5 最大并发连接数。");

        LinearLayout runtime = configSection(root, "运行参数");
        quicPolicy = quicPolicySpinner(runtime, "QUIC 策略", prefQuicPolicy());
        runtimeThreads = numberControl(
                runtime,
                "VPN 线程",
                prefString("runtime_threads", String.valueOf(DefaultConfig.RUNTIME_THREADS)),
                1,
                1);
        addFieldHelp(runtime, "仅用于 Android VPN。");
        compressionMode = spinner(
                runtime,
                "压缩模式",
                new String[]{"none", "lz4", "gzip", "zstd"},
                prefString("compression_mode", DefaultConfig.COMPRESSION_MODE));

        LinearLayout tcpConfig = configSection(root, "TCP 数据通道");
        LinearLayout tcpRelay = configGroup(
                tcpConfig,
                "TCP 转发",
                "两种模式均使用 TCP");
        addFieldHelp(tcpRelay, "TCP 目标始终使用独立 TCP 连接。");

        udpYamuxConfig = configSection(root, "UDP 数据 · TCP/Yamux");
        LinearLayout udpYamux = configGroup(
                udpYamuxConfig,
                "UDP Yamux",
                "仅全 TCP 模式");
        yamuxUdpSessions = numberControl(
                udpYamux,
                "外层连接",
                prefString(
                        "yamux_udp_sessions",
                        String.valueOf(DefaultConfig.UDP_YAMUX_SESSIONS)),
                1,
                1);
        addFieldHelp(udpYamux, "Yamux 外层连接上限。");
        yamuxUdpMaxStreamsPerSession = numberControl(
                udpYamux,
                "并发子流",
                prefString(
                        "yamux_udp_max_streams_per_session",
                        String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION)),
                1,
                1);
        addFieldHelp(udpYamux, "单连接最大 UDP 子流数。");
        yamuxUdpOpenStreamTimeoutSecs = numberControl(
                udpYamux,
                "打开子流超时",
                prefString(
                        "yamux_udp_open_stream_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
                1,
                1);
        addFieldHelp(udpYamux, "申请 Yamux 子流的超时。");
        yamuxUdpKeepaliveIntervalSecs = numberControl(
                udpYamux,
                "Keepalive 间隔",
                prefString(
                        "yamux_udp_keepalive_interval_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
                5,
                0);
        addFieldHelp(udpYamux, "Yamux 保活间隔；0 为关闭。");
        yamuxUdpConnectionWriteTimeoutSecs = numberControl(
                udpYamux,
                "写超时",
                prefString(
                        "yamux_udp_connection_write_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
                1,
                1);
        addFieldHelp(udpYamux, "Yamux 写入超时。");
        yamuxUdpStreamWindowSizeKb = numberControl(
                udpYamux,
                "流控窗口 KB",
                prefString(
                        "yamux_udp_stream_window_size_kb",
                        String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB)),
                256,
                DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB);
        addFieldHelp(udpYamux, "单个 UDP 子流缓冲窗口。");

        updateTransportModeSettingsVisibility();

        buildDirectAccessSection(root);
    }

}
