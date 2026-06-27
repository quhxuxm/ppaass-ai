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
        TextView actionsSubtitle = mutedText("将所有 Agent 设置恢复为内置默认值", 13f);
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
        proxyAddrs = field(connection, "Proxy 地址", prefString("proxy_addrs", DefaultConfig.PROXY_ADDR), 2,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        addFieldHelp(connection, "TCP / UDP 共用远端出口。");
        username = field(connection, "用户名", prefString("username", DefaultConfig.USERNAME));
        privateKey = field(
                connection,
                "私钥 PEM",
                DefaultConfig.normalizePrivateKeyPem(prefString("private_key_pem", DefaultConfig.PRIVATE_KEY_PEM)),
                5,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);

        LinearLayout httpProxy = configSection(root, "HTTP Proxy");
        httpProxyPort = numberControl(
                httpProxy,
                "监听端口",
                prefString("http_proxy_port", String.valueOf(DefaultConfig.HTTP_PROXY_PORT)),
                1,
                1);
        addFieldHelp(httpProxy, "监听 0.0.0.0，供同一 Wi-Fi 的外部客户端使用。");
        httpProxyThreads = numberControl(
                httpProxy,
                "代理线程",
                prefString("http_proxy_threads", String.valueOf(DefaultConfig.HTTP_PROXY_THREADS)),
                1,
                1);
        addFieldHelp(httpProxy, "HTTP Proxy 专属运行线程数，修改后重启 HTTP Proxy 生效。");

        LinearLayout runtime = configSection(root, "运行参数");
        quicPolicy = quicPolicySpinner(runtime, "QUIC 策略", prefQuicPolicy());
        runtimeThreads = numberControl(
                runtime,
                "VPN 线程",
                prefString("runtime_threads", String.valueOf(DefaultConfig.RUNTIME_THREADS)),
                1,
                1);
        addFieldHelp(runtime, "只影响 Android VPN Agent；HTTP Proxy 使用上方代理线程。");
        compressionMode = spinner(
                runtime,
                "压缩模式",
                new String[]{"none", "lz4", "gzip", "zstd"},
                prefString("compression_mode", DefaultConfig.COMPRESSION_MODE));

        LinearLayout tcpConfig = configSection(root, "TCP");
        LinearLayout tcpRelay = configGroup(
                tcpConfig,
                "TCP 转发",
                "普通 TCP 连接");
        addFieldHelp(tcpRelay, "TCP 目标连接使用独立的普通 TCP 连接承载。");

        LinearLayout udpConfig = configSection(root, "UDP");
        udpYamuxConfig = configGroup(
                udpConfig,
                "UDP Yamux",
                "作用于 UDP relay 子流");
        yamuxUdpSessions = numberControl(
                udpYamuxConfig,
                "外层连接",
                prefString(
                        "yamux_udp_sessions",
                        String.valueOf(DefaultConfig.UDP_YAMUX_SESSIONS)),
                1,
                1);
        addFieldHelp(udpYamuxConfig, "限制 UDP relay raw Yamux 外层连接上限；实际连接数按需增长。");
        yamuxUdpMaxStreamsPerSession = numberControl(
                udpYamuxConfig,
                "并发子流",
                prefString(
                        "yamux_udp_max_streams_per_session",
                        String.valueOf(DefaultConfig.UDP_YAMUX_MAX_STREAMS_PER_SESSION)),
                1,
                1);
        addFieldHelp(udpYamuxConfig, "限制单条 UDP Yamux session 同时承载的 UDP relay 子流数。");
        yamuxUdpOpenStreamTimeoutSecs = numberControl(
                udpYamuxConfig,
                "打开子流超时",
                prefString(
                        "yamux_udp_open_stream_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_OPEN_STREAM_TIMEOUT_SECS)),
                1,
                1);
        addFieldHelp(udpYamuxConfig, "影响新 UDP relay 通道申请 Yamux 子流的等待时间。");
        yamuxUdpKeepaliveIntervalSecs = numberControl(
                udpYamuxConfig,
                "Keepalive 间隔",
                prefString(
                        "yamux_udp_keepalive_interval_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_KEEPALIVE_INTERVAL_SECS)),
                5,
                0);
        addFieldHelp(udpYamuxConfig, "影响 UDP Yamux 外层连接的保活探测；0 表示关闭。");
        yamuxUdpConnectionWriteTimeoutSecs = numberControl(
                udpYamuxConfig,
                "写超时",
                prefString(
                        "yamux_udp_connection_write_timeout_secs",
                        String.valueOf(DefaultConfig.UDP_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS)),
                1,
                1);
        addFieldHelp(udpYamuxConfig, "影响 UDP Yamux 外层连接写入帧的超时判断。");
        yamuxUdpStreamWindowSizeKb = numberControl(
                udpYamuxConfig,
                "流控窗口 KB",
                prefString(
                        "yamux_udp_stream_window_size_kb",
                        String.valueOf(DefaultConfig.UDP_YAMUX_STREAM_WINDOW_SIZE_KB)),
                256,
                DefaultConfig.MIN_YAMUX_STREAM_WINDOW_SIZE_KB);
        addFieldHelp(udpYamuxConfig, "影响每个 UDP relay Yamux 子流可缓冲的窗口大小。");

        buildDirectAccessSection(root);
    }

}
