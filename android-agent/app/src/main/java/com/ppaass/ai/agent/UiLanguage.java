package com.ppaass.ai.agent;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** App-local UI language selection for the programmatically built Android UI. */
final class UiLanguage {
    static final String PREF_LANGUAGE = "ui_language";
    static final String DEFAULT_LANGUAGE = "zh-CN";
    static final String[] LANGUAGE_KEYS = {"zh-CN", "en"};
    static final String[] LANGUAGE_LABELS = {"中文", "English"};

    private static final Map<String, String> ENGLISH = new LinkedHashMap<>();
    private static final List<Map.Entry<String, String>> ENGLISH_BY_LENGTH;

    static {
        put("中文", "Chinese");
        put("状态", "Status"); put("配置", "Configuration"); put("系统", "System"); put("系统状态", "System status");
        put("外观", "Appearance"); put("界面语言", "Interface language");
        put("选择后立即应用，不影响代理配置和运行状态。", "Applied immediately without affecting proxy configuration or runtime state.");
        put("配色风格", "Color theme"); put("VPN 应用", "VPN apps"); put("选择", "Select");
        put("所有应用", "All apps"); put("未选择", "None selected"); put("已选择", "Selected");
        put("只有选中的应用会使用 VPN 路径", "Only selected apps use the VPN path");
        put("启动", "Start"); put("停止", "Stop"); put("启动中", "Starting");
        put("停止中", "Stopping"); put("停止中…", "Stopping…"); put("未连接", "Disconnected");
        put("已连接", "Connected"); put("运行中", "Running"); put("已停止", "Stopped");
        put("已关闭", "Off"); put("空闲", "Idle"); put("关闭", "Close");
        put("恢复默认", "Restore defaults"); put("恢复内置默认值", "Restore built-in defaults");
        put("已恢复默认配置", "Default configuration restored"); put("保存", "Save");
        put("取消", "Cancel"); put("确定", "OK"); put("应用", "Apply"); put("稍后", "Later"); put("刷新", "Refresh");
        put("实时状态", "Live status"); put("实时", "Live"); put("今日流量", "Today's traffic");
        put("下载", "Download"); put("上传", "Upload"); put("每小时下载", "Hourly download");
        put("每小时上传", "Hourly upload"); put("合计", "Total"); put("空闲", "Idle");
        put("双通道实时速率 · 刻度 ", "Dual-channel live rate · scale ");
        put("VPN 空闲 · 等待流量", "VPN idle · waiting for traffic");
        put("代理 DNS 记录", "Proxy DNS records"); put("最近 80 条 DNS", "Latest 80 DNS records");
        put("DNS 记录不可用", "DNS records unavailable"); put("等待代理 DNS 请求", "Waiting for proxy DNS requests");
        put("VPN 已停止", "VPN stopped"); put("暂无", "None"); put("不存在", "Not found");
        put("超时", "Timed out"); put("成功", "Success"); put("失败", "Failed");
        put("已直连", "Direct"); put("缓存命中", "Cache hit"); put("直连解析", "Direct resolution");
        put("系统 DNS", "System DNS"); put("全选", "Select all"); put("清空", "Clear");
        put("添加", "Add"); put("添加并重启", "Add and restart");
        put("过滤域名、IP、客户端、状态或解析器", "Filter domain, IP, client, status, or resolver");
        put("过滤代理 DNS 记录", "Filter proxy DNS records");
        put("没有符合过滤条件的 DNS 记录", "No DNS records match the filter");
        put("显示 ", "Showing "); put("全选结果", "Select results"); put("取消结果", "Deselect results");
        put(" · 待添加 ", " · to add "); put(" · 待移出 ", " · to remove ");
        put("移出", "Remove"); put("移出并重启", "Remove and restart");
        put("直连规则已添加", "Direct rule added"); put("直连规则已生效", "Direct rule applied");
        put("直连规则已添加，正在重启", "Direct rule added; restarting");
        put("直连规则已移出", "Direct rule removed");
        put("直连规则已移出，正在重启", "Direct rule removed; restarting");
        put("代理", "Proxy"); put("直连", "Direct"); put("规则", "Rules");
        put("直连策略", "Direct policy"); put("全走代理", "Proxy all"); put("全量直连", "Direct all");
        put("按规则", "By rules"); put("当前模式", "Current mode"); put("当前规则", "Current rules");
        put("规则管理", "Rule management"); put("规则数量", "Rule count"); put("规则类型", "Rule type");
        put("规则值", "Rule value"); put("删除规则", "Delete rule"); put("快捷预设", "Quick presets");
        put("通配符", "Wildcard"); put("域名", "Domain"); put("其他", "Other");
        put("本机", "Localhost"); put("私网", "Private network"); put("中国", "China");
        put("已解析 IP", "Resolved IP"); put("HTTP / SOCKS5 域名", "HTTP / SOCKS5 domains");
        put("TUN + DNS 缓存", "TUN + DNS cache");
        put("使用 example.com 或 *.example.com 匹配显式代理目标。", "Use example.com or *.example.com to match explicit proxy targets.");
        put("优先使用固定 IP 或 192.168.0.0/16 这样的网段。", "Prefer a fixed IP or a network such as 192.168.0.0/16.");
        put("需要先启用代理 DNS；命中 DNS 缓存后规则才会生效。", "Requires proxy DNS; rules take effect after a DNS cache hit.");
        put("连接", "Connection"); put("代理地址", "Proxy address"); put("用户名", "Username");
        put("密码", "Password"); put("共享监听端口", "Shared listen port");
        put("连接你的代理账户", "Connect your proxy account");
        put("登录后自动下载并应用当前账户获批的代理凭据。",
                "Sign in to download and apply the approved proxy credential for this account.");
        put("输入 Proxy Web 用户名", "Enter your Proxy Web username");
        put("至少 8 位", "At least 8 characters");
        put("记住用户名和密码", "Remember username and password");
        put("登录并配置 Agent", "Sign in and configure Agent");
        put("正在登录", "Signing in");
        put("使用浏览器登录", "Sign in with browser");
        put("正在等待浏览器授权", "Waiting for browser approval");
        put("取消第三方登录", "Cancel third-party sign-in");
        put("正在创建安全的浏览器登录请求…",
                "Creating a secure browser sign-in request…");
        put("请在浏览器完成登录并批准此设备，然后返回 Agent。",
                "Sign in and approve this device in the browser, then return to Agent.");
        put("浏览器授权仍在处理中，Agent 已降低检查频率。",
                "Browser approval is still pending; Agent is checking less frequently.");
        put("第三方登录已取消", "Third-party sign-in cancelled");
        put("设备登录已取消", "Device sign-in cancelled");
        put("无法创建设备登录请求", "Could not create the device sign-in request");
        put("无法创建设备登录轮询请求", "Could not create the device sign-in poll request");
        put("Proxy Web 返回的设备登录参数无效",
                "Proxy Web returned invalid device sign-in parameters");
        put("Proxy Web 返回的设备登录地址无效",
                "Proxy Web returned an invalid device sign-in URL");
        put("Proxy Web 返回的设备登录结果无效",
                "Proxy Web returned an invalid device sign-in result");
        put("无法打开第三方登录页面", "Could not open the third-party sign-in page");
        put("浏览器登录或应用 Agent 凭据失败",
                "Browser sign-in or Agent credential setup failed");
        put("你已在浏览器中拒绝这次 Agent 登录",
                "You denied this Agent sign-in in the browser");
        put("账号状态已变化，请重新开始登录",
                "The account changed; start sign-in again");
        put("浏览器登录请求已过期，请重新开始",
                "The browser sign-in request expired; start again");
        put("浏览器登录请求无效或已被使用，请重新开始",
                "The browser sign-in request is invalid or already used; start again");
        put("Proxy Web 返回的密钥版本无效",
                "Proxy Web returned an invalid key version");
        put("Proxy Web 返回的登录会话已经过期",
                "Proxy Web returned an expired sign-in session");
        put("新用户注册", "Create account");
        put("私钥会从 Proxy Web 自动下载到应用私有目录，不会显示在界面中。",
                "The private key is downloaded into app-private storage and is never shown in the UI.");
        put("请输入用户名", "Enter your username");
        put("密码至少需要 8 位", "Password must be at least 8 characters");
        put("无法保存已记住的登录信息", "Could not save remembered sign-in details");
        put("无法清除已记住的登录信息", "Could not clear remembered sign-in details");
        put("登录或应用 Agent 凭据失败", "Sign-in or Agent credential setup failed");
        put("无法完全清理旧的 Agent 私钥，请重试登录",
                "Could not completely remove the previous Agent key; try signing in again");
        put("无法完全删除 Agent 私钥；代理已停止，请重试登录以再次清理",
                "The Agent key could not be completely removed; proxies were stopped, and the next sign-in will retry cleanup");
        put("无法完全删除已失效的 Agent 私钥",
                "The expired Agent key could not be completely removed");
        put("无法打开新用户注册页面", "Could not open the account registration page");
        put("请先登录 Agent", "Sign in to Agent first");
        put("已退出 Agent", "Signed out of Agent");
        put("登录状态或代理凭据已过期，请重新登录",
                "Your sign-in or proxy credential expired; sign in again");
        put("当前登录用户", "Current signed-in user");
        put("退出登录", "Sign out");
        put("已登录：", "Signed in: ");
        put("密钥版本 ", "key version ");
        put("有效期至 ", "expires ");
        put("管理员账号不能用于 Agent，请使用普通用户账号登录",
                "Administrator accounts cannot use Agent; sign in with a regular user account");
        put("账号已停用", "This account is disabled");
        put("账号与 Proxy 用户绑定关系不一致，请联系管理员",
                "The account does not match its linked proxy user; contact the administrator");
        put("Proxy 用户已停用", "The proxy user is disabled");
        put("当前账号没有读取私钥的权限",
                "This account is not permitted to retrieve its private key");
        put("密钥已经过期，请先申请新密钥并等待管理员批准",
                "The key has expired; request a new key and wait for administrator approval");
        put("密钥申请正在等待管理员审批",
                "The key request is waiting for administrator approval");
        put("当前没有可用密钥，请先在用户中心提交申请并等待管理员批准",
                "No key is available; submit a request in the user portal and wait for approval");
        put("用户名或密码错误", "Incorrect username or password");
        put("认证服务 TLS 或证书校验失败，请联系管理员",
                "Authentication service TLS or certificate validation failed; contact the administrator");
        put("连接认证服务超时，请稍后重试",
                "Authentication service connection timed out; try again later");
        put("无法连接认证服务，请联系管理员检查 Agent 配置和服务状态",
                "Cannot reach the authentication service; ask the administrator to check Agent configuration and service status");
        put("认证服务请求失败，请稍后重试",
                "Authentication service request failed; try again later");
        put("Agent 认证服务配置无效，请联系管理员",
                "Agent authentication service configuration is invalid; contact the administrator");
        put("代理线程", "Proxy threads"); put("并发建连", "Concurrent connections");
        put("同端口支持 HTTP 与 SOCKS5。", "The same port supports HTTP and SOCKS5.");
        put("HTTP/SOCKS5 工作线程，重启后生效。", "HTTP/SOCKS5 worker threads; effective after restart.");
        put("HTTP/SOCKS5 最大并发连接数。", "Maximum concurrent HTTP/SOCKS5 connections.");
        put("运行参数", "Runtime settings"); put("VPN 线程", "VPN threads");
        put("仅用于 Android VPN。", "Used only by Android VPN."); put("压缩模式", "Compression mode");
        put("QUIC 策略", "QUIC policy"); put("按规则处理，未命中走代理", "Use rules; unmatched traffic uses proxy");
        put("阻断 UDP/443", "Block UDP/443"); put("允许：UDP/443 按规则转发；阻断：回退 TCP/TLS。", "Allow routes UDP/443 by rules; block falls back to TCP/TLS.");
        put("传输模式", "Transport mode"); put("自动", "Auto"); put("原生 UDP", "Native UDP");
        put("全 TCP", "All TCP"); put("当前模式", "Current mode"); put("UDP 代理通道", "UDP proxy channel");
        put("UDP 会话数", "UDP sessions"); put("控制连接超时（秒）", "Control connection timeout (seconds)");
        put("原生 UDP 握手与 TCP 连接共用。", "Shared by native UDP handshakes and TCP connections.");
        put("Auto/原生 UDP 使用；范围 1–8，运行中不可修改。", "Used by Auto/native UDP; range 1–8; cannot change while running.");
        put("修改传输模式前请先停止 VPN 和 HTTP / SOCKS5 代理", "Stop VPN and the HTTP / SOCKS5 proxy before changing transport mode");
        put("修改配置前请先停止 VPN 和 HTTP / SOCKS5 代理", "Stop VPN and the HTTP / SOCKS5 proxy before editing configuration");
        put("优先使用原生加密 UDP，超时后自动切换到 TCP/Yamux", "Prefer native encrypted UDP, then automatically fall back to TCP/Yamux on timeout");
        put("使用全 TCP 模式，TCP 和 UDP relay 均通过 TCP", "Use all-TCP mode; both TCP and UDP relay use TCP");
        put("使用原生 UDP 模式，TCP 数据走 TCP，UDP 报文逐包使用 AES-256-GCM 加密", "Use native UDP mode; TCP data uses TCP and each UDP packet is encrypted with AES-256-GCM");
        put("Agent 运行中，停止后才能删除直连规则", "Stop the running agent before deleting direct rules");
        put("按规则值", "By rule value");
        put("TCP 数据通道", "TCP data channel"); put("TCP 转发", "TCP forwarding");
        put("两种模式均使用 TCP", "TCP is used in both modes");
        put("TCP 目标始终使用独立 TCP 连接。", "TCP targets always use separate TCP connections.");
        put("UDP 数据 · TCP/Yamux", "UDP data · TCP/Yamux"); put("仅全 TCP 模式", "All-TCP mode only");
        put("外层连接", "Outer connections"); put("并发子流", "Concurrent streams");
        put("打开子流超时", "Open-stream timeout"); put("Keepalive 间隔", "Keepalive interval");
        put("写超时", "Write timeout"); put("流控窗口 KB", "Flow-control window KB");
        put("Yamux 外层连接上限。", "Maximum Yamux outer connections.");
        put("单连接最大 UDP 子流数。", "Maximum UDP streams per connection.");
        put("申请 Yamux 子流的超时。", "Timeout for acquiring a Yamux stream.");
        put("Yamux 保活间隔；0 为关闭。", "Yamux keepalive interval; 0 disables it.");
        put("Yamux 写入超时。", "Yamux write timeout.");
        put("单个 UDP 子流缓冲窗口。", "Buffer window for each UDP stream.");
        put("HTTP / SOCKS5 代理", "HTTP / SOCKS5 proxy");
        put("PPAASS HTTP / SOCKS5 代理", "PPAASS HTTP / SOCKS5 proxy");
        put("HTTP 与 SOCKS5 监听 0.0.0.0:", "HTTP and SOCKS5 listening on 0.0.0.0:");
        put("同端口支持 HTTP 与 SOCKS5", "The same port supports HTTP and SOCKS5");
        put("Wi-Fi / 热点共享入口", "Wi-Fi / hotspot shared access");
        put("同一网络使用上方地址", "Use an address above from the same network");
        put("USB 电脑访问", "USB computer access"); put("蓝牙电脑访问", "Bluetooth computer access");
        put("复制地址", "Copy address"); put("复制命令", "Copy command"); put("已复制", "Copied");
        put("无法访问剪贴板", "Cannot access the clipboard");
        put("已复制 USB 调试转发命令", "USB debugging forwarding command copied");
        put("显式代理地址", "explicit proxy address");
        put("PPAASS USB 调试转发命令", "PPAASS USB debugging forwarding command");
        put("等待 USB 网络共享地址", "Waiting for USB tethering address");
        put("USB 网络共享地址暂未被电脑识别", "The computer has not detected the USB tethering address");
        put("备用 ADB 转发  127.0.0.1:", "Fallback ADB forwarding  127.0.0.1:");
        put("优先使用系统 USB 网络共享；电脑侧未识别时，可备用复制 adb forward 命令", "Prefer system USB tethering; copy the adb forward command as a fallback if the computer does not detect it");
        put("主要方式是打开系统 USB 网络共享；ADB forward 仅作为备用调试方式", "Use system USB tethering primarily; ADB forward is only a debugging fallback");
        put("优先使用上方 USB 网络共享地址；ADB forward 可作为备用方式", "Prefer the USB tethering address above; ADB forward is available as a fallback");
        put("电脑未识别蓝牙网络共享", "The computer has not detected Bluetooth tethering");
        put("未检测到蓝牙网络共享地址", "No Bluetooth tethering address detected");
        put("打开设置", "Open settings");
        put("系统已开启共享，但电脑侧未建立蓝牙网络", "Tethering is enabled, but the computer has not established a Bluetooth network");
        put("配对电脑，并在系统里开启蓝牙网络共享", "Pair the computer and enable Bluetooth tethering in system settings");
        put("蓝牙", "Bluetooth"); put("入口", "Entry"); put("连通", "Connected");
        put("流量", "Traffic"); put("运行", "Run"); put("个连接", "connections"); put("个端口", "ports");
        put("当前 Wi-Fi 未获取到可访问 IPv4 地址", "Current Wi-Fi has no reachable IPv4 address");
        put("当前不在 Wi-Fi 下，且未检测到热点地址", "Not on Wi-Fi and no hotspot address was detected");
        put("电脑 HTTP 与 SOCKS5 代理都填上方同一个地址", "Use the same address above for both HTTP and SOCKS5 on the computer");
        put("VPN 连通性", "VPN connectivity"); put("测试 VPN 的 HTTPS 与 QUIC", "Test VPN HTTPS and QUIC");
        put("测试", "Test"); put("测试中", "Testing"); put("启动 VPN 后运行测试", "Start VPN before running tests");
        put("请先启动 VPN 再运行测试", "Start VPN before running tests");
        put("正在测试 Google 和 YouTube", "Testing Google and YouTube");
        put("正在运行 HTTPS 和 QUIC 检查", "Running HTTPS and QUIC checks");
        put("尚未运行测试", "No tests run yet"); put("通过", "Passed");
        put("无响应记录", "No response records"); put("查询超时", "Query timed out");
        put("UDP/443 超时", "UDP/443 timed out");
        put("UDP/443 有响应，但不是 QUIC 版本协商包", "UDP/443 responded, but not with QUIC version negotiation");
        put("没有可用地址：", "No usable address: ");
        put("HTTP / SOCKS5 客户端", "HTTP / SOCKS5 clients"); put("客户端", "Client");
        put("活动", "Active"); put("禁止", "Block"); put("已禁止", "Blocked");
        put("个活动", "active"); put("个已禁止", "blocked");
        put("已断开并禁止 ", "Disconnected and blocked "); put("已恢复 ", "Restored ");
        put("恢复", "Restore"); put("暂无活动客户端", "No active clients");
        put("暂无禁止客户端", "No blocked clients"); put("正在读取客户端", "Loading clients");
        put("客户端列表读取失败", "Failed to load client list"); put("新连接会被拒绝", "New connections will be rejected");
        put("模拟 GEO", "Mock GEO"); put("启用 Android 模拟定位", "Enable Android mock location");
        put("独立模拟 Android 系统定位，不依赖 VPN", "Mocks Android system location independently of VPN");
        put("选择地点", "Choose location"); put("选择模拟 GEO", "Choose mock GEO");
        put("未选择地点", "No location selected"); put("未选择地点（使用真实定位）", "No location selected (using real location)");
        put("可选常用城市，也可以输入自定义经纬度", "Choose a common city or enter custom coordinates");
        put("自定义", "Custom"); put("自定义经纬度", "Custom coordinates");
        put("经度", "Longitude"); put("纬度", "Latitude"); put("精度（米）", "Accuracy (meters)");
        put("位置", "Location"); put("启动 GEO", "Start GEO"); put("停止 GEO", "Stop GEO");
        put("模拟中", "Mocking"); put("正在切换模拟地点", "Switching mock location");
        put("正在启动模拟 GEO：", "Starting mock GEO: "); put("正在停止模拟 GEO", "Stopping mock GEO");
        put("模拟 GEO 未生效", "Mock GEO inactive"); put("模拟 GEO 启动失败：", "Failed to start mock GEO: ");
        put("模拟定位更新失败：", "Mock location update failed: ");
        put("Google 融合定位模拟启动超时", "Google fused-location mock start timed out");
        put("设备没有可用的 Android 定位服务", "No Android location service is available");
        put("无法清理上次遗留的 Android 测试定位 provider", "Could not remove the stale Android test-location provider");
        put("检测到上次模拟定位可能仍未清理。请在开发者选项中重新选择", "A previous mock location may not have been cleared. Reselect");
        put(" PPAASS VPN 后返回，或重启设备", " PPAASS VPN in Developer options, then return, or restart the device");
        put("Google Play 服务暂不可用，无法确认融合定位已清理", "Google Play services are unavailable; fused-location cleanup could not be confirmed");
        put("Android 测试定位 provider 清理失败", "Failed to remove the Android test-location provider");
        put("检测到上次模拟定位可能仍未清理。请重新授予定位权限后返回，", "A previous mock location may not have been cleared. Grant location permission again and return, ");
        put("或重启设备", "or restart the device");
        put("Google 融合定位清理失败：", "Google fused-location cleanup failed: ");
        put("请允许定位权限，以便同步 Google 融合定位", "Allow location permission to synchronize Google fused location");
        put("Google 融合定位模拟启动失败：", "Google fused-location mock start failed: ");
        put("模拟位置系统授权已被撤销", "Mock-location system authorization was revoked");
        put("定位权限已被撤销", "Location permission was revoked");
        put("Google 融合定位更新失败：", "Google fused-location update failed: ");
        put("收到 QUIC 版本协商包：", "Received QUIC version-negotiation packet: ");
        put(" B，来源 ", " B from ");
        put("地点已保存，点击“启动 GEO”后生效", "Location saved; tap “Start GEO” to apply");
        put("当前使用设备真实定位；已保留：", "Using real device location; saved: ");
        put("出口 IP 地区仍由所连接的代理节点决定。", "The connected proxy node still determines the egress IP region.");
        put("模拟定位是 Android 设备级能力，无法只限制到 VPN 应用列表，且应用可识别模拟标志。", "Mock location is device-wide, cannot be limited to selected VPN apps, and apps may detect the mock flag.");
        put("定位设置", "Location settings"); put("开启系统定位", "Enable system location");
        put("系统定位已关闭", "System location is off"); put("需要先开启 Android 系统定位", "Android system location must be enabled first");
        put("需要定位权限", "Location permission required"); put("允许定位权限", "Allow location permission");
        put("授予权限", "Grant permission"); put("打开应用设置", "Open app settings");
        put("打开定位设置", "Open location settings"); put("打开开发者选项", "Open developer options");
        put("无法打开定位设置", "Cannot open location settings");
        put("无法打开系统设置", "Cannot open system settings");
        put("无法打开应用设置", "Cannot open app settings");
        put("已清除模拟地点", "Mock location cleared");
        put("无法持久化模拟定位清理状态，请重试或重启设备", "Could not persist mock-location cleanup state; retry or restart the device");
        put("上次模拟定位未能完全清理，请重新授权后重试或重启设备", "The previous mock location was not fully cleared; authorize again and retry, or restart the device");
        put("未获得定位权限，无法持续模拟 Android 定位", "Location permission is missing; Android location cannot be mocked continuously");
        put("正在移除模拟定位并恢复设备真实定位", "Removing mock location and restoring the device's real location");
        put("需要清理", "Cleanup required"); put("重试清理", "Retry cleanup");
        put("正在清理由异常退出遗留的模拟定位", "Cleaning up mock location left by an abnormal exit");
        put("Android 要求定位前台服务持有定位权限", "Android requires the location foreground service to hold location permission");
        put("GPS、网络定位和融合定位正在使用所选地点", "GPS, network location, and fused location are using the selected place");
        put("等待恢复", "Waiting to resume"); put("打开应用后正在恢复模拟 GEO", "Open the app to resume mock GEO");
        put("正在接管 GPS、网络定位和融合定位", "Taking over GPS, network location, and fused location");
        put("系统暂时不允许启动模拟 GEO，请重试", "The system temporarily blocked mock GEO startup; retry");
        put("定位权限已被系统设为不再询问。请在应用设置的“权限”中允许定位。", "Location permission is set to “Don't ask again.” Allow it in the app's permission settings.");
        put("1. 打开开发者选项\n", "1. Open Developer options\n");
        put("2. 进入“选择模拟位置信息应用”\n", "2. Open “Select mock location app”\n");
        put("3. 选择 PPAASS VPN\n\n", "3. Select PPAASS VPN\n\n");
        put("Android 的系统定位当前已关闭，开启后才能向应用提供模拟坐标。", "Android system location is off. Enable it before providing mock coordinates to apps.");
        put("TCP / UDP 共用远端出口。", "TCP and UDP share the remote egress.");
        put("自动：原生 UDP 超时后仅该 session 转 TCP/Yamux；TCP 始终走 TCP。", "Auto: only a timed-out native UDP session falls back to TCP/Yamux; TCP always uses TCP.");
        put("模拟 GEO 未生效：无法持久化模拟定位会话状态", "Mock GEO inactive: could not persist mock-location session state");
        put("VPN 与模拟 GEO（", "VPN and mock GEO (");
        put("）运行中", ") running");
        put("VPN 运行中 · 打开应用后恢复模拟 GEO", "VPN running · open the app to resume mock GEO");
        put("VPN 运行中 · 模拟 GEO 启动中", "VPN running · starting mock GEO");
        put("VPN 运行中 · 正在停止模拟 GEO", "VPN running · stopping mock GEO");
        put("VPN 运行中", "VPN running"); put("打开应用后恢复模拟 GEO", "Open the app to resume mock GEO");
        put("后台服务运行中", "Background service running"); put("未知的模拟 GEO", "Unknown mock GEO");
        put("必须是数字", "must be numeric"); put("必须在 ", "must be between ");
        put(" 之间", ""); put("，已在直连规则中", ", already in direct rules");
        put("已选 ", "Selected "); put(" · 生成 ", " · generated ");
        put("HTTP/SOCKS5 与 TUN 共用", "Shared by HTTP/SOCKS5 and TUN");
        put("抓包", "Capture");
        put("明文抓包结果", "Plaintext capture results");
        put("筛选与排序", "Filter and sort");
        put("搜索 IP、端口、协议或预览内容", "Search IP, port, protocol, or preview content");
        put("搜索", "Search"); put("方向", "Direction"); put("协议", "Protocol");
        put("例如 1.5", "e.g. 1.5"); put("最小包大小 · KB", "Minimum packet size · KB");
        put("最新优先", "Newest first"); put("最早优先", "Oldest first");
        put("包大小：大到小", "Packet size: largest first");
        put("包大小：小到大", "Packet size: smallest first");
        put("协议 A → Z", "Protocol A → Z");
        put("源地址 A → Z", "Source address A → Z");
        put("目标地址 A → Z", "Destination address A → Z");
        put("排序", "Sort"); put("重置", "Reset");
        put("筛选立即应用 · 内容搜索仅覆盖 Payload 预览",
                "Filters apply immediately · content search covers only the payload preview");
        put("数据包列表", "Packet list");
        put("尚未读取抓包文件", "Capture file has not been read");
        put("没有符合条件的数据包", "No packets match the filters");
        put("清空抓包文件", "Clear capture file");
        put("将永久删除当前全部抓包记录。抓包若已开启，清空后会继续记录。",
                "This permanently deletes all current capture records. If capture is enabled, recording will continue.");
        put("确认清空", "Clear now");
        put("正在读取抓包结果…", "Reading capture results…");
        put("数据包 #", "Packet #");
        put("数据流", "Data flow"); put("协议分析", "Protocol analysis");
        put("原始数据", "Raw data"); put("无 Payload", "No payload");
        put("仅显示 Payload 预览，内容搜索也只覆盖这部分数据",
                "Only the payload preview is shown; content search covers the same preview");
        put("Payload Hex（预览前 ", "Payload Hex (first ");
        put("ASCII（预览前 ", "ASCII (first ");
        put(" / 共 ", " / total "); put(" 字节）", " bytes)");
        put(" 包 · 显示最近 ", " packets · showing latest ");
        put(" 包 · PCAP ", " packets · PCAP ");
        put(" · 点击查看详情", " · tap for details");
        put("共 ", "Total ");
        put("，已在直连规则中，点击选择后可移出",
                ", already in direct rules; tap to select for removal");
        put("，已选择", ", selected"); put("，未选择", ", not selected");
        put("全部方向", "All directions"); put("全部协议", "All protocols");
        put("Client → Agent / 目标", "Client → Agent / target");
        put("Agent / 目标 → Client", "Agent / target → Client");
        put("Client 到 Agent 或目标", "Client to Agent or target");
        put("Agent 或目标到 Client", "Agent or target to Client");
        put("，数据包 ", ", packet ");
        put("HTTP 代理", "HTTP proxy"); put("SOCKS5 代理", "SOCKS5 proxy");
        put("●  正在抓包", "●  Capturing");
        put("●  正在读取抓包…", "●  Reading capture…");
        put("●  正在开启抓包…", "●  Enabling capture…");
        put("●  正在关闭抓包…", "●  Disabling capture…");
        put("●  正在清空抓包…", "●  Clearing capture…");
        put("●  已开启，等待 VPN 或 HTTP / SOCKS5 代理",
                "●  Enabled; waiting for VPN or HTTP / SOCKS5 proxy");
        put("●  抓包已关闭", "●  Capture off");
        put("●  抓包状态不可用", "●  Capture status unavailable");
        put("开启抓包", "Start capture"); put("关闭抓包", "Stop capture");
        put("切换抓包失败：", "Failed to toggle capture: ");
        put("开启抓包失败：", "Failed to enable capture: ");
        put("关闭抓包失败：", "Failed to disable capture: ");
        put("清空抓包失败：", "Failed to clear capture: ");
        put("读取抓包失败：", "Failed to read capture: ");
        put("原生抓包服务未完成请求", "The native capture service did not complete the request");
        put("原生抓包服务返回空结果", "The native capture service returned an empty result");
        put("未知错误", "Unknown error");
        put("模式", "Mode"); put("TUN 流量策略", "TUN traffic policy");
        put("同端口显式代理流量", "Explicit proxy traffic on the same port");
        put("策略路由", "Policy routing"); put("使用当前直连模式", "Use the current direct mode");
        put("始终开启 VPN", "Always-on VPN");
        put("规则已保存，服务停止超时，请手动重启", "Rules saved, but service stop timed out; restart it manually");
        put("0 组", "0 groups"); put(" 组 · ", " groups · "); put(" 条", " items");
        put(" 等 ", " etc. "); put(" 个", " ");
        put("需要系统授权", "System authorization required"); put("开发者选项", "Developer options");
        put("开发者选项 → 选择模拟位置信息应用 → PPAASS VPN", "Developer options → Select mock location app → PPAASS VPN");
        put("这是 Android 的系统限制，应用不能代替你完成授权。", "This is an Android system restriction; the app cannot grant this authorization.");
        put("请先选择一个模拟地点", "Choose a mock location first");
        put("请选择一个地点后再启动模拟 GEO", "Choose a location before starting mock GEO");
        put("请先开启 Android 系统定位", "Enable Android system location first");
        put("请允许定位权限，以便持续模拟 Android 定位", "Allow location permission to continuously mock Android location");
        put("请在开发者选项中将 PPAASS VPN 设为模拟位置信息应用", "Set PPAASS VPN as the mock location app in Developer options");
        put("定位精度必须是数字", "Location accuracy must be numeric");
        put("定位精度必须在 0–10000 米之间", "Location accuracy must be between 0 and 10000 meters");
        put("北京", "Beijing"); put("上海", "Shanghai"); put("香港", "Hong Kong");
        put("东京", "Tokyo"); put("新加坡", "Singapore"); put("悉尼", "Sydney");
        put("伦敦", "London"); put("法兰克福", "Frankfurt"); put("纽约", "New York");
        put("佛罗里达", "Florida"); put("洛杉矶", "Los Angeles");
        put("午夜霓虹", "Midnight Neon"); put("深海蓝", "Deep Ocean"); put("森林绿", "Forest Green");
        put("日落橙", "Sunset Orange"); put("星云紫", "Nebula Violet");
        put("暖瓷白", "Warm Porcelain"); put("晴空白", "Clear Sky");
        put("薄荷白", "Mint White"); put("樱花白", "Sakura White");

        ENGLISH_BY_LENGTH = new ArrayList<>(ENGLISH.entrySet());
        ENGLISH_BY_LENGTH.sort(Comparator.comparingInt((Map.Entry<String, String> entry) ->
                entry.getKey().length()).reversed());
    }

    private UiLanguage() {
    }

    static String current(Context context) {
        return context.getSharedPreferences("ppaass_agent", Context.MODE_PRIVATE)
                .getString(PREF_LANGUAGE, DEFAULT_LANGUAGE);
    }

    static int languageIndex(Context context) {
        return "en".equals(current(context)) ? 1 : 0;
    }

    static String tr(Context context, String source) {
        return translate(current(context), source);
    }

    static String translate(String language, String source) {
        if (!"en".equals(language) || source == null || source.isEmpty()) {
            return source;
        }
        String exact = ENGLISH.get(source);
        if (exact != null) {
            return exact;
        }
        String translated = source;
        for (Map.Entry<String, String> entry : ENGLISH_BY_LENGTH) {
            if (translated.contains(entry.getKey())) {
                translated = translated.replace(entry.getKey(), entry.getValue());
            }
        }
        return translated
                .replaceAll("(\\d+) 条", "$1 items")
                .replaceAll("(\\d+) 个节点", "$1 nodes")
                .replaceAll("(\\d+) 个", "$1");
    }

    static void watch(Activity activity) {
        View root = activity.findViewById(android.R.id.content);
        if (root == null) {
            return;
        }
        localize(root);
    }

    static void localize(View view) {
        if (view instanceof TextView) {
            TextView textView = (TextView) view;
            CharSequence text = textView.getText();
            if (text != null) {
                String translated = tr(view.getContext(), text.toString());
                if (!translated.contentEquals(text)) {
                    textView.setText(translated);
                }
            }
            CharSequence hint = textView.getHint();
            if (hint != null) {
                String translatedHint = tr(view.getContext(), hint.toString());
                if (!translatedHint.contentEquals(hint)) {
                    textView.setHint(translatedHint);
                }
            }
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int index = 0; index < group.getChildCount(); index++) {
                localize(group.getChildAt(index));
            }
        }
    }

    private static void put(String chinese, String english) {
        ENGLISH.put(chinese, english);
    }
}
