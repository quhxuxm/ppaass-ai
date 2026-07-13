# Android Agent

这个目录包含 PPAASS 的 Android VPN Agent。

Android App 负责平台 VPN 层：

- `PpaassVpnService` 请求并建立 Android `VpnService`。
- Service 会对 agent 到 proxy 的控制连接调用 `VpnService.protect()`，避免控制连接被重新绕回 TUN；这样也兼容 Android 的始终开启 VPN / 阻止无 VPN 连接模式。
- 原始 VPN 文件描述符会被 detach 后传给 Rust JNI 库。

Rust 库负责数据包和协议层：

- `android-agent/native` 使用 `AsyncFd` 包装 VPN fd。
- Agent 到 proxy 默认使用 QUIC 双向流，界面可切换回 TCP 兼容模式；两种模式内的 PPAASS RSA/AES 加密协议保持一致。
- `netstack-smoltcp` 将 IP 包转换为 TCP stream 和 UDP payload session。
- TCP 和 UDP 流量会通过 `common` 和 `protocol` crate 转发到现有的 PPAASS proxy 协议。
- Android 的应用 allow-list 决定哪些应用进入 VPN。
- `direct_access` 支持与 desktop agent 一致的 `proxy_all`、`direct_all`、`rules` 三种模式；命中规则的 TCP/UDP 目标会使用受 `VpnService.protect()` 保护的本地 socket 直连，避免再次绕回 VPN。
- DNS 通过 VPN 路径进入 Rust；命中 `direct_access` 域名规则的 UDP 53 查询会用受保护 socket 直连上游 DNS，未命中规则的查询会映射到 proxy 侧 DNS 路径。
- 默认允许未命中 direct 规则的 UDP/443 QUIC 通过 proxy 侧 UDP relay；命中 direct 规则的 QUIC 会使用受保护 UDP socket 直连。需要强制应用回退 TCP/TLS 时可打开 Block QUIC。

## 构建

先安装 Android Studio 或 Android SDK，然后安装 Rust Android targets 和 `cargo-ndk`：

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk
```

项目自带固定为 Gradle 9.4.1 的 Wrapper；构建脚本会自动安装缺失的 Rust Android targets。也可以直接用 Android Studio 打开本目录：

```bash
./gradlew assembleDebug
```

构建 release APK 时使用对应平台脚本。Windows 也可以在仓库根目录直接运行同名入口脚本：

```bash
# Windows
.\build-release-apk-windows.bat

# macOS
bash ./build-release-apk-macos.command
```

Gradle 构建过程中会执行：

```bash
cargo ndk -t <abi> -o app/src/main/jniLibs build --manifest-path native/Cargo.toml --release --jobs 1
```

三个 ABI 会依次构建。Windows 默认使用单 Cargo 作业以避免 NDK 原生依赖并行构建卡住；需要自行提高并行度时可设置 `PPAASS_ANDROID_CARGO_JOBS`。

只有在 `app/src/main/jniLibs` 下已经存在预构建 `.so` 文件时，才使用 `-PskipRustBuild=true`。

Android App 层使用纯 Java。数据包栈和 proxy 协议桥接仍然在 `android-agent/native` 的 Rust 代码中。

Android native 内部会分别维护 TCP 和 UDP 两个 `YamuxSessionManager`；界面里的 session 数是最大外层连接数，实际连接会在现有 session 没有可立即打开子流的容量时按需增长，默认值来自 `DefaultConfig`。

## 运行配置

打开 App 后填写：

- proxy endpoints，支持逗号或换行分隔；默认值是 `140.82.30.214:80`
- transport mode，默认 `quic`；连接尚未支持 QUIC 的旧版 proxy 时选择 `tcp`
- 控制连接超时，QUIC 握手/双向流与 TCP 兼容连接共用，默认 30 秒
- username，默认是 `user1`
- RSA private key PEM，默认使用与 `config/local/users.toml` 中 `users.user1.public_key_pem` 配对的私钥
- HTTP Proxy 监听端口和专属运行线程数。线程数只影响 Android HTTP Proxy 的 native Tokio runtime，VPN Agent 仍使用通用运行线程配置。
- direct access mode 和 rules。规则支持精确域名、`*.example.com` 通配符、精确 IP 和 CIDR 网段；默认模式为 `proxy_all`，因此升级后不会自动旁路既有流量。
- 需要使用 VPN 的应用。选择器会列出请求网络权限的已安装包，包括系统包。选择为空表示所有系统流量进入 VPN，PPAASS Android Agent 自身的 proxy 控制连接会通过 `VpnService.protect()` 绕开 VPN，避免连接回环。选择一个或多个应用后会切换到 allow-list 模式，只有选中的应用会进入 VPN。

状态页的 VPN connectivity 面板可通过 VPN 路径测试 Google / YouTube 的 HTTPS 连通性，并通过 UDP/443 QUIC Version Negotiation 探测测试 QUIC 协议路径。allow-list 模式下 App 会自动把自身加入 VPN 路径用于诊断；proxy 控制连接仍通过 `VpnService.protect()` 排除。

## 始终开启 VPN

PPAASS Android Agent 声明支持 Android 系统设置里的“始终开启 VPN”。用户需要在系统设置中把 PPAASS 选为始终开启的 VPN；普通应用不能自行替用户打开该系统开关。

当系统以始终开启模式拉起 Service 时，界面会显示 `Always-on VPN`，同时仍保留 App 内的 `Stop` 按钮用于断开当前 VPN 会话。代理控制连接会在 native 建连前通过 `VpnService.protect(fd)` 排除出 VPN 路径，因此在“阻止无 VPN 连接”模式下也不会依赖把 App 自身加入 disallow-list。

TUN 地址和 MTU 是 Android App 内部固定配置，分别为 `10.10.10.2/24`、禁用 IPv6、MTU 1500，因此 UI 中不会展示这些选项。Android 会指向 VPN 网络路径内的一个 routed DNS 地址；Rust 会根据 `direct_access` 域名规则决定 DNS 查询直连还是映射为 `ProxyDns`。默认允许未命中 direct 规则的 QUIC 通过 proxy 侧 UDP relay；命中 direct 规则的 QUIC 会继续直连。需要强制应用回退 TCP/TLS 时可打开 Block QUIC。
