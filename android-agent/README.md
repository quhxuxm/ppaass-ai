# Android Agent

这个目录包含 PPAASS 的 Android VPN Agent。

Android App 负责平台 VPN 层：

- `PpaassVpnService` 请求并建立 Android `VpnService`。
- Service 会把 App 自身从 VPN 中排除，避免 agent 到 proxy 的控制连接被重新绕回 TUN。
- 原始 VPN 文件描述符会被 detach 后传给 Rust JNI 库。

Rust 库负责数据包和协议层：

- `android-agent/native` 使用 `AsyncFd` 包装 VPN fd。
- `netstack-smoltcp` 将 IP 包转换为 TCP stream 和 UDP payload session。
- TCP 和 UDP 流量会通过 `common` 和 `protocol` crate 转发到现有的 PPAASS proxy 协议。
- Android 的应用 allow-list 决定哪些应用进入 VPN。
- DNS 始终通过 VPN 路径转发；Rust 会把 TCP/UDP 53 端口包映射到 proxy 侧 DNS 路径，行为与 desktop agent 的 TUN 模式一致。
- QUIC 阻断逻辑与 desktop agent 的 TUN 模式保持一致。

## 构建

先安装 Android Studio 或 Android SDK，然后安装 Rust Android targets 和 `cargo-ndk`：

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk
```

在本目录下使用本地 Gradle 构建 debug APK，也可以直接用 Android Studio 打开本目录：

```bash
gradle assembleDebug
```

构建 release APK 时使用对应平台脚本：

```bash
# Windows
.\build-release-apk-windows.bat

# macOS
bash ./build-release-apk-macos.command
```

Gradle 构建过程中会执行：

```bash
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o app/src/main/jniLibs build --manifest-path native/Cargo.toml --release
```

只有在 `app/src/main/jniLibs` 下已经存在预构建 `.so` 文件时，才使用 `-PskipRustBuild=true`。

Android App 层使用纯 Java。数据包栈和 proxy 协议桥接仍然在 `android-agent/native` 的 Rust 代码中。

## 运行配置

打开 App 后填写：

- proxy endpoints，支持逗号或换行分隔；默认值是 `140.82.30.214:80`
- username，默认是 `user1`
- RSA private key PEM，默认使用与 `config/local/users.toml` 中 `users.user1.public_key_pem` 配对的私钥
- 需要使用 VPN 的应用。选择器会列出请求网络权限的已安装包，包括系统包。选择为空表示所有系统流量进入 VPN，同时 PPAASS Android Agent 自身会被排除以避免 proxy 连接回环。选择一个或多个应用后会切换到 allow-list 模式，只有选中的应用会进入 VPN。

TUN 地址和 MTU 是 Android App 内部固定配置，分别为 `10.10.10.2/24`、禁用 IPv6、MTU 1500，因此 UI 中不会展示这些选项。Android 会指向 VPN 网络路径内的一个 routed DNS 地址；Rust 会把 UDP 53 端口包映射为 `ProxyDns`，因此最终由 proxy 机器按其系统配置选择上游 DNS。默认阻断 QUIC，以匹配 desktop TUN 模式，并让 Google Play / YouTube 在 proxy 路径无法可靠处理 UDP/443 时回退到 TCP/TLS。
