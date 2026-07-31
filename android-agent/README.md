# Android Agent

这个目录包含 PPAASS 的 Android VPN Agent。

Android App 负责平台 VPN 层：

- `PpaassVpnService` 请求并建立 Android `VpnService`。
- Service 会对 agent 到 proxy 的控制连接调用 `VpnService.protect()`，避免控制连接被重新绕回 TUN；这样也兼容 Android 的始终开启 VPN / 阻止无 VPN 连接模式。
- 原始 VPN 文件描述符会被 detach 后传给 Rust JNI 库。

Rust 库负责数据包和协议层：

- `android-agent/native` 使用 `AsyncFd` 包装 VPN fd。
- Agent 到 proxy 默认使用混合传输：TCP 目标始终使用原有的独立 framed TCP 连接；只有需要代理的 UDP 使用有状态原生 UDP 会话。选择 TCP 模式后，代理 UDP 改走 TCP/Yamux。
- 原生 UDP 会话通过 RSA 完成身份认证和会话建立，再用 HKDF 派生方向隔离的密钥与 nonce 前缀。每个数据报都以独立序号进行 AES-256-GCM 保护，协议头作为 AAD，并通过滑动窗口防重放；超过 MTU 的 payload 使用有界分片/重组，每个分片独立认证。该外层不提供可靠排序或重传。
- `netstack-smoltcp` 将 IP 包转换为 TCP stream 和 UDP payload session。
- TCP 和 UDP 流量会通过 `common` 和 `protocol` crate 转发到现有的 PPAASS proxy 协议。
- Android 的应用 allow-list 决定哪些应用进入 VPN。
- `direct_access` 支持与 desktop agent 一致的 `proxy_all`、`direct_all`、`rules` 三种模式。Android 13+ 会把 `direct_all` 和规则中的固定 IP/CIDR 编译成 VPN 排除路由，使流量直接走系统网络、跳过用户态 TUN 转发；域名规则以及旧版 Android 仍使用受 `VpnService.protect()` 保护的本地 socket 直连，避免再次绕回 VPN。
- DNS 通过 VPN 路径进入 Rust；命中 `direct_access` 域名规则的 UDP 53 查询会用受保护 socket 直连上游 DNS，未命中规则的查询会映射到 proxy 侧 DNS 路径。
- 应用层 UDP/443 QUIC 命中 direct 规则时使用受保护 UDP socket 直连，不经过 PPAASS 原生 UDP 封装；未命中时通过 proxy UDP relay，UDP 模式使用原生加密 UDP，TCP 模式使用 TCP/Yamux。只有选择“阻断 UDP/443”时才会强制应用回退 TCP/TLS。

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

构建 release APK 时使用对应平台脚本。Windows 也可以在仓库根目录直接运行同名入口脚本。
不设置签名环境变量时，脚本会自动创建并复用已被 Git 忽略的
`android-agent/local-release.keystore`，最终生成可安装的
`app-release-signed.apk`：

```bash
# Windows
.\build-release-apk-windows.bat

# macOS
bash ./build-release-apk-macos.command
```

本地 keystore 是开发发布证书，需要妥善备份；删除或丢失后重新生成的 APK 无法覆盖安装
之前由它签名的版本。正式发布应把签名文件放在仓库外，并用以下环境变量覆盖本地签名配置：

```bash
export PPAASS_RELEASE_KEYSTORE=/secure/path/ppaass-release.keystore
export PPAASS_RELEASE_KEY_ALIAS=ppaass-release
export PPAASS_RELEASE_STORE_PASSWORD='...'
export PPAASS_RELEASE_KEY_PASSWORD='...'
```

Windows 使用同名环境变量。正式 keystore 和密码应保存在 GitHub Actions Secret、密码管理器
或受限的本机目录中，不得提交到仓库。普通模拟器/开发调试使用 `./gradlew assembleDebug`。

Gradle 构建过程中会执行：

```bash
cargo ndk -t <abi> -o app/src/main/jniLibs build --manifest-path native/Cargo.toml --release --jobs 1
```

三个 ABI 会依次构建。Windows 默认使用单 Cargo 作业以避免 NDK 原生依赖并行构建卡住；需要自行提高并行度时可设置 `PPAASS_ANDROID_CARGO_JOBS`。

只有在 `app/src/main/jniLibs` 下已经存在预构建 `.so` 文件时，才使用 `-PskipRustBuild=true`。

Android App 层使用纯 Java。数据包栈和 proxy 协议桥接仍然在 `android-agent/native` 的 Rust 代码中。

Android native 内部会分别维护 TCP 和 UDP 两条传输路径。TCP 路径始终为每个 TCP 目标建立独立 framed TCP 连接；`udp` 表示代理 UDP 使用有状态原生加密 UDP 会话池，`tcp` 表示使用 TCP/Yamux，`auto` 表示每个 UDP session 优先使用加密 UDP，某个 session 的认证或 CONNECT 超时后仅将该 session slot 回退到 TCP/Yamux。旧 `quic` 配置仍会被拒绝。

## 运行配置

打开 App 后必须先使用 Proxy Registry 的普通用户账号登录。Proxy Registry 地址由
`app/src/main/assets/agent.properties` 随安装包配置，不在登录界面显示。登录成功后，
App 会校验账号状态、密钥版本和有效期，从 Proxy Registry 下载当前用户已获管理员批准的
私钥，并保存到 Android 应用私有的 no-backup 目录；私钥不会在界面中显示，也不能由
用户手工更改。私钥文件固定为仅应用 UID 可读写，并记录长度与 SHA-256 摘要供每次服务
启动和进程恢复时校验。认证响应中的 `profile.proxy_addresses` 同样由服务端托管并按
顺序安全持久化；配置页不显示或编辑这些地址，日志也只记录地址数量。原生启动配置只读取
这份受管列表，不读取旧版 `proxy_addrs` SharedPreferences。`expires_at` 只作为服务端状态展示，不按 Android 本机时间自动
登出或停止代理。应用同时禁止云备份与设备迁移
复制登录密码、托管私钥及配置。旧版本留在 SharedPreferences 中的 username 和明文私钥
会在升级启动时清除。

Debug 构建由 `app/src/debug/assets/agent.properties` 覆盖为
`http://127.0.0.1:8787`，可配合 `adb reverse tcp:8787 tcp:<本机 Proxy Registry 端口>`
连接开发机。Proxy 地址不再由 Debug 或 Release 包内置，而由管理员在 Proxy Registry 分配；
本地调试若分配了回环地址，应为相应端口配置第二条 `adb reverse`。Release 构建继续使用
main 目录中的 HTTPS 正式认证地址和原生 UDP 默认模式。认证地址不会展示在登录页。

登录页只使用用户名和密码登录，并提供记住用户名和密码及新用户注册入口，不提供浏览器或设备
授权登录。记住的登录信息按产品要求存放在应用私有 SharedPreferences 中；取消“记住”会
立即删除已保存密码，退出账号会删除托管私钥，但普通密码登录时仍保留用户选择记住的登录信息。
登录态和托管私钥会跨 App 进程重启恢复，以便 VPN 与 HTTP/SOCKS5 服务长期运行。普通
网络错误、HTTP 401、认证错误以及本机 `expires_at` 计时都不会清理登录态或停止
代理。Entry 返回且用户名与当前登录一致的 `UserExpired`/`UserDisabled` 状态只会显示
在界面和前台通知中，Agent 仍保持运行并重试；
管理员续期后，下一次成功握手会自动清除提示并恢复代理。只有用户显式退出才会
清理正常保存的登录凭据。管理员账号也可以登录 Agent，并由管理员固有权限使用受控功能。

登录后可以配置：

- UDP 代理通道，默认配置值为 `udp`；可选择原生加密 UDP、TCP/Yamux 或自动模式。自动模式按 UDP session 独立回退，一个 session 超时不会影响其他 session。VPN 或 HTTP/SOCKS5 代理运行期间控件会锁定
- UDP 会话数，对应 `udp_session_pool_size`，默认 4，可配置 1–8；仅原生 UDP 模式显示。每个 flow 会稳定映射到其中一个有状态 UDP 会话
- 控制连接超时，原生 UDP 会话建立与普通 TCP 连接共用，默认 30 秒
- HTTP Proxy 监听端口和专属运行线程数。线程数只影响 Android HTTP Proxy 的 native Tokio runtime，VPN Agent 仍使用通用运行线程配置。
- direct access mode 和 rules。规则支持精确域名、`*.example.com` 通配符、精确 IP 和 CIDR 网段；默认模式为 `proxy_all`，因此升级后不会自动旁路既有流量。
- 需要使用 VPN 的应用。选择器会列出请求网络权限的已安装包，包括系统包。选择为空表示所有系统流量进入 VPN，PPAASS Android Agent 自身的 proxy 控制连接会通过 `VpnService.protect()` 绕开 VPN，避免连接回环。选择一个或多个应用后会切换到 allow-list 模式，只有选中的应用会进入 VPN。
- 模拟 GEO。可以选择内置城市或自定义经纬度；VPN 运行期间会同时更新 Android GPS、网络定位和 Google 融合定位，VPN 停止后恢复真实定位。首次使用需要开启系统定位、在 Android 开发者选项中把 PPAASS VPN 选为“模拟位置信息应用”，并授予定位权限。

Agent 权限每隔一段时间从 Proxy Registry 同步。没有抓包权限时不显示抓包页并强制关闭抓包；
没有出口修改权限时不显示出口配置区，传输模式、UDP 会话池、连接超时、QUIC、压缩和
TCP/Yamux 通道参数会在持久化与原生启动层同时回落内置默认值；没有系统运行参数权限时
不显示对应面板，VPN runtime 线程数回落默认值。其余基础状态、显式代理和直连规则入口
保持可用。受管 Proxy 地址列表更新时，正在运行的 VPN 与 HTTP/SOCKS5 服务会自动重载；
服务端明确返回未分配，或成功响应缺失/包含非法地址时，会清空受管地址并停止网络服务，
但保持用户登录。普通网络失败、5xx 或限流不会清空上次成功同步的地址。
升级后若恢复的旧会话完全没有受管地址状态，则不会兼容旧 `proxy_addrs`，会立即停网并提示
重新登录；明确的“未分配”状态则可跨进程恢复，继续保持登录并定期等待管理员完成分配。

## 运行时抓包

Android 抓包默认关闭，由 App 的“抓包”页面在运行时开启、关闭、刷新或清空，不要求重启 VPN 或 HTTP/SOCKS5 Agent。开启后，VPN/TUN 两个方向的原始 IP 包，以及显式 HTTP 与 SOCKS5 TCP 连接在 Client 与 Agent socket 边界传递的字节，会写入同一份可由 Wireshark 打开的 DLT_RAW PCAP。显式代理流量会由 native 封装为仅存在于 PCAP 中的合成 IP/TCP 包，并在实验性 TCP option 中携带自描述标记，使 HTTP/SOCKS5 入口协议与上传/下载方向在后续解析时仍可稳定识别。

抓包记录的是 Client 与 Agent 之间实际经过的字节，不会解密应用自身的 TLS，所以 HTTPS、TLS 隧道等 payload 仍保持密文。Android 的本地 SOCKS5 Agent 只支持 TCP CONNECT，并明确拒绝 UDP ASSOCIATE；因此 Android 不会抓取 SOCKS5 UDP 数据。桌面 Agent 另有 SOCKS5 UDP 支持，能力边界不同。

再次开启抓包时会追加到格式兼容的现有 PCAP，而不是截断已有记录；如果上次写入留下不完整的尾记录，会先修复到最后一条完整记录再追加。格式不兼容、头部损坏或中间记录无效的文件不会被覆盖，用户需要先备份或在 UI 中明确清空。

抓包列表支持关键字、方向、最小大小、排序、普通协议以及独立的“HTTP 代理”和“SOCKS5 代理”过滤；列表行和详情也会显示代理入口标签与 Client/Agent 方向。列表高度根据当前 Android 可用视口动态计算，填满页面下方剩余区域，并在面板内部滚动；空结果会在该区域居中显示。

## DNS 记录管理

状态页的代理 DNS 面板提供过滤输入框，可按域名、回答 IP、客户端、状态、解析器等字段搜索；空格分隔的多个条件按 AND 匹配，并识别常用中英文状态别名。过滤结果可以单条或批量选择，然后把对应域名/IP 加入直连规则，或把覆盖选中记录的现有直连规则移出。修改会保存配置；VPN 或 HTTP/SOCKS5 Agent 正在运行时，App 会按当前运行状态应用重启。

模拟 GEO 使用 Android 标准 mock-location 能力，因此有以下平台边界：

- 模拟定位是设备级状态，Android 不支持普通 `VpnService` 只对 VPN allow-list 中的应用修改定位；未进入 VPN 的应用也可能收到同一模拟位置。
- `Location.isMock()` 会标记该位置，目标应用可以识别或拒绝模拟位置。
- 该功能模拟 Android 系统定位，不会改变 SIM、时区、语言、Wi-Fi/基站等旁路信号。
- 公网 IP 的地理位置仍由所连接的 proxy 出口决定。要让 IP 属地与模拟坐标一致，必须连接部署在相应地区的 proxy 节点；客户端不能把单一固定出口变成任意地区。
- Android 14+ 不允许仅持有“使用期间”定位权限的应用从后台启动定位前台服务。因此系统在开机或始终开启模式下后台恢复 VPN 时，会先保持 VPN 网络可用；用户打开 PPAASS VPN 后，App 会自动恢复模拟 GEO。没有静默请求后台定位权限。

状态页的 VPN connectivity 面板可通过 VPN 路径测试 Google / YouTube 的 HTTPS 连通性，并通过 UDP/443 QUIC Version Negotiation 探测测试应用层 QUIC 协议路径。这个探测不是 Agent 到 Proxy 的外层传输协议。allow-list 模式下 App 会自动把自身加入 VPN 路径用于诊断；proxy 控制连接仍通过 `VpnService.protect()` 排除。

## 始终开启 VPN

PPAASS Android Agent 声明支持 Android 系统设置里的“始终开启 VPN”。用户需要在系统设置中把 PPAASS 选为始终开启的 VPN；普通应用不能自行替用户打开该系统开关。

当系统以始终开启模式拉起 Service 时，界面会显示 `Always-on VPN`，同时仍保留 App 内的 `Stop` 按钮用于断开当前 VPN 会话。代理控制连接会在 native 建连前通过 `VpnService.protect(fd)` 排除出 VPN 路径，因此在“阻止无 VPN 连接”模式下也不会依赖把 App 自身加入 disallow-list。

Agent 登录态会从应用私有的托管凭据恢复。设备重启或系统回收进程后，Android 再次拉起
Always-on Service 时可继续使用已登录用户的凭据恢复 VPN。账号过期或停用时保持服务和
重试，续期后的已验证成功握手会自动恢复；只有用户主动退出或托管凭据无法通过完整性校验
时才要求重新登录。

TUN 地址和 MTU 是 Android App 内部配置，地址为 `10.10.10.2/24`且默认禁用 IPv6。配置 MTU 为 1500；原生加密 UDP 模式下运行时会将有效 MTU 限制为 1280，使浏览器 QUIC 数据报保持为单个外层加密 UDP 包；TCP 模式仍使用配置值。这些选项不在 UI 中展示。Android 会指向 VPN 网络路径内的一个 routed DNS 地址；Rust 会根据 `direct_access` 域名规则决定 DNS 查询直连还是映射为 `ProxyDns`。UDP/443 应用层 QUIC 命中 direct 规则时使用受保护 UDP socket 直连且不经过 PPAASS 封装；未命中时通过 proxy UDP relay，UDP 模式使用原生加密 UDP，TCP 模式使用 TCP/Yamux。只有显式阻断时才让应用回退 TCP/TLS。
