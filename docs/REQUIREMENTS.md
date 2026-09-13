# PPAASS 当前功能清单

> 本文是从当前源码、配置模型和已接入的界面整理出的产品能力基线（截至 2026-09-13），描述“已经具备什么”，而非未来路线图。实现架构、协议、数据边界和部署细节见 [TECHNICAL_DETAILS.md](TECHNICAL_DETAILS.md)。

## 1. 产品范围

PPAASS 是一个由客户端 Agent、数据面 Proxy Entry 和控制面 Proxy Registry 组成的加密代理平台。普通用户在 Desktop 或 Android Agent 登录后，将本机显式代理或 VPN/TUN 流量经管理员分配的 Proxy Entry 转发至目标；管理员在 Registry 管理账号、密钥、权限和节点。

系统中的关键实体如下。

| 实体 | 已实现职责 |
| --- | --- |
| Desktop Agent | Windows/macOS 本地 HTTP/SOCKS5 代理、TUN、登录后的运行与可视化管理。 |
| Android Agent | Android VPN、显式 HTTP/SOCKS5 代理、应用分流和移动端管理界面。 |
| Proxy Entry | 校验数据面身份和权限，解析/连接目标并中继 TCP、UDP 与 DNS 流量。 |
| Proxy Registry | 账号、密钥、权限、节点目录、审计和访问历史的唯一权威来源。 |

## 2. 最终用户功能

### 2.1 账号与登录

- 支持本地账号注册、用户名密码登录和退出；密码至少 8 个 Unicode 字符、最长 256 UTF-8 字节，以 Argon2id 哈希保存。
- 用户可修改密码、显示昵称和头像。昵称会去除首尾空白、拒绝控制字符，最长 6 个 Unicode 字符；头像接受 PNG/JPEG/WebP，源文件最大 1 MiB，并保存为 64×64 图像。
- Desktop 和 Android 都提供“记住用户名和密码”选项；取消选择会删除已保存密码。
- 登录 Agent 后，Registry 下发已批准的用户名、权限、有效期、托管私钥、受分配的 Entry 地址及 Agent access token。地址、私钥、token 和 Registry URL 不会展示给前端页面或写入日志。
- 登录态可跨客户端进程恢复。临时网络失败、同步失败、401/5xx 或 Entry 连接失败不会自动登出或清除可用凭据；用户主动退出、凭据损坏，或明确未获分配节点时才停止相应网络服务。
- Desktop 可创建一次性、同源、90 秒有效的网页登录交接码，打开已登录的 Registry 账户管理页面；也提供供原生客户端使用的设备授权 API。

### 2.2 密钥申请与轮换

- 注册不会自动取得数据面密钥。无有效密钥的用户可提交附带最多 500 字留言的初始/重新生成申请，并查看处理结果、处理人和原因。
- 审批会生成版本化 RSA 密钥对、设置将来的到期时间，并一次性分配 1–32 个已启用的 Proxy 地址；私钥只以加密信封保存在 Registry，随后只提供给经认证的本人原生 Agent。
- 已有有效密钥且拥有 `key.rotate` 的用户，可在 Agent 中经密码确认直接轮换密钥；客户端会校验、受限保存新私钥，并在需要时重启运行中的 Agent。
- 管理员可批准或拒绝申请、创建已批准用户并为用户轮换密钥；管理界面和 API 均不返回公钥、私钥或可复制的凭据。

### 2.3 本地代理与流量转发

- Desktop Agent 在一个本地 TCP 监听端口自动识别 HTTP 和 SOCKS5。HTTP 支持普通请求和 CONNECT 隧道；SOCKS5 支持 TCP CONNECT 和 UDP ASSOCIATE。
- Android 提供显式 HTTP/SOCKS5 服务以及 `VpnService`。Android SOCKS5 仅支持 TCP CONNECT，明确拒绝 UDP ASSOCIATE。
- TCP 目标通过 Proxy Entry 建立连接并双向转发；域名可直接交给 Entry 解析，避免在 Agent 侧提前泄露 DNS 解析结果。
- 支持 TCP、单目标 UDP、共享 UDP relay 和 Proxy DNS。共享 UDP relay 用 flow ID 区分并发目标，适合 TUN 中的大量 UDP 流。
- 可选 `direct_access` 模式：`proxy_all`（默认）、`direct_all` 或规则模式。规则支持精确域名、`*.example.com`、精确 IP 和 IPv4/IPv6 CIDR；命中后由 Agent 使用本地受保护 socket 绕开代理。
- TCP 目标始终使用独立的加密 framed TCP 路径。代理 UDP 可选择原生加密 UDP（默认）、TCP/Yamux，或 `auto`：每个 UDP session slot 先尝试原生 UDP，控制/认证超时后仅该 slot 在当前进程内回退到 TCP/Yamux。
- 旧的 `transport_mode = "quic"` 及 `quic_connection_pool_size` 会被拒绝，不能被静默兼容为新传输模式。

### 2.4 桌面 TUN 与路由

- Desktop 可同时运行 TUN 和本地 HTTP/SOCKS5 监听；TUN 用用户态网络栈处理 IPv4/IPv6 TCP/UDP。
- 支持 TUN DNS 代理、普通 UDP 代理/直连开关和独立的 UDP/443 QUIC 策略（允许或阻断）。QUIC 命中直连规则时直连，其他可代理；阻断时促使应用退回 TCP/TLS。
- TUN 路由保护 Proxy Entry 的实际出站路径，避免流量回环；桌面 TUN DNS 方案不改写系统 DNS 配置。
- macOS 可使用本地特权 helper 创建/管理 TUN；Windows 提供相应服务/计划任务的运行支持。启动和停止会清理已记录的路由状态。

### 2.5 Android 专属能力

- VPN 支持全部应用或已选应用 allow-list；Agent 自己到 Registry/Entry 的控制连接会调用 `VpnService.protect()`，避免被送回 VPN，也兼容 Always-on VPN 和“阻止无 VPN 连接”。
- 支持 Android 系统的 Always-on VPN：系统重启或回收服务后可从完整性校验过的本地凭据恢复。
- 支持模拟 GEO：内置城市或自定义坐标可在 VPN 运行期更新 GPS、网络和融合定位；停止 VPN 后恢复真实定位。该功能受 Android mock-location 权限和平台限制约束，不会改变 SIM、时区、Wi-Fi/基站或公网出口 IP。
- 状态页可经 VPN 路径测试 HTTPS 连通性与 UDP/443 QUIC 协议路径；这项检测不改变 Agent 到 Entry 的外层传输方式。
- Android 的代理 DNS 面板支持按域名、回答 IP、客户端、状态或解析器过滤记录；用户可单选或批量把记录转为直连规则，或移除覆盖这些记录的现有规则。

## 3. 运行与可观测性

- Desktop UI 提供概览、转发、出口、路由、诊断、抓包、日志和原始 TOML 页面；运行中会锁定会影响传输语义的配置。界面可显示实时/当日流量和近期 DNS 记录。
- 经 `agent.proxy_entry.select` 授权的用户可在被分配的 Entry 中多选和切换；每个 Entry 可执行不访问第三方目标的加密下载测速，展示延迟和吞吐。
- Desktop 和 Android 的 Packet Capture 页面可在运行时启用、关闭、刷新和清空抓包，无须停止 Agent。输出为 Wireshark 可读取的 DLT_RAW PCAP，涵盖 TUN 双向 IP 包及本地显式代理边界数据。
- 抓包采用非阻塞有界队列和专用写入线程；磁盘跟不上时只丢弃抓包副本，不阻塞代理流量。TLS/HTTPS 应用负载仍是密文。
- PCAP 可追加到兼容的既有文件；若尾部不完整会修复到最后一条完整记录，格式或中间记录异常时不会覆盖原文件。Desktop 支持 SOCKS5 UDP 抓包；Android 不支持此项，因为其 SOCKS5 不支持 UDP ASSOCIATE。
- 客户端支持文件日志、可配日志级别、连接和 TUN 诊断；敏感凭据、token、私钥和已解密用户负载不应写入 tracing 日志。

## 4. Registry 用户中心与管理员功能

### 4.1 用户中心

- Vue 3 + PrimeVue Web 控制台提供注册、登录、个人资料、密码修改、密钥申请/状态和个人近期访问记录。
- 普通用户只能查阅自己的访问记录。记录按用户名和规范化目标主机/IP 聚合，保留最新端口、TCP/UDP、次数和时间，不保存 URL 路径或页面内容。
- 浏览器登录使用服务端不透明会话、HttpOnly Cookie 和 CSRF token；状态变更请求需要 CSRF 防护，并对认证接口实施限流与非枚举式错误返回。

### 4.2 管理控制台

- 固定根管理员是 `admin`，不能被禁用、降级或删除；其余管理员和普通账号可在满足状态约束后管理或删除。
- 管理员可创建、查询、更新、停用和删除账号，配置角色、期限、流量权限及可选 Agent 权限。
- 管理员可维护带稳定 ID、标签、地址和启用状态的 Proxy 地址目录，查看 Entry 心跳在线状态，并将地址分配给账号。已被使用的地址不能直接停用；删除会原子移除分配关系。
- 管理员可处理密钥申请、配置访问历史保留期（1–365 天）、查看带操作/关键字/游标筛选的审计记录。
- 审计覆盖密钥处理与轮换、账号和 Proxy 访问启停、地址节点启停及权限变更。敏感管理员操作要求记录原因，并与业务写入放在同一事务内。

### 4.3 权限与实时同步

- 数据面基础权限为 `proxy.connect.tcp`、`proxy.connect.udp`、`key.private.read` 和 `key.rotate`；Proxy Entry 在握手和运行期复查 TCP/UDP 权限、账号状态、密钥版本和到期时间。
- 可选 Agent 权限包括 `agent.packet_capture`、`agent.egress.edit`、`agent.runtime_threads.edit` 和 `agent.proxy_entry.select`。缺失权限时，页面会隐藏，原生命令/API 同样拒绝越权请求或回退安全默认值。
- Agent 登录后连接 `/api/v1/agent/events` SSE。初始同步和账号、权限、密钥、地址变更事件触发按需刷新；断线按 1–60 秒退避重连，并保留最近一次成功配置。
- 如果没有可用分配地址，新的 Agent 登录会失败关闭；已登录客户端会停止新的代理流量但保留身份，等待管理员修复分配。

## 5. Entry 与 Registry 的服务能力

- Entry 在同一数值端口监听 TCP 和原生 UDP，处理 direct framed TCP、Yamux 子流和已认证 UDP session；它可配置认证、目标连接、TCP relay、半关闭、Yamux 空闲和 UDP flow/session 的超时。
- Entry 的原生 UDP session 支持全局与每用户名上限、每 session 有界队列、每 session flow 上限、共享 UDP relay 内层 socket 上限及独立的有界分片重组。达到容量时保留已有 flow，拒绝新 flow。
- Entry 启动后独立地向 Registry 注册稳定 ID、版本和 `advertised_address`，每 30 秒发送心跳；Registry 不可用不会阻塞 TCP/UDP 监听。
- Registry 是账号、配置、私钥、地址分配、审计和访问历史的唯一权威存储。Entry 仅经受控 HTTP/SSE API 获取公开授权快照、维护本地 SQLite last-known-good 副本并批量幂等上报访问记录。
- 首份完整授权快照前 Entry 拒绝认证；之后 Registry 暂时不可用时可继续服务该快照中的用户。授权变更在下一次完整快照同步后生效。

## 6. 交付与质量保障

- Rust workspace 包含协议、公共库、Entry、Registry、Desktop Agent 后端、Android JNI 库和集成/性能测试工具；前端分别使用 Vue/Tauri 与 Vue/PrimeVue，Android 使用 Java + JNI。
- 集成测试提供 HTTP、TCP 和 UDP mock target/client，覆盖认证、协议、连接、数据转发、回压、并发、会话回归和容量边界。性能工具生成 HTML、JSON 和 Markdown 报告，包含吞吐、延迟百分位和资源指标。
- CI 包含 Rust 构建/测试、源码行数限制、Registry 前端测试与构建、Desktop Windows/macOS 构建测试、Android Java/Rust 测试及 APK 构建，以及独立集成测试和静态/安全扫描。
- 提供独立的 Entry 与 Registry 部署工作流。生产 Registry 使用两个共享 SQLite 的进程并由 Caddy 对外提供 HTTPS；Entry 可部署到另一台机器，运行时不依赖访问 Registry 的数据库文件。

## 7. 明确的安全与产品边界

- Proxy 地址由 Registry 托管，不允许通过产品 `agent.toml`、旧 `proxy_addrs` 字段或公共 `--proxy` 参数手工注入。
- Desktop/Android 只有完成原生认证、领取受管凭据后才可运行产品数据流；仅 CI 的 integration harness 能显式传入测试 Entry 地址。
- Entry 不读取 Registry 的私钥、密码、会话或权威数据库；授权快照只包含数据面所需的用户名、公钥、权限、状态、密钥版本和到期时间。
- 原生 UDP 是无连接数据报承载：允许有限乱序，但不提供额外的可靠排序或重传。它不能被当作普通可靠字节流。
- Registry HTTPS 客户端在现有 Desktop/Android 实现中有意跳过证书链和主机名校验；生产部署仍应让 Registry 位于受信任的 HTTPS 反向代理之后，并严格保护控制 token、数据库和密钥加密主密钥。
