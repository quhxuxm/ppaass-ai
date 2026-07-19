# PPAASS 项目学习导览

这份文档按“先看整体，再看主链路，再看复杂分支”的顺序梳理整个项目。读完以后，你应该能回答三个问题：

1. 用户的流量从哪里进入，经过哪些模块，最后如何到达目标服务器。
2. Agent 和 Proxy 之间的认证、加密、连接复用、数据封包分别由谁负责。
3. 桌面 UI、Android VPN、测试和部署脚本分别接在核心代理系统的哪个位置。

本文所有流程图都保存在 `docs/diagrams/*.mmd`。部分旧 SVG 渲染产物已经清理，避免展示与当前混合传输架构不一致的旧图。

## 1. 项目一句话

PPAASS 是一个 Rust 实现的加密代理系统。客户端侧运行 Agent，服务端侧运行 Proxy。Agent 接收本机 HTTP/SOCKS5/TUN/VPN 流量；TCP 目标始终通过原有的独立 framed TCP 连接到 Proxy。配置值 `transport_mode = "udp"` 表示只有代理 UDP 使用原生加密 UDP 会话；配置值 `transport_mode = "tcp"` 表示代理 UDP 改由 raw TCP/Yamux 承载。TCP 和 TCP/Yamux 路径继续使用 PPAASS Auth/Connect/Data 流协议，原生 UDP 路径使用独立的认证数据报协议。Proxy 做用户认证、出站连接和数据回传。

核心 workspace：

```text
ppaass-ai/
├── desktop-agent-be/    # 桌面 Agent 后端：HTTP/SOCKS5/TUN、TCP direct framed、原生 UDP/TCP-Yamux
├── proxy/               # 服务端 Proxy：TCP direct framed/Yamux 与 raw UDP session、认证、目标 relay、上游转发
├── protocol/            # Agent <-> Proxy 流协议与原生 UDP 数据报协议、编解码、加密、压缩
├── common/              # Agent/Proxy 复用的客户端握手、传输选择、Yamux、工具
├── desktop-agent-ui/    # Tauri 2 + Vue 3 桌面 UI，内嵌 desktop-agent-be 运行
├── android-agent/       # Android VpnService + Rust JNI native Agent
├── tests/               # mock target、mock client、集成测试、性能测试和报告
├── config/              # local/remote 示例配置
├── keys/                # 示例私钥，proxy 侧 users.toml 存公钥
└── .github/workflows/   # unit/integration/clippy/deploy workflow
```

## 2. 总体架构图

Mermaid 源码：[01-overall-architecture.mmd](diagrams/01-overall-architecture.mmd)

这张图是全项目的骨架。无论流量来自桌面本地代理、桌面 TUN，还是 Android VPN，最终都尽量复用同一套 `common` + `protocol` + `proxy` 逻辑。

## 3. 最重要的三个概念

### 3.1 Agent

Agent 是客户端入口。

桌面 Agent 的入口在：

- `desktop-agent-be/src/main.rs`
- `desktop-agent-be/src/lib.rs`
- `desktop-agent-be/src/server.rs`

它做的事情：

- 读取 `agent.toml`。
- 启动 Tokio runtime。
- 监听 `listen_addr`，用首字节识别 HTTP 还是 SOCKS5。
- 如果 `[tun] enabled = true`，额外启动 TUN 模式。
- 代理 TCP 始终通过 `YamuxSessionManager::connect_to_target(...)` 返回 direct framed PPAASS TCP 流。代理 UDP 在 `udp` 模式交给有状态原生 UDP 会话，以数据报收发 `Connect/Data/Close` 消息；在 `tcp` 模式才返回 Yamux 子流。原生 UDP 不能被当成可靠、有序的 `AsyncRead/AsyncWrite` 字节流。

### 3.2 Proxy

Proxy 是服务端出口。

入口在：

- `proxy/src/main.rs`
- `proxy/src/server.rs`
- `proxy/src/connection/mod.rs`

它做的事情：

- 读取 `proxy.toml` 和 `users.toml`。
- 在同一个数值端口同时监听 Agent 的入站 TCP 和 raw UDP。TCP 入站先 peek 首包判断是 direct framed PPAASS 还是 raw Yamux；UDP 入站按原生协议建立、查找和维护认证 session。
- 对每条 direct framed 连接或 Yamux 子流执行流式 PPAASS Auth，再等待 `ConnectRequest`；原生 UDP 则先做 RSA 身份认证/会话建立，再处理被逐包认证的 `Connect/Data/Close` 数据报。
- 根据目标类型进入 TCP relay、单目标 UDP、共享 UDP relay、Proxy DNS 或上游转发。
- TCP relay 始终使用独立 direct framed TCP 连接；UDP relay 根据 Agent 模式使用原生加密 UDP session 池或 raw TCP/Yamux session 池。

### 3.3 Protocol

`protocol` crate 是 Agent 和 Proxy 的共同语言。

关键文件：

- `protocol/src/message/*.rs`
- `protocol/src/codec/message_codec.rs`
- `protocol/src/codec/agent_codec.rs`
- `protocol/src/codec/proxy_codec.rs`
- `protocol/src/crypto/*.rs`

它定义了：

- `ProxyRequest`: `Auth`、`Connect`、`Data`
- `ProxyResponse`: `Auth`、`Connect`、`Data`、`Error`
- `Address`: `Domain`、`Ipv4`、`Ipv6`、`ProxyDns`、`UdpRelay`
- `DataPacket`: `stream_id + data + is_end`
- `MessageCodec`: 长度前缀、bitcode 序列化、压缩、AES-GCM 加解密
- `udp_transport`: 原生 UDP 的 RSA 会话建立、方向隔离密钥、固定头、逐包 AES-256-GCM、重放窗口和有界分片/重组

## 4. Agent 启动流程

![Agent 启动流程](diagrams/02-agent-startup.svg)

Mermaid 源码：[02-agent-startup.mmd](diagrams/02-agent-startup.mmd)

这里有个设计点：TUN 模式启用时，本地 HTTP/SOCKS5 监听仍然保留，所以用户可以同时用系统级 TUN 和手动浏览器代理。

## 5. 认证与加密流程

![认证与加密流程](diagrams/03-auth-encryption.svg)

Mermaid 源码：[03-auth-encryption.mmd](diagrams/03-auth-encryption.mmd)

这张图描述 direct framed TCP 与 TCP/Yamux 子流的流式握手。注意顺序：认证响应本身是未加密的。双方必须在成功响应之后才把 AES cipher 写入 `CipherState`，否则读写状态会错位。

实现细节：

- 客户端握手在 `common/src/client_connection/authenticated.rs`。
- Proxy 认证在 `proxy/src/connection/auth.rs`。
- 加解密状态在 `protocol/src/codec/cipher_state.rs`。
- AES-GCM 在 `protocol/src/crypto/aes_gcm_cipher.rs`。

原生 UDP 不复用上述有序字节流状态机，其线协议在 `protocol/src/udp_transport/`：

- Agent 使用用户 RSA 私钥为 session ID、时间戳和 client nonce 的认证上下文提供身份证明；Proxy 校验用户公钥与时间窗口。
- Proxy 为成功认证的 session 产生 master key 和 server nonce，并只把 RSA 保护后的 session secret 返回给 Agent。
- 双方通过 HKDF 派生 Agent→Proxy 与 Proxy→Agent 两组 AES-256-GCM key/nonce prefix，避免双向密钥与 nonce 空间复用。
- 每个加密数据报都有独立递增的 `seq`；完整固定头（magic、version、kind、session ID、sequence、message/fragment 信息和总长度）作为 AAD。
- 接收端用滑动 replay window 在允许有限乱序的同时丢弃重复包和过旧包。原生 UDP 外层不补可靠排序或重传。
- 大消息按安全 MTU 做有界分片/重组，每个分片拥有自己的 sequence 和 AEAD tag，重组资源有大小与时限边界。

安全观察：流式 PPAASS Auth 为了满足“Agent 持私钥、Proxy 持公钥”的需求，使用了私钥操作和公钥还原的 RSA 原语。这是签名式思路，不是常见的“公钥加密、私钥解密”KEM 流程。原生 UDP 则把身份签名与 Proxy→Agent 的 RSA session-secret 保护拆开；两条路径在生产安全评审时都应单独审计。

## 6. 目标传输管理：TCP 固定 direct framed，UDP 可选原生 UDP/TCP-Yamux

Agent 保留 `tcp_sessions` 和 `udp_sessions` 等管理器概念，但两条路径的抽象不再强行统一成“目标流”：

- `tcp_sessions`: HTTP CONNECT、普通 HTTP、SOCKS5 TCP、TUN TCP 使用；无论 `transport_mode` 取何值，每个 TCP 目标都建立一条 direct framed PPAASS TCP 连接到 Proxy。
- 代理 UDP: SOCKS5 UDP、TUN UDP、DNS proxy、共享 UDP relay 使用；`transport_mode = "udp"` 时经有状态原生 UDP session 发送独立数据报，`transport_mode = "tcp"` 时从 raw TCP/Yamux 外层连接打开子流。
- 直连 UDP: `direct_access` 命中时从 Agent 本地绑定/保护的 UDP socket 直接到目标，不进入上述任一代理封装。

关键文件：

- `desktop-agent-be/src/yamux_session/manager.rs`
- `desktop-agent-be/src/yamux_session/proxy_connection.rs`
- `desktop-agent-be/src/yamux_session/manager/yamux.rs`
- `common/src/transport.rs`
- `common/src/client_connection/udp.rs`
- `common/src/client_connection/yamux.rs`
- `protocol/src/udp_transport/*.rs`

Mermaid 源码：[04-yamux-session-manager.mmd](diagrams/04-yamux-session-manager.mmd)

当前传输关系：

- TCP 目标：Agent 直接连 Proxy，连接内执行 PPAASS Auth，然后发送 `ConnectRequest`，后续数据通过加密 `DataPacket` 传输；这条路径完全不读取 UDP session 数。
- 原生 UDP 模式：Agent 维护 1–8 条有状态 UDP session/socket。UDP flow 稳定映射到一个 session，先用 RSA 完成 session 身份认证和密钥建立，再发送逐包 AES-256-GCM 保护的 `Connect/Data/Close` 消息。数据报允许丢包和有限乱序，不提供外层重传或可靠有序语义。
- TCP 模式 UDP relay：Agent 到 Proxy 的外层连接是 raw TCP + `tokio-yamux`；每个 UDP relay 目标或共享 relay 通道先打开 Yamux 子流，再在子流内执行 PPAASS Auth/Connect/Data。
- Agent 启动时不预热 UDP Yamux session；`sessions` 只在 TCP 模式生效，表示最大外层连接数，请求路径在现有 session 没有可立即打开子流的容量时按需补 1 条。`udp_session_pool_size` 只属于原生 UDP 模式。
- Proxy 的 TCP accept 会判断首包是否像 Yamux header；direct framed 连接直接进入流协议状态机，Yamux 连接先 accept 子流。raw UDP listener 则按 session ID 分发数据报，完成认证、AEAD 校验、防重放、重组和 UDP flow relay。

## 7. HTTP 本地代理路径

文件：`desktop-agent-be/src/http_handler.rs`

![HTTP 本地代理路径](diagrams/05-http-path.svg)

Mermaid 源码：[05-http-path.mmd](diagrams/05-http-path.mmd)

细节：

- CONNECT 不会一开始就给客户端 200。代理路径会先让 Proxy 成功连上目标，再回复 200，避免客户端拿到半开的隧道。
- 普通 HTTP 请求会把代理收到的 absolute-form URI 修正成 origin-form path/query 再发给目标。
- IPv6 Host 头有专门解析逻辑。

## 8. SOCKS5 本地代理路径

文件：

- `desktop-agent-be/src/socks5_handler.rs`
- `desktop-agent-be/src/socks5_handler/tcp.rs`
- `desktop-agent-be/src/socks5_handler/udp_associate.rs`
- `desktop-agent-be/src/socks5_handler/udp_relay.rs`

![SOCKS5 本地代理路径](diagrams/06-socks5-path.svg)

Mermaid 源码：[06-socks5-path.mmd](diagrams/06-socks5-path.mmd)

SOCKS5 本地侧不做用户认证；用户身份是 Agent 到 Proxy 的 RSA/AES 握手承担的。

## 9. Proxy 连接状态机

Mermaid 源码：[07-proxy-state-machine.mmd](diagrams/07-proxy-state-machine.mmd)

关键文件：

- `proxy/src/server.rs`: 入站 TCP/raw UDP accept、direct framed/Yamux 识别、原生 UDP session 分发与认证超时。
- `proxy/src/native_udp.rs`: raw UDP listener、session 生命周期、认证消息、flow relay 与回包。
- `proxy/src/connection/auth.rs`: 每条 direct framed 连接或 Yamux 子流内的流式 Auth。
- `proxy/src/connection/connect.rs`: Connect 分流。
- `proxy/src/connection/relay.rs`: TCP/单目标 UDP 中继。
- `proxy/src/connection/udp_relay.rs`: 共享 UDP relay。
- `proxy/src/connection/upstream.rs`: forward mode 连接上游 PPAASS proxy。
- `protocol/src/udp_transport/`: raw UDP listener 使用的认证、packet codec、防重放和重组规则。

## 10. UDP 的两种代理承载

UDP relay 的两种传输模式共享上层 flow/目标语义，但线协议不同。`udp` 模式通过认证的原生数据报传递 `OpenData`、`ConnectResponse`、`Data`、`Close` 和保活消息；`OpenData` 把目标地址与首个 UDP payload 合并，不再单独往返 `Connect`。`tcp` 模式则为 UDP 目标或共享 relay 打开 Yamux 子流，并继续使用完整的 PPAASS Auth/Connect/Data 帧。TCP 目标始终使用 direct framed TCP，不进入任何 UDP transport 分支。

TCP 模式的 Yamux 流程图源码：[08-yamux-substream-datapacket.mmd](diagrams/08-yamux-substream-datapacket.mmd)

TCP/Yamux 模式顺序：

- Agent 在 Yamux 子流内发送 `Auth`。
- Proxy 对该业务流认证成功后返回 `AuthResponse`。
- Agent 在同一业务流内发送目标 `ConnectRequest`，例如单目标 UDP 或 `Address::UdpRelay`。
- 成功后双方继续通过加密的 `DataPacket` 传输 payload 和半关闭信号。
- 上层 SOCKS/TUN UDP 只看到普通 UDP payload；raw TCP/Yamux 提供复用和流控。

原生 UDP 模式先建立共享 session，再以 `flow_id` 关联每个目标的 Connect/Data/Close。每个数据报或分片单独加密认证，接收端只有在 AEAD、sequence/replay window 和分片重组全部通过后才把消息交给 relay。它不会把多条数据报拼成可靠字节流，也不会因丢包阻塞后续独立数据报。

## 11. UDP relay

UDP 有两种代理语义。

### 11.1 单目标 UDP

一个 `ConnectRequest` 对应一个 UDP 目标。Proxy 端 `UdpSocket::connect(target)`，后续只收发 payload。

### 11.2 共享 UDP relay

用于高并发 UDP，尤其是 TUN 模式下很多 UDP flow。

![共享 UDP relay](diagrams/09-udp-relay.svg)

Mermaid 源码：[09-udp-relay.mmd](diagrams/09-udp-relay.mmd)

TCP/Yamux 模式在 `DataPacket` 内使用 `UdpRelayPacket`，原生 UDP 模式在已认证的 `UdpSessionMessage` 内表达等价的 flow/target/payload 关系。共享 relay 的核心字段包括：

- `flow_id`
- `address`
- `data`

Proxy 对每个 `flow_id` 维护一个 UDP socket。资源控制包括：

- 每个内部队列大小。
- 每条共享 relay 的内层 flow/目标 socket 上限；达到上限后已有 flow 继续工作，新 flow 在创建 socket 前被丢弃。
- 每条原生 UDP session 的外层 flow 上限；达到上限后重复 Connect 保持幂等，新 Connect 返回失败。
- 每个 UDP flow 的 idle timeout。
- 每条原生 UDP session 的分片重组默认最多保留 64 条未完整消息和 1 MiB payload，仍可容纳单条 70 KiB 协议消息。

## 12. TUN 模式

文件主线：

- `desktop-agent-be/src/tun_handler.rs`
- `desktop-agent-be/src/tun_handler/proxy_routing.rs`
- `desktop-agent-be/src/tun_handler/device/*`
- `desktop-agent-be/src/tun_handler/netstack.rs`
- `desktop-agent-be/src/tun_handler/tasks.rs`
- `desktop-agent-be/src/tun_handler/tcp.rs`
- `desktop-agent-be/src/tun_handler/udp.rs`
- `desktop-agent-be/src/tun_handler/dns_proxy.rs`
- `desktop-agent-be/src/tun_handler/udp_relay.rs`

![TUN 模式](diagrams/10-tun-mode.svg)

Mermaid 源码：[10-tun-mode.mmd](diagrams/10-tun-mode.mmd)

TUN 模式里的关键细节：

- 必须先固定 agent 到 proxy 的控制连接出口，再安装默认路由劫持，否则控制连接会回流进 TUN。
- 桌面 TUN 使用 `netstack-smoltcp` 把 IP 包还原为 TCP/UDP。
- DNS proxy 不修改系统 DNS，而是捕获发往 53 端口的请求，通过 `Address::ProxyDns` 让 Proxy 端解析。
- DNS 响应里的域名/IP 映射会进入 `DirectDomainCache`，帮助后续 IP 连接按域名规则直连。
- TUN TCP 不再读取首包嗅探 TLS SNI/HTTP Host；域名规则只依赖显式域名目标或 DNS proxy 记录的域名/IP 缓存。
- `[tun].proxy_udp` 默认开启，未命中直连规则的普通 UDP 沿用共享 UDP relay；`udp` 模式通过原生加密 UDP session 承载，`tcp` 模式通过 TCP/Yamux 承载。关闭后除代理 DNS 与独立处理的 UDP/443 应用层 QUIC 外，其余 UDP 由 Agent 绑定物理出口直接发往目标。
- UDP/443 命中直连规则时由 Agent 的绑定/保护 UDP socket 直接到目标，完全不经过 PPAASS 原生 UDP 封装；未命中时使用共享 UDP relay，并按 `transport_mode` 选择原生加密 UDP 或 TCP/Yamux。
- `proxy_dns` 与 `proxy_udp` 独立；开启代理 DNS 时，有效 DNS 请求仍交给 Proxy 端解析。
- `quic_policy` 只控制应用层 UDP/443 QUIC：默认允许命中 `direct_access` 的流量直连，未命中时按所选 UDP transport 代理。只有显式开启阻断时，才会丢弃 UDP/443 并强制应用回退 TCP/TLS。这里的 QUIC 与 Agent→Proxy 外层协议无关。
- macOS 可使用同一个 `desktop-agent` 二进制的 helper service 模式处理 TUN/路由权限。
- Windows 启动脚本会安装最高权限计划任务来避免每次 UAC。

## 13. Proxy 出站与 forward mode

普通模式：

![Proxy 出站](diagrams/11-proxy-egress.svg)

Mermaid 源码：[11-proxy-egress.mmd](diagrams/11-proxy-egress.mmd)

forward mode：

![forward mode](diagrams/12-forward-mode.svg)

Mermaid 源码：[12-forward-mode.mmd](diagrams/12-forward-mode.mmd)

forward mode 里，Proxy A 作为“下游 Proxy 的服务端”和“上游 Proxy 的客户端”同时存在，连接上游时复用 `common::ClientConnection` 的 Auth/Connect 逻辑。

## 14. 配置关系

### Agent 配置

主要文件：`desktop-agent-be/src/config/agent_config.rs`

常见字段：

- `listen_addr`: 本地 HTTP/SOCKS5 监听地址。
- `proxy_addrs`: 远端 Proxy 地址列表，连接时随机选择。
- `username`: 用户名。
- `private_key_path`: 用户私钥。
- `transport_mode`: 只接受 `udp`/`tcp`；`udp` 是 TCP direct framed + 原生加密 UDP，`tcp` 是 TCP direct framed + UDP TCP/Yamux。旧值 `quic` 不兼容且会被拒绝，不做别名或自动迁移。
- `udp_session_pool_size`: 仅原生 UDP relay 使用，范围 1–8；每项代表一条有状态 UDP session/socket，TCP 目标完全不读取该值。旧字段 `quic_connection_pool_size` 同样会被拒绝。
- `compression_mode`: `none`、`lz4`、`gzip`、`zstd`；仅用于 framed TCP/TCP-Yamux，原生加密 UDP 数据报不压缩。
- `[yamux.udp]`: 仅 `tcp` 模式下 Agent 端 UDP relay 使用的 raw Yamux 最大 session 数、每 session 子流数、窗口等。TCP relay 始终不使用 Yamux session。
- `[tun]`: TUN 设备、普通 UDP 直连/代理切换、DNS、应用层 UDP/443 QUIC policy、helper、状态文件。
- `[direct_access]`: `proxy_all`、`direct_all`、`rules`。

### Proxy 配置

主要文件：`proxy/src/config/proxy_config.rs`

常见字段：

- `listen_addr`: Proxy 监听地址。
- Proxy 在 `listen_addr` 的同一数值端口绑定 TCP 与 raw UDP；启用原生 UDP 模式时防火墙必须同时放行 UDP。
- `users_path`: 用户配置文件。
- `compression_mode`: Proxy framed TCP/TCP-Yamux 响应编码使用的压缩模式；不影响原生 UDP。
- `replay_attack_tolerance`: Auth 时间戳容忍窗口，默认 300 秒。
- `[yamux]`: Proxy 作为 `tcp` 模式 UDP Yamux acceptor 的子流上限、窗口和超时。TCP 入站 framed 连接进入 PPAASS 流协议处理；raw UDP 入站进入独立的 session packet codec。
- `forward_mode`: 是否转发到上游 Proxy。
- `outbound_interface`: 出站网卡，支持空、具体网卡、`auto`。
- `dns_upstream_addr`: Proxy 端 DNS 上游。
- `auth_timeout_secs`、`tcp_relay_idle_timeout_secs`、`yamux_session_idle_timeout_secs`。
- `udp_relay_channel_size`: 共享 UDP relay 每条内部队列大小。
- `udp_relay_max_flows`: 每条共享 UDP relay 的内层 flow/目标 socket 上限，默认 256。
- `udp_session_limit`: 同时存在的已认证原生 UDP session 上限，默认 4096。
- `udp_session_channel_size`: 每个原生 UDP session 的有界数据报队列，默认 256。
- `udp_session_max_flows`: 每个原生 UDP session 的外层 flow 上限，默认 256。

### 用户配置

主要文件：

- `proxy/src/config/user_config.rs`
- `proxy/src/user_manager.rs`
- `config/local/users.toml`

字段：

- `username`: 必须与 `[users.<key>]` 的 key 一致。
- `public_key_pem`: Proxy 持有用户公钥。
- `expires_at`: 可选 RFC3339 或 Unix 秒级时间戳。

## 15. 桌面 UI

技术栈：

- Vue 3 + TypeScript + PrimeVue。
- Tauri 2 Rust 后端。
- UI 后端直接依赖 `desktop-agent-be` crate。

主线文件：

- `desktop-agent-ui/src/App.vue`
- `desktop-agent-ui/src/composables/useDesktopAgent.ts`
- `desktop-agent-ui/src-tauri/src/app.rs`
- `desktop-agent-ui/src-tauri/src/agent.rs`
- `desktop-agent-ui/src-tauri/src/config.rs`

![桌面 UI](diagrams/13-desktop-ui.svg)

Mermaid 源码：[13-desktop-ui.mmd](diagrams/13-desktop-ui.mmd)

重要设计：

- UI 不是简单启动外部 `desktop-agent.exe`。非 Windows 主要走内嵌 Agent 线程。
- 启动前如果配置有脏改动，会先保存配置。
- Agent 运行中锁定配置，避免运行时改 TOML 和内存状态不一致。
- 传输模式只显示“原生加密 UDP”和“TCP/Yamux”：选择前者时才显示 1–8 的 UDP session 数；TCP 目标的说明始终是原有 direct framed TCP。Agent 启动后传输模式不能切换。
- Windows 有 service / 计划任务路径。
- macOS 有 TUN helper 检查和安装路径。
- 前端有 fallback 数据，所以非 Tauri 浏览器里也能看到 UI 骨架。

## 16. Android Agent

Android 分两层：

![Android Agent](diagrams/14-android-agent.svg)

Mermaid 源码：[14-android-agent.mmd](diagrams/14-android-agent.mmd)

关键文件：

- `android-agent/app/src/main/java/com/ppaass/ai/agent/PpaassVpnService.java`
- `android-agent/app/src/main/java/com/ppaass/ai/agent/NativeAgent.java`
- `android-agent/native/src/jni_api.rs`
- `android-agent/native/src/netstack.rs`
- `android-agent/native/src/yamux_session.rs`
- `android-agent/native/src/config.rs`

Android 和桌面 TUN 的相同点：

- 都用 `netstack-smoltcp`。
- 都复用 `common` 和 `protocol`。
- 都支持 TCP 固定 direct framed、UDP 原生加密 UDP/TCP-Yamux 可选传输、direct_access、proxy DNS、应用层 QUIC 分流和可选 QUIC 阻断。桌面 TUN 还可通过 `proxy_udp` 将代理 DNS 与 UDP/443 应用层 QUIC 之外的普通 UDP 切换为 Agent 本地直连。

不同点：

- Android 的 TUN fd 由系统 `VpnService` 创建。
- 控制连接通过 `VpnService.protect(fd)` 排除出 VPN 路径。
- 配置从 Java UI 的 JSON 传给 Rust，不是读 TOML。
- Android 支持应用 allow-list。
- Android UI 仅在选择 `udp` 模式时显示 1–8 的原生 UDP session 数；VPN 或本地 HTTP/SOCKS5 Agent 运行期间锁定传输模式，避免界面选择与 native 运行状态分离。

## 17. 测试体系

测试工具在 `tests/` crate。

![测试体系](diagrams/15-testing-topology.svg)

Mermaid 源码：[15-testing-topology.mmd](diagrams/15-testing-topology.mmd)

主要文件：

- `tests/src/mock_target.rs`: HTTP、TCP echo、UDP echo 目标。
- `tests/src/mock_client.rs`: HTTP client、SOCKS5 TCP/UDP client。
- `tests/src/integration_tests.rs`: 功能链路测试。
- `tests/src/performance_tests.rs`: 并发压测、延迟直方图、吞吐、系统指标。
- `tests/src/report.rs`: HTML/JSON/Markdown 报告。
- `run-tests.sh`: 启动测试工具的脚本。

典型运行顺序：

```bash
cargo build --release --workspace

# 终端 1
./run-tests.sh mock-target

# 终端 2
cargo run --release -p proxy -- --config config/local/proxy.toml

# 终端 3
cargo run --release -p desktop-agent-be --bin desktop-agent -- --config config/local/agent.toml

# 终端 4
./run-tests.sh integration
./run-tests.sh performance 100 60
```

注意：文档和 CI 中有的示例使用 `127.0.0.1:7070`，当前 `config/local/agent.toml` 里是 `0.0.0.0:10080`。跑测试时要让 `AGENT_ADDR` 和实际配置一致。

## 18. CI 与部署

`.github/workflows/` 里主要有：

- `unit-test.yml`: Debian container，Rust 1.93，build workspace，跑 unit tests。
- `integration-test.yml`: 启动 mock target、proxy、agent，然后跑 integration tests。
- `rust-clippy.yml`: Clippy SARIF 分析。
- `deploy-proxy.yml`: 手动选择 production/dev/qa，构建 Linux proxy，打包 `proxy`、`proxy.toml`、`users.toml`、`start-proxy.sh`，上传远端并重启。
- `checkmarx-one.yml` / `codescan.yml`: 安全/代码扫描。

部署脚本：

- `start-proxy.sh`: Linux Proxy supervisor，支持 start/stop/status/restart，可 systemd 外独立守护。
- `start-agent.bat`: Windows Agent；TUN 开启时安装/使用最高权限计划任务。
- `start-agent.sh` / `start-agent.command`: macOS/Linux Agent；macOS TUN helper 自动安装。

## 19. 建议阅读顺序

如果你要真正吃透项目，建议按这个顺序读：

1. `README.md`、`docs/REQUIREMENTS.md`：先知道业务目标。
2. `Cargo.toml`：看 workspace 和核心依赖。
3. `protocol/src/message/*.rs`：先看协议消息长什么样。
4. `protocol/src/codec/message_codec.rs`：理解帧、压缩和 AES 的位置。
5. `common/src/client_connection/authenticated.rs`：理解 Auth + Connect 客户端流程。
6. `proxy/src/server.rs`、`proxy/src/connection/auth.rs`、`proxy/src/connection/connect.rs`：看 Proxy 状态机。
7. `desktop-agent-be/src/server.rs`：看本地入口如何分 HTTP/SOCKS/TUN。
8. `desktop-agent-be/src/http_handler.rs` 和 `socks5_handler.rs`：看本地代理细节。
9. `common/src/transport.rs`、`common/src/client_connection/udp.rs`、`protocol/src/udp_transport/*` 与 `desktop-agent-be/src/yamux_session/*`：分别看传输选择、原生 UDP client/packet protocol，以及 TCP/direct-framed 和 TCP-mode Yamux 流。
10. `proxy/src/connection/relay.rs`、`udp_relay.rs`：看数据搬运。
11. `desktop-agent-be/src/tun_handler/*`：最后再读 TUN，因为它依赖前面所有概念。
12. `desktop-agent-ui/src-tauri/src/app.rs` 和 `agent.rs`：看 UI 如何嵌入 Agent。
13. `android-agent/native/src/netstack.rs` 和 `yamux_session.rs`：看 Android 如何复用核心。
14. `tests/src/integration_tests.rs`：用测试把理解闭环。

## 20. 常见容易误解的点

- Agent 本地 SOCKS5 默认无认证，不代表系统无用户认证；真正的用户认证发生在 Agent 到 Proxy。
- 全 TCP 模式的 Yamux 外层连接是 raw TCP，不再经过 PPAASS Auth/Connect；PPAASS Auth/Connect 发生在 UDP Yamux 子流内。
- `transport_mode = "udp"` 不是“所有数据走 UDP”，而是 TCP 目标继续使用 direct framed PPAASS TCP，只有代理 UDP 使用原生加密 UDP session。
- `transport_mode = "tcp"` 也不改变 TCP 目标路径，只是把代理 UDP 切换到 raw TCP/Yamux。
- 旧的 `transport_mode = "quic"` 与 `quic_connection_pool_size` 已移除且不会自动迁移；必须显式改为新配置。
- `quic_policy` 和 UDP/443 Version Negotiation 诊断说的是应用层 QUIC，不是 Agent→Proxy 外层。命中 `direct_access` 的 UDP 使用本地直连 socket，也不经过原生 UDP 封装。
- `Address::UdpRelay`、`Address::ProxyDns` 是协议虚拟地址，不是真实互联网目标。
- TUN 模式要先固定 proxy 控制连接的物理出口，再安装 TUN 路由。
- `direct_access` 在 TUN 模式下直接看 IP/CIDR；域名规则只在 DNS proxy 缓存命中时影响已解析 IP，不再通过 TLS SNI/HTTP Host 嗅探补充。
- Proxy 的 `compression_mode` 和 Agent 的 `compression_mode` 是 framed TCP/TCP-Yamux 上各自发送方向的编码选择；实际解码靠消息里的 compression flag。原生 UDP 始终保持数据报边界，不使用该压缩设置。

## 21. 一张压缩版端到端图

Mermaid 源码：[16-end-to-end.mmd](diagrams/16-end-to-end.mmd)

这就是整个项目的主线：入口很多，最终都收敛到“目标解析 -> 是否直连 -> Auth/Connect -> relay”。
