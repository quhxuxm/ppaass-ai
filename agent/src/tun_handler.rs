//! TUN 模式转发器。
//!
//! 当 TUN 模式启用时，agent 会打开一个 TUN 设备，并使用
//! [`netstack-smoltcp`](https://crates.io/crates/netstack-smoltcp) 在其上构建
//! 用户空间 TCP/IP 协议栈。协议栈接受的每个 TCP/UDP 流都会通过现有的
//! [`ConnectionPool`] 转发到代理，复用 SOCKS5/HTTP 处理器所使用的相同协议。
//! 匹配 `direct_access` 规则的目标将直连，不经过代理。

use crate::config::TunConfig;
use crate::connection_pool::ConnectionPool;
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AgentError, Result};
use crate::telemetry;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use protocol::{Address, TransportProtocol};
use route_manager::{Route, RouteManager};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, warn};
use tun_rs::DeviceBuilder;

/// 公开入口：构建 TUN 设备，连接到 netstack，运行转发循环直到 `shutdown` 触发。
#[instrument(skip(pool, direct_checker, shutdown))]
pub async fn run_tun_mode(
    config: TunConfig,
    proxy_addrs: Vec<String>,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
    shutdown: CancellationToken,
) -> Result<()> {
    info!(
        "启动 TUN 模式转发器：设备={} ipv4={} ipv6={:?} mtu={}",
        config.name, config.ipv4, config.ipv6, config.mtu
    );
    let proxy_dns = config.proxy_dns;
    if proxy_dns {
        info!("TUN DNS 请求将交给 proxy 端默认 DNS 处理");
    }

    // ---- 1. 构建 TUN 设备 ------------------------------------------------
    let (ipv4, ipv4_prefix) = parse_cidr_v4(&config.ipv4)?;
    let ipv6_config = config.ipv6.as_deref().map(parse_cidr_v6).transpose()?;
    let tun_networks = TunNetworks {
        ipv4,
        ipv4_prefix,
        ipv6: ipv6_config,
    };
    let mut builder = DeviceBuilder::new()
        .name(&config.name)
        .mtu(config.mtu)
        .ipv4(ipv4, ipv4_prefix, None);
    if let Some((ipv6, ipv6_prefix)) = ipv6_config {
        builder = builder.ipv6(ipv6, ipv6_prefix);
    }
    let device = builder
        .build_async()
        .map_err(|e| AgentError::Connection(format!("创建 TUN 设备失败：{e}")))?;
    let tun_name = device
        .name()
        .map_err(|e| AgentError::Connection(format!("读取 TUN 设备名失败：{e}")))?;
    let tun_if_index = device
        .if_index()
        .map_err(|e| AgentError::Connection(format!("读取 TUN if_index 失败：{e}")))?;
    let device = Arc::new(device);
    info!(
        "TUN 设备已创建：名称={} if_index={}",
        tun_name, tun_if_index
    );

    // ---- 1b. 检测物理出口 IP ---------------------------------------------
    // 在修改任何路由之前，探测向代理服务器发包时 OS 会使用哪个本地 IP。
    // 该 IP 属于物理网卡。我们后续通过 TcpSocket::bind 将所有代理连接
    // 锁定到这个 IP，确保 split-default TUN 路由生效后流量仍从物理网卡出。
    let outbound_ip = detect_outbound_ip(&proxy_addrs);
    if let Some(ip) = outbound_ip {
        info!("检测到物理出口 IP：{}；代理连接将绑定到该地址", ip);
        pool.set_proxy_bind_ip(Some(ip));
    } else {
        warn!(
            "无法检测物理出口 IP — 代理连接可能会回环进入 TUN。\
             请确保启动 TUN 模式前代理服务器可达。"
        );
    }

    // TUN 模式必须在设置绑定 IP 后、劫持默认路由前预热连接池。
    // 否则预热连接可能不绑定物理出口，后续连接也可能被新路由绕回 TUN。
    pool.prewarm().await;

    // ---- 1c. 劫持路由表 --------------------------------------------------
    // 解析代理服务器地址以安装 /32 旁路路由（纵深防御），
    // 然后将默认路由重定向到 TUN。RouteGuard 在 drop 时恢复所有路由。
    let proxy_ips = resolve_proxy_ips(&proxy_addrs);
    let route_guard =
        match RouteGuard::install(tun_if_index, ipv4, config.ipv6.as_deref(), &proxy_ips) {
            Ok(g) => Some(g),
            Err(e) => {
                warn!(
                    "安装 TUN 路由失败（继续运行但不劫持路由）：{e}。\
                 可能需要手动配置路由或以提升权限运行。"
                );
                None
            }
        };

    // ---- 2. 构建用户空间网络协议栈 ----------------------------------------
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(config.mtu as usize)
        .build()
        .map_err(|e| AgentError::Connection(format!("构建 netstack 失败：{e}")))?;
    if let Some(runner) = runner {
        tokio::spawn(runner);
    }
    let tcp_listener =
        tcp_listener.ok_or_else(|| AgentError::Connection("netstack TCP 监听器不可用".into()))?;
    let udp_socket =
        udp_socket.ok_or_else(|| AgentError::Connection("netstack UDP 套接字不可用".into()))?;

    let (mut stack_sink, mut stack_stream) = stack.split();

    // ---- 3. TUN <-> netstack 数据包穿梭 ----------------------------------
    let device_in = device.clone();
    let shutdown_in = shutdown.clone();
    let mtu = config.mtu as usize;
    let tun_to_stack = tokio::spawn(async move {
        let mut buf = vec![0u8; mtu.max(1500) + 64];
        loop {
            tokio::select! {
                _ = shutdown_in.cancelled() => break,
                read = device_in.recv(&mut buf) => {
                    match read {
                        Ok(n) if n > 0 => {
                            let pkt = buf[..n].to_vec();
                            if let Err(e) = stack_sink.send(pkt).await {
                                warn!("向 netstack 推送数据包失败：{e}");
                                break;
                            }
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            error!("TUN 读取错误：{e}");
                            break;
                        }
                    }
                }
            }
        }
        debug!("tun_to_stack 任务退出");
    });

    let device_out = device.clone();
    let shutdown_out = shutdown.clone();
    let stack_to_tun = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_out.cancelled() => break,
                pkt = stack_stream.next() => {
                    match pkt {
                        Some(Ok(pkt)) => {
                            if let Err(e) = device_out.send(&pkt).await {
                                warn!("向 TUN 设备写入数据包失败：{e}");
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            warn!("netstack 流错误：{e}");
                        }
                        None => break,
                    }
                }
            }
        }
        debug!("stack_to_tun 任务退出");
    });

    // ---- 4. TCP 监听器 ---------------------------------------------------
    let pool_tcp = pool.clone();
    let checker_tcp = direct_checker.clone();
    let shutdown_tcp = shutdown.clone();
    let tun_networks_tcp = tun_networks;
    let proxy_dns_tcp = proxy_dns;
    let mut tcp_listener = tcp_listener;
    let tcp_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_tcp.cancelled() => break,
                accepted = tcp_listener.next() => {
                    let Some((stream, source_addr, target_addr)) = accepted else { break };
                    // 对于 netstack 接受的 TcpStream：
                    //   source_addr = TUN 内客户端的源地址
                    //   target_addr = 客户端尝试访问的真实目标地址
                    debug!("TUN TCP {} -> {}", source_addr, target_addr);
                    let pool = pool_tcp.clone();
                    let checker = checker_tcp.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_tun_tcp(
                                stream,
                                source_addr,
                                target_addr,
                                tun_networks_tcp,
                                proxy_dns_tcp,
                                pool,
                                checker,
                            ).await
                        {
                            debug!("TUN TCP 流结束：{e}");
                        }
                    });
                }
            }
        }
        debug!("tcp_task 退出");
    });

    // ---- 5. UDP 套接字 ---------------------------------------------------
    let pool_udp = pool.clone();
    let checker_udp = direct_checker.clone();
    let shutdown_udp = shutdown.clone();
    let tun_networks_udp = tun_networks;
    let proxy_dns_udp = proxy_dns;
    let udp_task = tokio::spawn(async move {
        let (mut udp_rx, udp_tx) = udp_socket.split();
        let udp_tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
        let sessions: Arc<
            dashmap::DashMap<(SocketAddr, SocketAddr), tokio::sync::mpsc::Sender<Vec<u8>>>,
        > = Arc::new(dashmap::DashMap::new());

        loop {
            tokio::select! {
                _ = shutdown_udp.cancelled() => break,
                msg = udp_rx.next() => {
                    let Some((data, source_addr, target_addr)) = msg else { break };
                    // 对于 UDP：
                    //   source_addr = TUN 内客户端的源地址
                    //   target_addr = 客户端发送数据报的真实目标地址
                    let key = (source_addr, target_addr);
                    if let Some(tx) = sessions.get(&key).map(|t| t.clone()) {
                        let _ = tx.send(data).await;
                        continue;
                    }

                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                    sessions.insert(key, tx.clone());
                    let _ = tx.send(data).await;

                    let pool = pool_udp.clone();
                    let checker = checker_udp.clone();
                    let sessions_c = sessions.clone();
                    let udp_tx_c = udp_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_tun_udp(
                                source_addr,
                                target_addr,
                                tun_networks_udp,
                                proxy_dns_udp,
                                rx,
                                udp_tx_c,
                                pool,
                                checker,
                            ).await
                        {
                            debug!("TUN UDP 会话结束：{e}");
                        }
                        sessions_c.remove(&key);
                    });
                }
            }
        }
        debug!("udp_task 退出");
    });

    // ---- 6. 等待关闭 -----------------------------------------------------
    shutdown.cancelled().await;
    info!("收到 TUN 模式关闭请求");
    let _ = tokio::join!(tun_to_stack, stack_to_tun, tcp_task, udp_task);

    // 清除绑定 IP 覆盖，使连接池恢复为不绑定模式
    pool.set_proxy_bind_ip(None);

    // 显式 drop 路由守卫，此时 TUN 设备仍存活，
    // 内核能接受路由删除调用
    drop(route_guard);

    info!("TUN 模式转发器已停止");
    Ok(())
}

// ---------------------------------------------------------------------------
// TCP 单流处理器
// ---------------------------------------------------------------------------

async fn handle_tun_tcp(
    mut client: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    tun_networks: TunNetworks,
    proxy_dns: bool,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        reject_tun_target("TCP", source, target, tun_networks)?;
    }
    let target_label = if proxy_dns_request {
        format!("{target} -> proxy默认DNS")
    } else {
        target.to_string()
    };

    if !proxy_dns_request && direct_checker.is_direct(&address) {
        let target_str = address_to_string(&address);
        info!("TUN TCP 直连 -> {}", target_str);
        let mut target = TcpStream::connect(&target_str)
            .await
            .map_err(|e| AgentError::Connection(format!("直连 {target_str} 失败：{e}")))?;
        match tokio::io::copy_bidirectional(&mut client, &mut target).await {
            Ok((c2t, t2c)) => {
                telemetry::emit_traffic("TUN TCP (直连)", target_label, c2t, t2c);
            }
            Err(e) => debug!("TUN TCP 直连中继结束：{e}"),
        }
        let _ = client.shutdown().await;
        return Ok(());
    }

    if proxy_dns_request {
        info!("TUN TCP DNS -> 代理 -> {}", target_label);
    } else {
        info!("TUN TCP -> 代理 -> {}", target_label);
    }
    let connected = pool
        .as_ref()
        .get_connected_stream(address, TransportProtocol::Tcp)
        .await?;
    let mut proxy_io = connected.into_async_io();
    match tokio::io::copy_bidirectional(&mut client, &mut proxy_io).await {
        Ok((c2p, p2c)) => {
            telemetry::emit_traffic("TUN TCP", target_label, c2p, p2c);
        }
        Err(e) => debug!("TUN TCP 中继结束：{e}"),
    }
    let _ = client.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// UDP 单会话处理器
// ---------------------------------------------------------------------------

type UdpWriter = Arc<tokio::sync::Mutex<netstack_smoltcp::udp::WriteHalf>>;

async fn handle_tun_udp(
    client: SocketAddr, // TUN 内客户端的源地址
    target: SocketAddr, // 客户端尝试访问的真实目标地址
    tun_networks: TunNetworks,
    proxy_dns: bool,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    netstack_tx: UdpWriter,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        reject_tun_target("UDP", client, target, tun_networks)?;
    }
    let target_label = if proxy_dns_request {
        format!("{target} -> proxy默认DNS")
    } else {
        target.to_string()
    };

    if !proxy_dns_request && direct_checker.is_direct(&address) {
        let target_str = address_to_string(&address);
        info!("TUN UDP 直连 -> {}", target_str);
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&target_str).await?;
        let socket = Arc::new(socket);

        let socket_w = socket.clone();
        let write = async move {
            while let Some(data) = rx.recv().await {
                if let Err(e) = socket_w.send(&data).await {
                    debug!("UDP 直连发送错误：{e}");
                    break;
                }
            }
        };
        let netstack_tx_r = netstack_tx.clone();
        let read = async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv(&mut buf).await {
                    Ok(n) => {
                        let pkt = buf[..n].to_vec();
                        let mut s = netstack_tx_r.lock().await;
                        if let Err(e) = s.send((pkt, target, client)).await {
                            debug!("UDP 直连回复错误：{e}");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("UDP 直连接收错误：{e}");
                        break;
                    }
                }
            }
        };
        tokio::select! {
            _ = write => {}
            _ = read => {}
        }
        telemetry::emit_traffic("TUN UDP (直连)", target_label, 0, 0);
        return Ok(());
    }

    if proxy_dns_request {
        info!("TUN UDP DNS -> 代理 -> {}", target_label);
    } else {
        info!("TUN UDP -> 代理 -> {}", target_label);
    }
    let connected = pool
        .as_ref()
        .get_connected_stream(address, TransportProtocol::Udp)
        .await?;
    let proxy_io = connected.into_async_io();
    let (mut reader, mut writer) = tokio::io::split(proxy_io);

    let write = async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = writer.write_all(&data).await {
                debug!("UDP 代理写入错误：{e}");
                break;
            }
            let _ = writer.flush().await;
        }
    };
    let netstack_tx_r = netstack_tx.clone();
    let read = async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 65535];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let pkt = buf[..n].to_vec();
                    let mut s = netstack_tx_r.lock().await;
                    if let Err(e) = s.send((pkt, target, client)).await {
                        debug!("UDP 代理回复错误：{e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("UDP 代理读取错误：{e}");
                    break;
                }
            }
        }
    };
    tokio::select! {
        _ = write => {}
        _ = read => {}
    }

    telemetry::emit_traffic("TUN UDP", target_label, 0, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct TunNetworks {
    ipv4: Ipv4Addr,
    ipv4_prefix: u8,
    ipv6: Option<(Ipv6Addr, u8)>,
}

impl TunNetworks {
    fn contains_ip(self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => ipv4_in_cidr(ip, self.ipv4, self.ipv4_prefix),
            IpAddr::V6(ip) => self
                .ipv6
                .is_some_and(|(network, prefix)| ipv6_in_cidr(ip, network, prefix)),
        }
    }
}

fn reject_tun_target(
    transport: &str,
    source: SocketAddr,
    target: SocketAddr,
    tun_networks: TunNetworks,
) -> Result<()> {
    if !tun_networks.contains_ip(target.ip()) {
        return Ok(());
    }

    let message = format!(
        "TUN {transport} 目标地址异常：源地址 {source}，目标地址 {target} 落在 TUN 自身网段内；\
         这通常表示源地址和目标地址仍被反向使用"
    );
    error!("{message}");
    Err(AgentError::Connection(message))
}

fn address_for_tun_target(target: SocketAddr, proxy_dns: bool) -> (Address, bool) {
    if proxy_dns && target.port() == 53 {
        return (
            Address::ProxyDns {
                port: target.port(),
            },
            true,
        );
    }

    (socket_addr_to_address(target), false)
}

fn parse_cidr_v4(s: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| AgentError::Connection(format!("无效的 IPv4 CIDR：{s}")))?;
    let ip: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|e| AgentError::Connection(format!("无效的 IPv4 地址 {ip}：{e}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|e| AgentError::Connection(format!("无效的 IPv4 前缀 {prefix}：{e}")))?;
    if prefix > 32 {
        return Err(AgentError::Connection(format!(
            "无效的 IPv4 前缀 {prefix}：必须小于等于 32"
        )));
    }
    Ok((ip, prefix))
}

fn parse_cidr_v6(s: &str) -> Result<(std::net::Ipv6Addr, u8)> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| AgentError::Connection(format!("无效的 IPv6 CIDR：{s}")))?;
    let ip: std::net::Ipv6Addr = ip
        .parse()
        .map_err(|e| AgentError::Connection(format!("无效的 IPv6 地址 {ip}：{e}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|e| AgentError::Connection(format!("无效的 IPv6 前缀 {prefix}：{e}")))?;
    if prefix > 128 {
        return Err(AgentError::Connection(format!(
            "无效的 IPv6 前缀 {prefix}：必须小于等于 128"
        )));
    }
    Ok((ip, prefix))
}

fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_cidr(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from_be_bytes(ip.octets()) & mask) == (u128::from_be_bytes(network.octets()) & mask)
}

fn socket_addr_to_address(addr: SocketAddr) -> Address {
    match addr.ip() {
        IpAddr::V4(v4) => Address::Ipv4 {
            addr: v4.octets(),
            port: addr.port(),
        },
        IpAddr::V6(v6) => Address::Ipv6 {
            addr: v6.octets(),
            port: addr.port(),
        },
    }
}

// ---------------------------------------------------------------------------
// 路由表劫持
// ---------------------------------------------------------------------------

/// 检测 OS 当前使用哪个本地 IP 来到达代理服务器。
///
/// 创建一个 connected UDP 套接字（实际不发送数据包），让 OS 告知它会使用哪个
/// 本地地址。因为此操作在安装任何 TUN 路由规则之前运行，所以结果是物理网卡
/// 的 IP。将该 IP 存入 [`ConnectionPool::set_proxy_bind_ip`] 可确保即使
/// split-default TUN 路由生效后，代理 TCP 连接仍绑定到物理网卡，防止路由回环。
fn detect_outbound_ip(proxy_addrs: &[String]) -> Option<IpAddr> {
    for entry in proxy_addrs {
        // 确保有端口分量以便 `to_socket_addrs` 解析
        let candidate = if entry.contains(':') {
            entry.clone()
        } else {
            format!("{entry}:443")
        };
        if let Ok(mut iter) = candidate.to_socket_addrs() {
            if let Some(dst) = iter.next() {
                let bind_str = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                if let Ok(sock) = std::net::UdpSocket::bind(bind_str) {
                    if sock.connect(dst).is_ok() {
                        if let Ok(local) = sock.local_addr() {
                            return Some(local.ip());
                        }
                    }
                }
            }
        }
    }
    None
}

/// 将 `proxy_addrs` 中的每个 "host:port" 字符串解析为唯一 IP 列表。
/// 解析失败的主机名会被静默跳过（会打印警告）。
fn resolve_proxy_ips(proxy_addrs: &[String]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for entry in proxy_addrs {
        // 接受 "host:port" 或裸 "host"
        let candidates: Vec<String> = if entry.contains(':') {
            vec![entry.clone()]
        } else {
            vec![format!("{entry}:0")]
        };
        let mut resolved = false;
        for c in candidates {
            match c.to_socket_addrs() {
                Ok(iter) => {
                    for sa in iter {
                        let ip = sa.ip();
                        if !out.contains(&ip) {
                            out.push(ip);
                        }
                        resolved = true;
                    }
                }
                Err(e) => debug!("解析代理地址 {entry} 失败：{e}"),
            }
        }
        if !resolved {
            warn!("无法解析代理地址 {entry}；旁路路由已跳过");
        }
    }
    out
}

/// 记录所有已安装的路由，以便在 drop 时删除。
struct RouteGuard {
    mgr: RouteManager,
    installed: Vec<Route>,
}

impl RouteGuard {
    /// 先安装代理 /32 旁路路由，再安装指向 TUN 的 split-default 路由。
    /// 顺序很重要：旁路路由必须先于默认重定向存在，否则内核无法到达代理。
    fn install(
        tun_if_index: u32,
        tun_ipv4: Ipv4Addr,
        tun_ipv6_cidr: Option<&str>,
        proxy_ips: &[IpAddr],
    ) -> Result<Self> {
        let mut mgr = RouteManager::new()
            .map_err(|e| AgentError::Connection(format!("RouteManager 初始化失败：{e}")))?;

        // 查询当前默认 IPv4/IPv6 路由，保留网关供代理流量使用
        let (default_v4_gw, default_v4_if) = match mgr.list() {
            Ok(routes) => find_default_route(&routes, false),
            Err(e) => {
                warn!("无法列出当前路由：{e}");
                (None, None)
            }
        };
        let (default_v6_gw, default_v6_if) = match mgr.list() {
            Ok(routes) => find_default_route(&routes, true),
            Err(e) => {
                warn!("无法列出当前 IPv6 路由：{e}");
                (None, None)
            }
        };
        info!(
            "现有默认路由：v4 网关={:?} 接口={:?}，v6 网关={:?} 接口={:?}",
            default_v4_gw, default_v4_if, default_v6_gw, default_v6_if
        );

        let mut installed: Vec<Route> = Vec::new();

        // --- 代理旁路路由 -------------------------------------------------
        for ip in proxy_ips {
            let route = match ip {
                IpAddr::V4(v4) => {
                    let mut r = Route::new(IpAddr::V4(*v4), 32);
                    if let Some(gw) = default_v4_gw {
                        r = r.with_gateway(gw);
                    }
                    if let Some(idx) = default_v4_if {
                        r = r.with_if_index(idx);
                    }
                    r
                }
                IpAddr::V6(v6) => {
                    let mut r = Route::new(IpAddr::V6(*v6), 128);
                    if let Some(gw) = default_v6_gw {
                        r = r.with_gateway(gw);
                    }
                    if let Some(idx) = default_v6_if {
                        r = r.with_if_index(idx);
                    }
                    r
                }
            };
            match mgr.add(&route) {
                Ok(()) => {
                    info!("已安装代理旁路路由：{}", route);
                    installed.push(route);
                }
                Err(e) => warn!("为 {ip} 安装旁路路由失败：{e}"),
            }
        }

        // --- 经 TUN 的 split-default 路由 ---------------------------------
        // IPv4: 0.0.0.0/1 和 128.0.0.0/1 — 合起来覆盖整个 IPv4 地址空间，
        // 且比现有的 0.0.0.0/0 更具体，因此普通流量优先走 TUN，
        // 而代理的 /32 路由更具体，仍走原网关。
        let v4_splits = [
            Route::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
                .with_if_index(tun_if_index)
                .with_gateway(IpAddr::V4(tun_ipv4)),
            Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
                .with_if_index(tun_if_index)
                .with_gateway(IpAddr::V4(tun_ipv4)),
        ];
        for route in v4_splits {
            match mgr.add(&route) {
                Ok(()) => {
                    info!("已安装 split-default 路由：{}", route);
                    installed.push(route);
                }
                Err(e) => warn!("安装 split-default 路由 {} 失败：{e}", route),
            }
        }

        // IPv6: ::/1 和 8000::/1，仅当 TUN 配置了 IPv6 地址时安装。
        if let Some(v6_cidr) = tun_ipv6_cidr {
            if let Ok((tun_ipv6, _)) = parse_cidr_v6(v6_cidr) {
                let v6_splits = [
                    Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1)
                        .with_if_index(tun_if_index)
                        .with_gateway(IpAddr::V6(tun_ipv6)),
                    Route::new(IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1)
                        .with_if_index(tun_if_index)
                        .with_gateway(IpAddr::V6(tun_ipv6)),
                ];
                for route in v6_splits {
                    match mgr.add(&route) {
                        Ok(()) => {
                            info!("已安装 IPv6 split-default 路由：{}", route);
                            installed.push(route);
                        }
                        Err(e) => {
                            warn!("安装 IPv6 split-default 路由 {} 失败：{e}", route)
                        }
                    }
                }
            }
        }

        Ok(Self { mgr, installed })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        info!(
            "正在恢复路由表：删除 {} 条已安装的路由",
            self.installed.len()
        );
        // 反序删除：先删 split-default 路由使内核立即回退到原默认路由，
        // 再删代理 /32 旁路路由。
        while let Some(route) = self.installed.pop() {
            match self.mgr.delete(&route) {
                Ok(()) => debug!("已删除路由：{}", route),
                Err(e) => warn!("删除路由 {} 失败：{e}", route),
            }
        }
    }
}

/// 在 `routes` 中找到第一条非 TUN 的默认路由。
/// 返回 (网关, if_index) 以供安装旁路路由使用。
/// `want_v6 == true` 时查找 ::/0 而非 0.0.0.0/0。
fn find_default_route(routes: &[Route], want_v6: bool) -> (Option<IpAddr>, Option<u32>) {
    for r in routes {
        if r.prefix() != 0 {
            continue;
        }
        let is_v6 = matches!(r.destination(), IpAddr::V6(_));
        if is_v6 != want_v6 {
            continue;
        }
        let dest_unspec = match r.destination() {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        };
        if !dest_unspec {
            continue;
        }
        return (r.gateway(), r.if_index());
    }
    (None, None)
}
