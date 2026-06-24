//! SOCKS5 TCP 命令处理。
//!
//! CONNECT 是常规浏览器/应用代理路径；BIND 较少用，但同样会在直连或代理路径中
//! 最终转换成一个 `AsyncRead + AsyncWrite` 双向中继。

use super::*;
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};
use crate::tun_handler::domain_sniff::{extract_http_host, extract_tls_sni};

/// SOCKS5 IP 目标首包嗅探最大长度。这里只用于恢复被本地 DNS 解析掉的域名，
/// 不追求完整 TLS ClientHello 覆盖率；超出后直接按原始 IP 转发。
const SOCKS_SNIFF_MAX_BYTES: usize = 4096;
/// SOCKS5 已经完成握手后客户端通常会立刻发送 TLS ClientHello/HTTP 请求。
/// 等待过长会直接拖慢非 HTTP/TLS 的 IP 连接，因此保持和 TUN 轻量嗅探一致。
const SOCKS_SNIFF_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(60);
/// 已经读到部分首包后，后续补读只给一个很短的空闲窗口，避免拆包时误等满 60ms。
const SOCKS_SNIFF_INTER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(10);

pub(super) async fn handle_tcp_connect(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    target_addr: TargetAddr,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    let target_label = format_target_addr(&target_addr);
    let relay_buffer_size = pool.tcp_relay_buffer_size();

    // 将目标地址转换为协议 Address，之后直连规则和 proxy Connect 都使用同一表示。
    let address = convert_target_addr(&target_addr);

    if direct_checker.is_direct(&address) {
        // === 直连路径 ===
        let target_str = address_to_string(&address);
        info!("SOCKS5 CONNECT 使用直连连接到 {}", target_str);

        match TcpStream::connect(&target_str).await {
            Ok(mut target_stream) => {
                // SOCKS5 直连隧道也关闭 Nagle，避免本地代理模式下小控制帧被延迟合并。
                if let Err(err) = target_stream.set_nodelay(true) {
                    debug!("SOCKS5 直连目标 TCP_NODELAY 设置失败，继续使用默认行为：{err}");
                }
                // SOCKS5 要先回复成功，客户端才会开始发送 TCP payload。
                let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
                let mut client_stream = protocol
                    .reply_success(bind_addr)
                    .await
                    .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

                info!("SOCKS5 直连隧道已建立，开始数据中继");

                match relay_tcp_bidirectional(
                    &mut client_stream,
                    &mut target_stream,
                    relay_buffer_size,
                    TcpRelayOptions::standard(&target_label),
                )
                .await
                {
                    Ok(stats) => {
                        info!(
                            "直连 SOCKS5 中继完成: {} 字节发出, {} 字节接收",
                            stats.client_to_remote, stats.remote_to_client
                        );
                        telemetry::emit_traffic(
                            "SOCKS5 CONNECT (direct)",
                            target_label,
                            stats.client_to_remote,
                            stats.remote_to_client,
                        );
                    }
                    Err(e) => {
                        debug!("直连 SOCKS5 中继结束: {}", e);
                    }
                }
                Ok(())
            }
            Err(e) => {
                error!("直连到 {} 失败: {}", target_str, e);
                let _ = protocol.reply_error(&ReplyError::HostUnreachable).await;
                Err(AgentError::Connection(format!("直连失败: {}", e)))
            }
        }
    } else {
        // === 代理路径 ===
        // 如果 SOCKS5 客户端传来的是 IP:443/IP:80，通常表示浏览器或系统已经在本地
        // 做了 DNS 解析。这里做一次轻量首包嗅探，只用于日志和流量标签，不再把
        // proxy 目标从原始 IP 改成域名：部分视频 CDN 的签名/边缘调度会绑定浏览器
        // 已解析出的具体 IP，改由 proxy 重新解析域名反而会造成某些分片请求失败。
        if let Some(port) = socks_sniff_port(&target_addr) {
            let connected_stream = match pool
                .as_ref()
                .get_connected_stream(address.clone(), TransportProtocol::Tcp)
                .await
            {
                Ok(stream) => stream,
                Err(e) => {
                    error!("SOCKS5 连接原始 IP proxy 目标失败: {}", e);
                    let _ = protocol.reply_error(&ReplyError::HostUnreachable).await;
                    return Err(e);
                }
            };

            let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
            let mut client_stream = protocol
                .reply_success(bind_addr)
                .await
                .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

            let sniffed = sniff_first_client_bytes(&mut client_stream, port).await;
            let mut proxy_label = target_label.clone();
            if !sniffed.is_empty() {
                if let Some(domain) = sniff_domain(port, &sniffed) {
                    debug!(
                        "SOCKS5 IP 目标首包域名：{} -> {}，代理目标保留原始 IP",
                        target_label, domain
                    );
                    proxy_label = format!("首包域名 {domain}，原始目标 {target_label}");
                } else {
                    debug!(
                        "SOCKS5 IP 目标首包未解析出域名：target={} bytes={}",
                        target_label,
                        sniffed.len()
                    );
                }
            }

            info!("SOCKS5 隧道已建立，开始数据中继");
            return relay_data(
                &mut client_stream,
                connected_stream,
                "SOCKS5 CONNECT",
                proxy_label,
                relay_buffer_size,
                &sniffed,
            )
            .await;
        }

        let connected_stream = match pool
            .as_ref()
            .get_connected_stream(address, TransportProtocol::Tcp)
            .await
        {
            Ok(stream) => {
                info!("从连接池获取已连接流, stream_id: {}", stream.stream_id());
                stream
            }
            Err(e) => {
                error!("从连接池获取流失败: {}", e);
                let _ = protocol.reply_error(&ReplyError::HostUnreachable).await;
                return Err(e);
            }
        };

        // 发送成功回复，使用虚拟绑定地址
        // 代理路径中真实出口在 proxy 端，agent 本地只返回占位绑定地址。
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut client_stream = protocol
            .reply_success(bind_addr)
            .await
            .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

        info!("SOCKS5 隧道已建立，开始数据中继");

        // 启动双向数据中继
        relay_data(
            &mut client_stream,
            connected_stream,
            "SOCKS5 CONNECT",
            target_label,
            relay_buffer_size,
            &[],
        )
        .await
    }
}

pub(super) async fn handle_tcp_bind(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    target_addr: TargetAddr,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    info!("处理 SOCKS5 BIND 命令，目标: {:?}", target_addr);
    let target_label = format_target_addr(&target_addr);
    let relay_buffer_size = pool.tcp_relay_buffer_size();

    // 将目标地址转换为协议 Address
    let address = convert_target_addr(&target_addr);

    // 在随机端口上绑定 TCP 套接字以接受传入连接
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(|e| AgentError::Socks5(format!("绑定 TCP 套接字失败: {}", e)))?;

    let bind_addr = listener
        .local_addr()
        .map_err(|e| AgentError::Socks5(format!("获取本地地址失败: {}", e)))?;

    info!("SOCKS5 BIND 监听在 {}", bind_addr);

    // 发送第一个成功回复，包含绑定地址
    let _tcp_stream = protocol
        .reply_success(bind_addr)
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    // 等待绑定地址上的传入连接
    // BIND 不应无限等待远端连接，超时后释放监听端口。
    match tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept()).await {
        Ok(Ok((mut incoming_stream, peer_addr))) => {
            info!(
                "SOCKS5 BIND: 接受来自 {} 的连接，目标 {:?}",
                peer_addr, address
            );

            if direct_checker.is_direct(&address) {
                // === 直连路径 ===
                let target_str = address_to_string(&address);
                info!("SOCKS5 BIND 使用直连连接到 {}", target_str);

                match TcpStream::connect(&target_str).await {
                    Ok(mut target_stream) => {
                        // BIND 直连同样关闭 Nagle，保持与 CONNECT 直连一致的小包时延。
                        if let Err(err) = target_stream.set_nodelay(true) {
                            debug!(
                                "SOCKS5 BIND 直连目标 TCP_NODELAY 设置失败，继续使用默认行为：{err}"
                            );
                        }
                        info!("SOCKS5 BIND 直连隧道已建立，开始数据中继");
                        match relay_tcp_bidirectional(
                            &mut incoming_stream,
                            &mut target_stream,
                            relay_buffer_size,
                            TcpRelayOptions::standard(&target_label),
                        )
                        .await
                        {
                            Ok(stats) => {
                                info!(
                                    "直连 SOCKS5 BIND 中继完成: {} 字节发出, {} 字节接收",
                                    stats.client_to_remote, stats.remote_to_client
                                );
                                telemetry::emit_traffic(
                                    "SOCKS5 BIND (direct)",
                                    target_label,
                                    stats.client_to_remote,
                                    stats.remote_to_client,
                                );
                            }
                            Err(e) => {
                                debug!("直连 SOCKS5 BIND 中继结束: {}", e);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        error!("直连到目标失败: {}", e);
                        Err(AgentError::Connection(format!("直连失败: {}", e)))
                    }
                }
            } else {
                // === 代理路径 ===
                let connected_stream = match pool
                    .as_ref()
                    .get_connected_stream(address, TransportProtocol::Tcp)
                    .await
                {
                    Ok(stream) => {
                        info!("从连接池获取已连接流, stream_id: {}", stream.stream_id());
                        stream
                    }
                    Err(e) => {
                        error!("从连接池获取流失败: {}", e);
                        return Err(e);
                    }
                };

                info!("SOCKS5 BIND 隧道已建立，开始数据中继");

                relay_data(
                    &mut incoming_stream,
                    connected_stream,
                    "SOCKS5 BIND",
                    target_label,
                    relay_buffer_size,
                    &[],
                )
                .await
            }
        }
        Ok(Err(e)) => {
            error!("接受传入连接失败: {}", e);
            Err(AgentError::Socks5(format!("接受连接失败: {}", e)))
        }
        Err(_) => {
            error!("SOCKS5 BIND: 等待传入连接超时");
            Err(AgentError::Socks5("等待传入连接超时".to_string()))
        }
    }
}

async fn relay_data(
    client_stream: &mut TcpStream,
    connected_stream: ConnectedStream,
    protocol: &str,
    target: String,
    relay_buffer_size: usize,
    initial_client_bytes: &[u8],
) -> Result<()> {
    // ConnectedStream 隐藏 legacy/Yamux 差异，上层只看到一个可读写的 proxy 目标流。
    // 但 relay 策略不能完全无差别：legacy Framed 写端是 DataPacketSink/SinkWriter，
    // 如果使用 Tokio copy 路径，写入可能先停在 framed writer 缓冲里，SOCKS5 客户端
    // 会感知为首包慢、交互顿一下或小请求迟迟不出去。Yamux 子流本身是裸字节流，
    // 继续走标准 copy，避免逐写 flush 把吞吐打碎。
    let proxy_is_framed = connected_stream.is_framed();
    let mut proxy_io = connected_stream.into_async_io();
    if !initial_client_bytes.is_empty() {
        // 首包嗅探会消耗客户端已经发出的 TLS ClientHello/HTTP 请求头；连接到最终
        // proxy 目标后必须先补发这段数据，否则目标侧会看到被截断的握手。
        proxy_io.write_all(initial_client_bytes).await?;
        proxy_io.flush().await?;
    }

    match relay_tcp_bidirectional(
        client_stream,
        &mut proxy_io,
        relay_buffer_size,
        if proxy_is_framed {
            TcpRelayOptions::framed_proxy(&target)
        } else {
            TcpRelayOptions::standard(&target)
        },
    )
    .await
    {
        Ok(stats) => {
            info!(
                "SOCKS5 中继完成: {} 字节 客户端->代理, {} 字节 代理->客户端, buffer={} bytes",
                stats.client_to_remote, stats.remote_to_client, relay_buffer_size
            );
            telemetry::emit_traffic(
                protocol,
                target,
                stats.client_to_remote,
                stats.remote_to_client,
            );
        }
        Err(e) => {
            // 客户端关闭连接时出现的连接错误是预期的
            debug!("SOCKS5 中继结束: {}", e);
        }
    }

    Ok(())
}

fn socks_sniff_port(target: &TargetAddr) -> Option<u16> {
    let port = match target {
        TargetAddr::Ip(addr) => addr.port(),
        TargetAddr::Domain(_, _) => return None,
    };

    // 只对常见 HTTP/TLS 端口嗅探，避免 SSH、数据库等 server-first/非 HTTP 协议
    // 因 SOCKS5 成功响应后等待首包而增加不必要延迟。
    matches!(port, 80 | 443 | 8000 | 8080 | 8443 | 853).then_some(port)
}

async fn sniff_first_client_bytes(client: &mut TcpStream, port: u16) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(SOCKS_SNIFF_MAX_BYTES);
    let deadline = tokio::time::Instant::now() + SOCKS_SNIFF_TIMEOUT;
    let mut chunk = [0u8; 1024];

    loop {
        if buffer.len() >= SOCKS_SNIFF_MAX_BYTES {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let read_timeout = if buffer.is_empty() {
            remaining
        } else {
            remaining.min(SOCKS_SNIFF_INTER_READ_TIMEOUT)
        };
        match tokio::time::timeout(read_timeout, client.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buffer.extend_from_slice(&chunk[..n]);
                if sniff_buffer_ready(port, &buffer) {
                    break;
                }
            }
            Ok(Err(e)) => {
                debug!("SOCKS5 首包嗅探读取失败：{e}");
                break;
            }
            Err(_) => break,
        }
    }

    buffer
}

fn sniff_buffer_ready(port: u16, buf: &[u8]) -> bool {
    if sniff_domain(port, buf).is_some() {
        return true;
    }

    has_complete_tls_record(buf) || has_complete_http_headers(buf)
}

fn has_complete_tls_record(buf: &[u8]) -> bool {
    if buf.len() < 5 || buf[0] != 0x16 {
        return false;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    buf.len() >= 5usize.saturating_add(record_len)
}

fn has_complete_http_headers(buf: &[u8]) -> bool {
    std::str::from_utf8(buf)
        .map(|text| text.contains("\r\n\r\n"))
        .unwrap_or(false)
}

fn sniff_domain(port: u16, buf: &[u8]) -> Option<String> {
    match port {
        80 | 8080 | 8000 => extract_http_host(buf).or_else(|| extract_tls_sni(buf)),
        _ => extract_tls_sni(buf).or_else(|| extract_http_host(buf)),
    }
}
