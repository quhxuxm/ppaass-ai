//! SOCKS5 TCP 命令处理。
//!
//! CONNECT 是常规浏览器/应用代理路径；BIND 较少用，但同样会在直连或代理路径中
//! 最终转换成一个 `AsyncRead + AsyncWrite` 双向中继。

use super::*;
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};

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
        // 代理入口采用“本地握手先成功，proxy 建连随后完成”的策略，和 TUN 行为保持一致。
        // 浏览器播放 HLS/视频时会创建大量短连接；如果 SOCKS5 必须等 proxy 端目标连接
        // 完成后才回复 success，每个分片都会额外暴露一次远端建连延迟，分片最终大小正常
        // 但播放器会感到卡顿。若后续 proxy 建连失败，直接关闭本地隧道，让浏览器重试。
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut client_stream = protocol
            .reply_success(bind_addr)
            .await
            .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

        // SOCKS5 的 DOMAIN 目标必须原样交给 proxy 端解析。
        // 如果 agent 在本地先解析，再把 IP 发给 proxy，会破坏“从 proxy 出口访问”的
        // DNS/CDN 语义，也会让远端分流规则失去域名上下文。这里刻意只透传
        // Address::Domain，不做任何 agent 侧 DNS fallback。
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
                error!("SOCKS5 已回复成功后获取 proxy 流失败: {}", e);
                return Err(e);
            }
        };

        info!("SOCKS5 隧道已建立，开始数据中继");

        // 启动双向数据中继
        relay_data(
            &mut client_stream,
            connected_stream,
            "SOCKS5 CONNECT",
            target_label,
            relay_buffer_size,
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
                // BIND 代理路径与 CONNECT 保持一致：域名只透传，不在 agent 本地解析。
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
) -> Result<()> {
    // ConnectedStream 隐藏 legacy/Yamux 差异，上层只看到一个可读写的 proxy 目标流。
    // 但 relay 策略不能完全无差别：legacy Framed 写端是 DataPacketSink/SinkWriter，
    // 如果使用 Tokio copy 路径，写入可能先停在 framed writer 缓冲里，SOCKS5 客户端
    // 会感知为首包慢、交互顿一下或小请求迟迟不出去。Yamux 子流本身是裸字节流，
    // 继续走标准 copy，避免逐写 flush 把吞吐打碎。
    let proxy_is_framed = connected_stream.is_framed();
    let mut proxy_io = connected_stream.into_async_io();

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
