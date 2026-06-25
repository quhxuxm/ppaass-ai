//! CONNECT 分流层。
//!
//! 认证后的第一条 `ConnectRequest` 会到这里。它不直接搬数据，而是先根据
//! `Address` 和 `TransportProtocol` 决定后续生命周期：直连 TCP/UDP、
//! 共享 UDP relay，或 forward 到上游 proxy。

use super::*;

impl ServerConnection {
    pub(super) async fn handle_connect(&mut self, connect_request: ConnectRequest) -> Result<()> {
        debug!("连接请求：{:?}", connect_request.address);

        // UdpRelay 是协议内的“虚拟地址”，不代表真实目标服务器，而是告诉 proxy
        // 在当前加密 PPAASS 子 stream 内建立共享 UDP relay。
        if matches!(connect_request.address, Address::UdpRelay) {
            if connect_request.transport != TransportProtocol::Udp {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "UDP relay only supports UDP transport".to_string(),
                    )
                    .await;
            }
            if self.proxy_config.forward_mode {
                return self.handle_upstream_connect(connect_request).await;
            }
            return self.handle_udp_relay_connect(connect_request).await;
        }

        // 检查是否启用了转发模式
        if self.proxy_config.forward_mode {
            return self.handle_upstream_connect(connect_request).await;
        }

        // 普通 Domain/IPv4/IPv6 目标到这里才会被转换成 Tokio 可连接的 host:port。
        let target_addr = self.target_addr_for_request(&connect_request.address)?;
        match connect_request.transport {
            TransportProtocol::Tcp => self.handle_tcp_connect(connect_request, &target_addr).await,
            TransportProtocol::Udp => self.handle_udp_connect(connect_request, &target_addr).await,
        }
    }

    fn target_addr_for_request(&self, address: &Address) -> Result<String> {
        // ProxyDns 是特殊地址类型，需要在 proxy 端决定真正的 DNS 上游。
        target_addr_for_address(&self.proxy_config, address)
    }

    async fn handle_upstream_connect(&mut self, connect_request: ConnectRequest) -> Result<()> {
        debug!("正在将请求转发到上游代理");

        // 转发模式下 proxy 作为客户端连接下一跳 proxy，再把 agent 流量接过去。
        // 对 agent 来说下游 proxy 仍像目标连接；对本 proxy 来说上游 proxy 是 AsyncRead/AsyncWrite。
        match UpstreamConnection::connect(
            &self.proxy_config,
            connect_request.address.clone(),
            connect_request.transport,
        )
        .await
        {
            Ok(upstream_conn) => {
                debug!("已连接到上游代理");
                // 只有上游连接成功后才回复 agent 连接成功。
                self.send_connect_success(
                    connect_request.request_id.clone(),
                    "Connected through upstream",
                )
                .await?;

                let (yamux_connection, mut stream) = upstream_conn.into_parts();
                // 上游连接也是一个 AsyncRead/AsyncWrite，复用普通 TCP 中继逻辑。
                let relay_result = self.relay(connect_request.request_id, &mut stream).await;
                yamux_connection.close().await;
                relay_result?;
            }
            Err(e) => {
                error!("连接上游代理失败：{}", e);
                self.send_connect_error(
                    connect_request.request_id,
                    format!("Upstream error: {}", e),
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn handle_tcp_connect(
        &mut self,
        connect_request: ConnectRequest,
        target_addr: &str,
    ) -> Result<()> {
        // 通过启动时共享的出站状态连接目标，避免每次请求重新读取路由表。
        // 超时只包 connect 阶段；连接建立后的空闲控制交给 relay 层。
        let connect_timeout = Duration::from_secs(self.proxy_config.connect_timeout_secs);
        match tokio::time::timeout(connect_timeout, self.egress_state.connect_tcp(target_addr))
            .await
        {
            Ok(Ok(mut target_stream)) => {
                debug!(
                    "已连接到目标（TCP）：{}，出站设备={}",
                    target_addr,
                    self.proxy_config
                        .outbound_interface
                        .as_deref()
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or("默认路由")
                );
                self.send_connect_success(connect_request.request_id.clone(), "Connected")
                    .await?;
                self.relay(connect_request.request_id, &mut target_stream)
                    .await?;
            }
            Ok(Err(e)) => {
                warn!("连接目标失败（TCP）：{}，目标={}", e, target_addr);
                self.send_connect_error(
                    connect_request.request_id,
                    format!("Failed to connect: {}", e),
                )
                .await?;
            }
            Err(_) => {
                warn!(
                    "连接目标超时（TCP）：目标={}，超时={} 秒",
                    target_addr, self.proxy_config.connect_timeout_secs
                );
                self.send_connect_error(
                    connect_request.request_id,
                    format!(
                        "Connect timeout after {} seconds",
                        self.proxy_config.connect_timeout_secs
                    ),
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn handle_udp_connect(
        &mut self,
        connect_request: ConnectRequest,
        target_addr: &str,
    ) -> Result<()> {
        debug!("正在处理 UDP 连接请求：{connect_request:?}");

        // UDP 也复用同一份出站状态，保持 TCP/UDP 的出口选择一致。
        // tokio 的 UDP connect 只是固定默认对端，后续 send/recv 不需要每包携带地址。
        match self.egress_state.connect_udp(target_addr).await {
            Ok(socket) => {
                debug!(
                    "已连接到目标（UDP）：{}，出站设备={}",
                    target_addr,
                    self.proxy_config
                        .outbound_interface
                        .as_deref()
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or("默认路由")
                );
                self.send_connect_success(connect_request.request_id.clone(), "Connected")
                    .await?;
                self.relay_udp(connect_request.request_id, socket).await?;
            }
            Err(e) => {
                warn!("连接目标失败（UDP）：{}，目标={}", e, target_addr);
                self.send_connect_error(
                    connect_request.request_id,
                    format!("Failed to connect UDP: {}", e),
                )
                .await?;
            }
        }

        Ok(())
    }
}
