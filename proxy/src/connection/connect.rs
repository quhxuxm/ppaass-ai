use super::*;

impl ServerConnection {
    pub(super) async fn handle_connect(&mut self, connect_request: ConnectRequest) -> Result<()> {
        debug!("连接请求：{:?}", connect_request.address);

        // 检查用户带宽限制
        if let Some(user_config) = &self.user_config
            && !self
                .bandwidth_monitor
                .check_limit(&user_config.username)
                .await
        {
            return self
                .send_connect_error(
                    connect_request.request_id,
                    "Bandwidth limit exceeded".to_string(),
                )
                .await;
        }

        if matches!(connect_request.address, Address::TcpYamux) {
            if self.proxy_config.transport.tcp_mode == TcpTransportMode::Legacy {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "TCP Yamux is disabled by proxy config".to_string(),
                    )
                    .await;
            }
            if connect_request.transport != TransportProtocol::Tcp {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "TCP Yamux only supports TCP transport".to_string(),
                    )
                    .await;
            }
            self.send_connect_success(connect_request.request_id.clone(), "TCP Yamux connected")
                .await?;
            // Yamux 外层 session 是一条长期复用的控制/数据通道；不要套 pre-connect idle。
            // 死连接由 Yamux keepalive 发现；TCP 子流空闲策略由 yamux_tcp_relay_idle_timeout_secs 控制。
            return self
                .handle_tcp_yamux_connect(connect_request.request_id)
                .await;
        }

        if matches!(connect_request.address, Address::UdpYamux) {
            if self.proxy_config.transport.udp_mode == TcpTransportMode::Legacy {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "UDP Yamux is disabled by proxy config".to_string(),
                    )
                    .await;
            }
            if connect_request.transport != TransportProtocol::Udp {
                return self
                    .send_connect_error(
                        connect_request.request_id,
                        "UDP Yamux only supports UDP transport".to_string(),
                    )
                    .await;
            }
            self.send_connect_success(connect_request.request_id.clone(), "UDP Yamux connected")
                .await?;
            return self
                .handle_udp_yamux_connect(connect_request.request_id)
                .await;
        }

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

                let mut stream = upstream_conn.into_stream();
                // 上游连接也是一个 AsyncRead/AsyncWrite，复用普通 TCP 中继逻辑。
                self.relay(connect_request.request_id, &mut stream).await?;
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
