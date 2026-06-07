//! 从连接池取得“已经连接目标”的流。
//!
//! 对上层 HTTP/SOCKS/TUN 来说，调用这里后拿到的就是可读写的目标流；
//! 这里内部会决定用 Yamux 子流、legacy 预热连接，还是按需新建连接。

use super::*;

impl ConnectionPool {
    /// 从池中获取连接并连接到目标。
    /// 连接被消费（不归还池）。
    #[instrument(skip(self))]
    pub async fn get_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<ConnectedStream> {
        if self.use_yamux && self.yamux_transport == Some(transport) {
            // Yamux 是优先路径：不用为每个目标重新 TCP connect + Auth。
            // auto 模式允许在 Yamux 外层不可用时回退 legacy，yamux 模式则直接报错。
            match self
                .get_yamux_connected_stream(address.clone(), transport)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(err)
                    if self.yamux_mode == Some(TcpTransportMode::Auto)
                        && should_fallback_yamux_error(&err) =>
                {
                    warn!("{} Yamux 不可用，回退到 legacy：{}", self.pool_name, err);
                }
                Err(err) => return Err(err),
            }
        }

        loop {
            // legacy 路径：先尝试消费一条预热连接；池空时同步新建，保证请求可继续。
            let (conn, from_pool) = match self.pool.try_remove() {
                Ok(conn) => {
                    // 取出的连接会被本次请求消费，不再归还池中。
                    self.available.fetch_sub(1, Ordering::AcqRel);
                    self.refill_notify.notify_one();
                    // 丢弃过期连接，避免拿到 proxy 已经按 idle timeout 关闭的连接。
                    if conn.is_expired(self.max_connection_age) {
                        debug!("丢弃过期的池连接，尝试下一条或创建新连接");
                        continue;
                    }
                    debug!("使用池中的预热连接");
                    (conn, true)
                }
                Err(_) => {
                    // 池为空时走按需创建，保证请求不依赖预热成功。
                    self.refill_notify.notify_one();
                    debug!("无可用预热连接，创建新连接");
                    (
                        ProxyConnection::new(
                            &self.config,
                            self.get_proxy_bind_ip(),
                            self.get_proxy_bind_interface(),
                        )
                        .await?,
                        false,
                    )
                }
            };

            let connect_result = conn.connect_target(address.clone(), transport).await;
            match connect_result {
                Ok(stream) => return Ok(stream),
                Err(err) if from_pool && should_retry_pooled_connect_error(&err) => {
                    warn!("预热代理连接不可用，已丢弃并重试：{}", err);
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
    }
}
