//! UDP relay flow 之间共享的小型数据结构和公共调度逻辑。
//!
//! 这里的队列项会持有 `UdpRelayBufferedBytesPermit`，表示对应 payload 已经计入
//! 全局缓冲预算。队列项被发送、丢弃或任务退出时 permit Drop，预算随之释放。
//!
//! legacy `Address::UdpRelay` 和 Yamux UDP relay 的外层通道不同：前者通过
//! `ProxyRequest/ProxyResponse::Data` 读写，后者通过 Yamux 子流上的
//! `DatagramStreamIo` 读写。但两者在 proxy 侧维护 UDP flow 的方式完全一致：
//! 根据 agent 传来的 `flow_id` 找到或创建一个已 connect 到目标地址的 UDP socket，
//! 再把上行 payload 投递给该 flow 任务，并把目标响应送回主 relay 循环。
//! 因此公共逻辑放在本文件，外层 relay 只保留“怎么读 agent、怎么写 agent”的差异。

use super::target::relay_target_addr;
use super::*;
use std::collections::HashMap;

// 主 relay 循环收到一个下行响应后，会顺手把队列里已经就绪的响应一起写出。
// 这个上限避免高回包流量下每个 UDP 包都触发一次 flush，同时也避免单次 drain
// 过久导致上行读取和 flow_done 清理被饿住。32 是保守值：足够减少系统调用/唤醒，
// 又不会让一个热 flow 长时间占住 relay 主循环。
pub(super) const UDP_RELAY_RESPONSE_BATCH_LIMIT: usize = 32;

pub(super) struct UdpRelayFlow {
    // 主 relay 循环通过这个 sender 把同一 flow_id 的上行 UDP payload 送给 flow 任务。
    // 每个 flow 背后对应一个已 connect 的 `tokio::net::UdpSocket`；这样后续发送时
    // 不需要重复解析目标地址，也能让 socket.recv 只接收该目标返回的数据。
    pub(super) tx: tokio::sync::mpsc::Sender<QueuedUdpRelayData>,
}

pub(super) struct QueuedUdpRelayData {
    pub(super) data: Vec<u8>,
    // 持有期间表示这段上行 payload 仍在内部队列中占用内存预算。
    pub(super) _buffer_permit: UdpRelayBufferedBytesPermit,
}

pub(super) struct QueuedUdpRelayResponse {
    pub(super) packet: UdpRelayPacket,
    // 持有期间表示这段下行 payload 仍在内部队列中占用内存预算。
    // 注意：主 relay 把 response 编码并写入外层 writer 后，仍会继续持有 permit
    // 直到 flush 完成。否则在 writer 背后堆积的数据还没真正交给网络层时，预算
    // 就已经释放，会低估下行积压，背压也会被削弱。
    pub(super) _buffer_permit: UdpRelayBufferedBytesPermit,
}

#[derive(Clone)]
pub(super) struct UdpRelayFlowChannels {
    pub(super) response_tx: tokio::sync::mpsc::Sender<QueuedUdpRelayResponse>,
    pub(super) flow_done_tx: tokio::sync::mpsc::Sender<u64>,
}

#[derive(Clone, Copy)]
pub(super) struct UdpRelayFlowOptions {
    pub(super) idle_timeout: Duration,
    pub(super) channel_size: usize,
}

#[derive(Clone)]
pub(super) struct UdpRelayFlowContext {
    // proxy 出站状态封装了直连、绑定接口、路由守护等策略；flow 创建时统一从这里
    // connect UDP 目标，确保 legacy 和 Yamux relay 走同一套出站规则。
    egress_state: Arc<EgressState>,
    // flow 任务只和主 relay 循环通信：目标响应从 response_tx 回主循环，
    // flow 退出通知从 flow_done_tx 回主循环，用于清理 flow 表。
    channels: UdpRelayFlowChannels,
    // 全局连接限制器同时控制活跃 UDP flow 数和 queued payload 字节数。
    connection_limiter: ConnectionLimiter,
    max_buffered_bytes: usize,
    // 日志标签区分 legacy UDP relay 与 Yamux UDP relay，公共逻辑不用知道外层通道类型。
    relay_label: &'static str,
    // `spawn_guarded` 使用的任务名；保持两个路径在日志/监控里可区分。
    flow_task_name: &'static str,
}

pub(super) struct UdpRelayFlowSet {
    // flow_id -> flow 发送队列。flow_id 由 agent 端根据 client/target 会话分配；
    // proxy 只保证同一个 flow_id 复用同一个 UDP socket。
    flows: HashMap<u64, UdpRelayFlow>,
    // 单条共享 relay 连接允许的 flow 数上限，防止一个连接持有过多 UDP socket。
    max_flows: usize,
    // 全局 flow 上限仅用于日志输出；真实许可由 connection_limiter 的 permit 控制。
    max_global_flows: usize,
    options: UdpRelayFlowOptions,
    context: UdpRelayFlowContext,
}

impl UdpRelayFlowSet {
    pub(super) fn new(
        proxy_config: &ProxyConfig,
        egress_state: Arc<EgressState>,
        connection_limiter: ConnectionLimiter,
        channels: UdpRelayFlowChannels,
        relay_label: &'static str,
        flow_task_name: &'static str,
    ) -> Self {
        // 所有 relay 路径都从 ProxyConfig 读取同一组 UDP relay 参数，避免 legacy 与
        // Yamux 因默认值或边界处理不同而出现行为分叉。
        let channel_size = udp_relay_channel_size(proxy_config);
        Self {
            flows: HashMap::new(),
            max_flows: proxy_config.max_udp_relay_flows_per_connection,
            max_global_flows: proxy_config.max_udp_relay_flows,
            options: UdpRelayFlowOptions {
                idle_timeout: Duration::from_secs(proxy_config.udp_relay_idle_timeout_secs),
                channel_size,
            },
            context: UdpRelayFlowContext {
                egress_state,
                channels,
                connection_limiter,
                max_buffered_bytes: proxy_config.max_udp_relay_buffered_bytes,
                relay_label,
                flow_task_name,
            },
        }
    }

    pub(super) fn idle_timeout(&self) -> Duration {
        self.options.idle_timeout
    }

    pub(super) fn remove(&mut self, flow_id: u64) {
        // flow 任务在 idle、socket 错误、队列关闭等情况下都会发送 done 通知。
        // 这里删除表项后，后续同一 flow_id 如果再次出现，会重新创建 UDP socket。
        if self.flows.remove(&flow_id).is_some() {
            debug!(
                "{} flow {flow_id} 已清理，active_flows={}",
                self.context.relay_label,
                self.flows.len()
            );
        }
    }

    pub(super) async fn dispatch(&mut self, relay_packet: UdpRelayPacket) {
        let flow_id = relay_packet.flow_id;

        // 首包到达时才创建 UDP socket。这样没有实际数据的 flow 不占资源；
        // 同时上限检查和全局 flow permit 只在真正需要 socket 时发生。
        if !self.flows.contains_key(&flow_id)
            && !self
                .create_flow(flow_id, relay_packet.address.clone())
                .await
        {
            return;
        }

        let Some(flow) = self.flows.get(&flow_id) else {
            return;
        };
        // 上行 payload 在进入 per-flow 队列前就申请字节预算。队列满、flow 关闭或
        // 任务发送完成都会 Drop permit，预算才随之释放；这能真实反映内部积压。
        let Some(buffer_permit) = try_acquire_udp_relay_buffer(
            &self.context.connection_limiter,
            self.context.max_buffered_bytes,
            flow_id,
            relay_packet.data.len(),
            "上行",
        ) else {
            return;
        };
        let queued = QueuedUdpRelayData {
            data: relay_packet.data,
            _buffer_permit: buffer_permit,
        };
        match flow.tx.try_send(queued) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // UDP 本身没有可靠重传语义；内部队列满时选择丢包而不是 await。
                // 如果这里等待，会让共享 relay 主循环被单个慢 flow 拖住，影响其他 flow。
                debug!(
                    "{} flow {flow_id} 发送队列已满，丢弃一个 UDP 数据包",
                    self.context.relay_label
                );
            }
            Err(TrySendError::Closed(_)) => {
                // flow 任务已经退出但 done 通知可能还没被主循环处理，直接清理表项。
                self.flows.remove(&flow_id);
            }
        }
    }

    async fn create_flow(&mut self, flow_id: u64, address: Address) -> bool {
        // per-connection 上限保护单条共享 relay 连接，避免一个 agent 连接无限扩张到
        // 成千上万个 UDP socket；0 表示不限制，保持配置语义与旧实现一致。
        if self.max_flows != 0 && self.flows.len() >= self.max_flows {
            warn!(
                "{} flow 数已达上限（{}），丢弃 flow {} 的数据包",
                self.context.relay_label, self.max_flows, flow_id
            );
            return false;
        }

        let Some(flow_permit) = self.context.connection_limiter.try_acquire_udp_relay_flow() else {
            warn!(
                "proxy 全局 UDP relay flow 数已达上限（当前={}，上限={}），丢弃 flow {} 的数据包",
                self.context.connection_limiter.active_udp_relay_flows(),
                self.max_global_flows,
                flow_id
            );
            return false;
        };

        // 创建 flow 需要先拿全局 permit。permit 会移动进 flow 任务，并在任务退出时 Drop。
        // 如果创建 socket 失败，permit 会在本函数返回前 Drop，不会泄漏全局计数。
        match spawn_udp_relay_flow(
            flow_id,
            address,
            flow_permit,
            self.options,
            self.context.clone(),
        )
        .await
        {
            Ok(flow) => {
                self.flows.insert(flow_id, flow);
                debug!(
                    "{} flow {flow_id} 已创建，active_flows={}",
                    self.context.relay_label,
                    self.flows.len()
                );
                true
            }
            Err(e) => {
                debug!(
                    "{} flow {} 连接目标失败：{}",
                    self.context.relay_label, flow_id, e
                );
                false
            }
        }
    }
}

pub(super) fn udp_relay_channel_size(config: &ProxyConfig) -> usize {
    config.udp_relay_channel_size.max(1)
}

pub(super) fn try_acquire_udp_relay_buffer(
    limiter: &ConnectionLimiter,
    max_buffered_bytes: usize,
    flow_id: u64,
    bytes: usize,
    direction: &str,
) -> Option<UdpRelayBufferedBytesPermit> {
    match limiter.try_acquire_udp_relay_buffered_bytes(bytes) {
        Some(permit) => Some(permit),
        None => {
            warn!(
                "proxy UDP relay 缓冲字节数已达上限（当前={}，上限={}），丢弃 flow {} 的{}数据包（{} bytes）",
                limiter.active_udp_relay_buffered_bytes(),
                max_buffered_bytes,
                flow_id,
                direction,
                bytes
            );
            None
        }
    }
}

async fn spawn_udp_relay_flow(
    flow_id: u64,
    address: Address,
    flow_permit: UdpRelayFlowPermit,
    options: UdpRelayFlowOptions,
    context: UdpRelayFlowContext,
) -> Result<UdpRelayFlow> {
    let target_addr = relay_target_addr(&address)?;
    // flow 创建时就把 UDP socket connect 到具体目标，后续只需 send/recv payload。
    // 这里不能延迟到 flow 任务里再 connect：主 relay 需要知道创建是否成功，失败时
    // 直接丢弃首包并保持外层 relay 连接继续服务其他 flow。
    let socket = context
        .egress_state
        .connect_udp(&target_addr)
        .await
        .map_err(|e| ProxyError::Connection(format!("Failed to connect UDP relay target: {e}")))?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<QueuedUdpRelayData>(options.channel_size);
    let response_address = address.clone();
    let response_tx = context.channels.response_tx;
    let flow_done_tx = context.channels.flow_done_tx;
    let connection_limiter = context.connection_limiter;
    let max_buffered_bytes = context.max_buffered_bytes;
    let relay_label = context.relay_label;
    let flow_idle_timeout = options.idle_timeout;

    spawn_guarded(context.flow_task_name, async move {
        // flow_permit 的生命周期绑定到任务；任务退出即释放全局 UDP flow 计数。
        let _flow_permit = flow_permit;
        // UDP 单包理论最大 payload 不超过 65535，这里复用同一个 buffer 接收目标响应，
        // 只有真正排入下行队列时才复制出 Vec，避免每次 recv 前重新分配。
        let mut buf = vec![0u8; 65535];
        let idle = tokio::time::sleep(flow_idle_timeout);
        tokio::pin!(idle);

        loop {
            tokio::select! {
                // flow 长时间无上行也无下行时主动退出，释放 UDP socket 和 flow permit。
                _ = &mut idle => break,
                maybe_data = rx.recv() => {
                    let Some(queued) = maybe_data else { break };
                    let data = queued.data;
                    // 对 UDP send 也套 idle_timeout，避免异常网络栈或绑定接口问题让 flow
                    // 任务永久卡在一次发送上。
                    match tokio::time::timeout(flow_idle_timeout, socket.send(&data)).await {
                        Ok(Ok(_)) => {
                            idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                        }
                        Ok(Err(e)) => {
                            debug!("{relay_label} flow {flow_id} 发送失败：{e}");
                            break;
                        }
                        Err(_) => {
                            debug!(
                                "{relay_label} flow {flow_id} 发送超过 {} 秒，关闭该 flow",
                                flow_idle_timeout.as_secs()
                            );
                            break;
                        }
                    }
                }
                read = socket.recv(&mut buf) => {
                    match read {
                        Ok(n) => {
                            // 下行响应也计入全局缓冲预算，防止目标大量回包压垮内存。
                            // 如果预算不足，关闭该 flow 比继续读包更稳：关闭 socket 后
                            // 目标回包自然停止进入本进程，flow 表也会被主循环清理。
                            let Some(buffer_permit) = try_acquire_udp_relay_buffer(
                                &connection_limiter,
                                max_buffered_bytes,
                                flow_id,
                                n,
                                "下行",
                            ) else {
                                debug!("{relay_label} flow {flow_id} 响应缓冲预算不足，关闭该 flow 以释放 socket");
                                break;
                            };
                            let response = QueuedUdpRelayResponse {
                                packet: UdpRelayPacket {
                                    flow_id,
                                    address: response_address.clone(),
                                    data: buf[..n].to_vec(),
                                },
                                _buffer_permit: buffer_permit,
                            };
                            match response_tx.try_send(response) {
                                Ok(()) => {
                                    idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                                }
                                Err(TrySendError::Full(_)) => {
                                    // 下行汇总队列满说明外层 agent 连接写不出去或主循环跟不上。
                                    // 继续保留 socket 会让目标回包持续堆积，所以关闭该 flow。
                                    debug!("{relay_label} flow {flow_id} 响应队列已满，关闭该 flow 以释放 socket");
                                    break;
                                }
                                Err(TrySendError::Closed(_)) => break,
                            }
                        }
                        Err(e) => {
                            debug!("{relay_label} flow {flow_id} 接收失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
        drop(socket);
        let _ = flow_done_tx.send(flow_id).await;
        debug!("{relay_label} flow {flow_id} 已结束");
    });

    Ok(UdpRelayFlow { tx })
}
