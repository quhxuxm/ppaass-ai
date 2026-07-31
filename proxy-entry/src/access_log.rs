//! Proxy 访问记录的异步批量上报层。
//!
//! 代理连接的热路径只向有界队列执行一次 `try_send`，Registry HTTP 上报由
//! 后台任务串行完成。批次失败时使用同一 ID 有界重试，由 Registry 保证幂等。

use crate::control_plane::AccessEventSink;
use protocol::{Address, TransportProtocol};
use proxy_control_protocol::{AccessEvent, AccessProtocol, MAX_ACCESS_EVENTS_PER_BATCH};
use rand::RngExt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

const ACCESS_LOG_CHANNEL_SIZE: usize = 4096;
const ACCESS_LOG_BATCH_FLUSH_MILLIS: u64 = 1_000;
const ACCESS_LOG_BATCH_MAX_ATTEMPTS: u32 = 5;
const ACCESS_LOG_RETRY_MAX_SECONDS: u64 = 5;

/// 可廉价 clone 并注入每条连接/UDP flow 的非阻塞访问记录器。
#[derive(Clone, Default)]
pub(crate) struct AccessRecorder {
    sender: Option<mpsc::Sender<AccessEvent>>,
}

impl AccessRecorder {
    pub(crate) fn start(sink: Arc<dyn AccessEventSink>) -> Self {
        let (sender, receiver) = mpsc::channel(ACCESS_LOG_CHANNEL_SIZE);
        tokio::spawn(run_writer(sink, receiver));
        Self {
            sender: Some(sender),
        }
    }

    /// 仅记录 proxy 已经成功建立的真实目标。虚拟的 ProxyDns/UdpRelay 地址由其
    /// 真正目标 flow 负责，避免产生误导性或重复记录。
    pub(crate) fn record(&self, username: &str, transport: TransportProtocol, address: &Address) {
        let Some(sender) = self.sender.as_ref() else {
            return;
        };
        let Some((target_host, target_port)) = access_target(address) else {
            return;
        };
        let pending = AccessEvent {
            username: username.to_owned(),
            protocol: match transport {
                TransportProtocol::Tcp => AccessProtocol::Tcp,
                TransportProtocol::Udp => AccessProtocol::Udp,
            },
            target_host,
            target_port,
            accessed_at: OffsetDateTime::now_utc().unix_timestamp(),
        };
        match sender.try_send(pending) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(record)) => {
                warn!(
                    username = %record.username,
                    target_host = %record.target_host,
                    target_port = record.target_port,
                    "访问记录队列已满，丢弃一条记录"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("访问记录后台任务已经退出，无法继续记录");
            }
        }
    }
}

fn access_target(address: &Address) -> Option<(String, u16)> {
    match address {
        Address::Domain { host, port } => Some((host.clone(), *port)),
        Address::Ipv4 { addr, port } => Some((Ipv4Addr::from(*addr).to_string(), *port)),
        Address::Ipv6 { addr, port } => Some((Ipv6Addr::from(*addr).to_string(), *port)),
        Address::ProxyDns { .. } | Address::UdpRelay => None,
    }
}

async fn run_writer(sink: Arc<dyn AccessEventSink>, mut receiver: mpsc::Receiver<AccessEvent>) {
    while let Some(first) = receiver.recv().await {
        let mut records = Vec::with_capacity(MAX_ACCESS_EVENTS_PER_BATCH);
        records.push(first);
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(ACCESS_LOG_BATCH_FLUSH_MILLIS);
        let mut receiver_closed = false;
        while records.len() < MAX_ACCESS_EVENTS_PER_BATCH {
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(record)) => records.push(record),
                Ok(None) => {
                    receiver_closed = true;
                    break;
                }
                Err(_) => break,
            }
        }

        let batch_id = new_batch_id();
        let mut retry_delay = std::time::Duration::from_secs(1);
        let mut delivered = false;
        for attempt in 1..=ACCESS_LOG_BATCH_MAX_ATTEMPTS {
            match sink.submit_access_batch(&batch_id, &records).await {
                Ok(()) => {
                    delivered = true;
                    debug!(batch_id, record_count = records.len(), "访问记录批次已上报");
                    break;
                }
                Err(error) if attempt < ACCESS_LOG_BATCH_MAX_ATTEMPTS => {
                    warn!(
                        %error,
                        batch_id,
                        record_count = records.len(),
                        attempt,
                        "访问记录批次上报失败，将使用同一批次 ID 重试"
                    );
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2)
                        .min(std::time::Duration::from_secs(ACCESS_LOG_RETRY_MAX_SECONDS));
                }
                Err(error) => {
                    warn!(
                        %error,
                        batch_id,
                        record_count = records.len(),
                        "访问记录批次达到重试上限，按尽力记录语义丢弃"
                    );
                }
            }
        }
        if !delivered {
            error!(
                batch_id,
                record_count = records.len(),
                "访问记录批次未能持久化"
            );
        }
        if receiver_closed {
            break;
        }
    }
}

fn new_batch_id() -> String {
    let mut random = [0_u8; 16];
    rand::rng().fill(&mut random);
    hex::encode(random)
}

#[cfg(test)]
mod tests {
    use super::{access_target, run_writer};
    use crate::{
        control_plane::AccessEventSink,
        error::{ProxyError, Result},
    };
    use protocol::Address;
    use proxy_control_protocol::{AccessEvent, AccessProtocol};
    use std::sync::Arc;
    use tokio::sync::{Mutex, Notify, mpsc};

    #[derive(Default)]
    struct RetrySink {
        batch_ids: Mutex<Vec<String>>,
        delivered: Notify,
    }

    #[async_trait::async_trait]
    impl AccessEventSink for RetrySink {
        async fn submit_access_batch(&self, batch_id: &str, _events: &[AccessEvent]) -> Result<()> {
            let mut ids = self.batch_ids.lock().await;
            ids.push(batch_id.to_string());
            if ids.len() == 1 {
                return Err(ProxyError::ControlPlane("模拟响应丢失".to_string()));
            }
            self.delivered.notify_one();
            Ok(())
        }
    }

    #[test]
    fn maps_real_targets_without_virtual_addresses() {
        assert_eq!(
            access_target(&Address::Domain {
                host: "example.com".to_string(),
                port: 443,
            }),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            access_target(&Address::Ipv4 {
                addr: [192, 0, 2, 1],
                port: 53,
            }),
            Some(("192.0.2.1".to_string(), 53))
        );
        assert_eq!(access_target(&Address::ProxyDns { port: 53 }), None);
        assert_eq!(access_target(&Address::UdpRelay), None);
    }

    #[tokio::test]
    async fn retries_a_batch_with_the_same_id() {
        let sink = Arc::new(RetrySink::default());
        let (sender, receiver) = mpsc::channel(2);
        tokio::spawn(run_writer(sink.clone(), receiver));
        sender
            .send(AccessEvent {
                username: "alice".to_string(),
                protocol: AccessProtocol::Tcp,
                target_host: "example.com".to_string(),
                target_port: 443,
                accessed_at: 1,
            })
            .await
            .unwrap();
        drop(sender);
        tokio::time::timeout(std::time::Duration::from_secs(3), sink.delivered.notified())
            .await
            .unwrap();

        let batch_ids = sink.batch_ids.lock().await;
        assert_eq!(batch_ids.len(), 2);
        assert_eq!(batch_ids[0], batch_ids[1]);
    }
}
