//! Proxy 访问记录的异步写入层。
//!
//! 代理连接的热路径只向有界队列执行一次 `try_send`，SQLite 等持久化工作由
//! 后台任务串行完成。未配置共享用户数据库时 recorder 是 no-op，从而完整保留
//! `users.toml` 模式。

use protocol::{Address, TransportProtocol};
use proxy_user_store::{
    AccessLogRepository, AccessProtocol, MAX_ACCESS_LOG_RETENTION_DAYS,
    MIN_ACCESS_LOG_RETENTION_DAYS, NewAccessRecord,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

const ACCESS_LOG_CHANNEL_SIZE: usize = 4096;
const ACCESS_LOG_PURGE_INTERVAL_SECS: u64 = 60 * 60;
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

#[derive(Debug)]
struct PendingAccessRecord {
    username: String,
    protocol: AccessProtocol,
    target_host: String,
    target_port: u16,
    accessed_at: i64,
}

/// 可廉价 clone 并注入每条连接/UDP flow 的非阻塞访问记录器。
#[derive(Clone, Default)]
pub(crate) struct AccessRecorder {
    sender: Option<mpsc::Sender<PendingAccessRecord>>,
}

impl AccessRecorder {
    pub(crate) fn start(repository: Arc<dyn AccessLogRepository>) -> Self {
        let (sender, receiver) = mpsc::channel(ACCESS_LOG_CHANNEL_SIZE);
        tokio::spawn(run_writer(repository, receiver));
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
        let pending = PendingAccessRecord {
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

async fn run_writer(
    repository: Arc<dyn AccessLogRepository>,
    mut receiver: mpsc::Receiver<PendingAccessRecord>,
) {
    purge_expired_records(repository.as_ref()).await;
    let mut purge_interval = tokio::time::interval(std::time::Duration::from_secs(
        ACCESS_LOG_PURGE_INTERVAL_SECS,
    ));
    // 第一次 tick 会立即完成；启动时已经主动清理过，消费掉它即可。
    purge_interval.tick().await;

    loop {
        tokio::select! {
            maybe_record = receiver.recv() => {
                let Some(record) = maybe_record else {
                    break;
                };
                let result = repository
                    .record_access(NewAccessRecord {
                        username: record.username,
                        protocol: record.protocol,
                        target_host: record.target_host,
                        target_port: record.target_port,
                        accessed_at: record.accessed_at,
                    })
                    .await;
                if let Err(error) = result {
                    warn!("写入用户访问记录失败：{error}");
                }
            }
            _ = purge_interval.tick() => {
                purge_expired_records(repository.as_ref()).await;
            }
        }
    }
}

async fn purge_expired_records(repository: &dyn AccessLogRepository) {
    let settings = match repository.get_access_log_settings().await {
        Ok(settings) => settings,
        Err(error) => {
            warn!("读取访问记录保留策略失败，跳过本轮清理：{error}");
            return;
        }
    };
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS)
        .contains(&settings.retention_days)
    {
        warn!(
            retention_days = settings.retention_days,
            "访问记录保留天数超出支持范围，跳过本轮清理"
        );
        return;
    }
    let before = OffsetDateTime::now_utc().unix_timestamp()
        - i64::from(settings.retention_days) * SECONDS_PER_DAY;
    match repository.purge_access_records_before(before).await {
        Ok(0) => {}
        Ok(deleted) => debug!(
            deleted,
            retention_days = settings.retention_days,
            "已清理过期访问记录"
        ),
        Err(error) => warn!("清理过期访问记录失败：{error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::access_target;
    use protocol::Address;

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
}
