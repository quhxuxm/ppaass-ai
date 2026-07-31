use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::store::{AgentEventRecord, AgentEventRepository, UserRepositoryError};
use tokio::sync::broadcast;
use tracing::{debug, error, warn};

const EVENT_BUFFER_CAPACITY: usize = 256;
const EVENT_DATABASE_BATCH_SIZE: u32 = 256;
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(200);
const EVENT_ERROR_BACKOFF_MAX: Duration = Duration::from_secs(5);
const EVENT_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const EVENT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentServerEvent {
    pub(crate) revision: u64,
    pub(crate) kind: Arc<str>,
    account_id: Option<Arc<str>>,
}

impl AgentServerEvent {
    pub(crate) fn is_visible_to(&self, account_id: &str) -> bool {
        self.account_id
            .as_deref()
            .is_none_or(|target| target == account_id)
    }

    pub(crate) fn affects_proxy_authorization(&self) -> bool {
        matches!(
            self.kind.as_ref(),
            "profile_changed" | "profiles_changed" | "sync"
        )
    }
}

struct AgentEventHubInner {
    sender: broadcast::Sender<AgentServerEvent>,
    latest_revision: AtomicU64,
}

#[derive(Clone)]
pub struct AgentEventHub {
    inner: Arc<AgentEventHubInner>,
}

impl AgentEventHub {
    pub async fn start(
        repository: Arc<dyn AgentEventRepository>,
    ) -> Result<Self, UserRepositoryError> {
        let latest_revision = repository.latest_agent_event_revision().await?;
        let (sender, _) = broadcast::channel(EVENT_BUFFER_CAPACITY);
        let inner = Arc::new(AgentEventHubInner {
            sender,
            latest_revision: AtomicU64::new(latest_revision),
        });
        tokio::spawn(poll_agent_events(
            Arc::downgrade(&inner),
            repository,
            latest_revision,
        ));
        Ok(Self { inner })
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<AgentServerEvent> {
        self.inner.sender.subscribe()
    }

    pub(crate) fn latest_revision(&self) -> u64 {
        self.inner.latest_revision.load(Ordering::Acquire)
    }
}

async fn poll_agent_events(
    inner: Weak<AgentEventHubInner>,
    repository: Arc<dyn AgentEventRepository>,
    mut cursor: u64,
) {
    let mut error_backoff = EVENT_POLL_INTERVAL;
    let mut next_maintenance = tokio::time::Instant::now() + EVENT_MAINTENANCE_INTERVAL;
    loop {
        let Some(hub) = inner.upgrade() else {
            return;
        };
        match repository
            .list_agent_events_after(cursor, EVENT_DATABASE_BATCH_SIZE)
            .await
        {
            Ok(events) => {
                error_backoff = EVENT_POLL_INTERVAL;
                if let Some(first) = events.first()
                    && first.revision > cursor.saturating_add(1)
                {
                    // 当前实例落后超过事件保留窗口时，不能假装仍拥有完整事件序列。
                    // 全局 sync 会让所有本地 Agent 直接读取最新权威快照。
                    send_event(
                        &hub,
                        AgentServerEvent {
                            revision: first.revision.saturating_sub(1),
                            kind: Arc::from("sync"),
                            account_id: None,
                        },
                    );
                }
                let event_count = events.len();
                for event in events {
                    cursor = event.revision;
                    if let Some(event) = server_event(event) {
                        send_event(&hub, event);
                    }
                }
                hub.latest_revision.store(cursor, Ordering::Release);
                drop(hub);

                if tokio::time::Instant::now() >= next_maintenance {
                    purge_expired_events(repository.as_ref()).await;
                    next_maintenance = tokio::time::Instant::now() + EVENT_MAINTENANCE_INTERVAL;
                }
                if event_count == EVENT_DATABASE_BATCH_SIZE as usize {
                    continue;
                }
                tokio::time::sleep(EVENT_POLL_INTERVAL).await;
            }
            Err(error) => {
                error!(%error, ?error_backoff, "读取跨进程 Agent 事件日志失败，将重试");
                drop(hub);
                tokio::time::sleep(error_backoff).await;
                error_backoff = (error_backoff * 2).min(EVENT_ERROR_BACKOFF_MAX);
            }
        }
    }
}

fn server_event(event: AgentEventRecord) -> Option<AgentServerEvent> {
    match event.kind.as_str() {
        "profile_changed"
        | "profiles_changed"
        | "key_request_changed"
        | "admin_key_requests_changed" => Some(AgentServerEvent {
            revision: event.revision,
            kind: Arc::from(event.kind),
            account_id: event.account_id.map(Arc::from),
        }),
        unknown => {
            warn!(
                revision = event.revision,
                kind = unknown,
                "忽略未知的 Agent 事件日志类型"
            );
            None
        }
    }
}

fn send_event(hub: &AgentEventHubInner, event: AgentServerEvent) {
    debug!(
        revision = event.revision,
        kind = %event.kind,
        account_id = event.account_id.as_deref(),
        "向当前 Registry 实例的 Agent SSE 连接广播事件"
    );
    let _ = hub.sender.send(event);
}

async fn purge_expired_events(repository: &dyn AgentEventRepository) {
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(EVENT_RETENTION.as_secs());
    let Ok(before) = i64::try_from(before) else {
        return;
    };
    match repository.purge_agent_events_before(before).await {
        Ok(0) => {}
        Ok(purged) => debug!(purged, "已清理过期的 Agent 事件日志"),
        Err(error) => warn!(%error, "清理过期 Agent 事件日志失败，将在下个周期重试"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{NewProxyAddress, ProxyAddressRepository, SqliteUserRepository};
    use tempfile::TempDir;

    #[tokio::test]
    async fn independent_registry_hubs_receive_the_same_sqlite_event() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("users.sqlite3");
        let first_store = Arc::new(SqliteUserRepository::connect(&path).await.unwrap());
        let second_store = Arc::new(SqliteUserRepository::connect(&path).await.unwrap());
        let first_hub = AgentEventHub::start(first_store.clone()).await.unwrap();
        let second_hub = AgentEventHub::start(second_store).await.unwrap();
        let mut first_receiver = first_hub.subscribe();
        let mut second_receiver = second_hub.subscribe();

        first_store
            .create_proxy_address(NewProxyAddress {
                proxy_address_id: "proxy-event-test".to_string(),
                label: "Event test".to_string(),
                address: "127.0.0.1:8080".to_string(),
                enabled: true,
            })
            .await
            .unwrap();

        let first = tokio::time::timeout(Duration::from_secs(2), first_receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(2), second_receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.kind.as_ref(), "admin_key_requests_changed");
        assert!(first.is_visible_to("any-account"));
        assert!(first.revision > 0);
    }
}
