use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{AuthenticatedConnection, ClientStream};
use protocol::{Address, TransportProtocol};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info, warn};

use crate::config::AndroidAgentConfig;
use crate::error::{AndroidAgentError, Result};

const MAX_CONCURRENT_POOL_CONNECTS: usize = 5;
const POOL_MAX_CONNECTION_AGE: Duration = Duration::from_secs(90);

struct PooledConnection {
    connection: AuthenticatedConnection,
    created_at: Instant,
}

pub struct AndroidConnectionPool {
    config: Arc<AndroidAgentConfig>,
    pool_size: usize,
    pool_name: &'static str,
    connections: Mutex<VecDeque<PooledConnection>>,
    refill_notify: Notify,
}

impl AndroidConnectionPool {
    pub fn new(
        config: Arc<AndroidAgentConfig>,
        pool_size: usize,
        pool_name: &'static str,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            pool_size,
            pool_name,
            connections: Mutex::new(VecDeque::new()),
            refill_notify: Notify::new(),
        })
    }

    pub async fn prewarm(self: &Arc<Self>) {
        info!(
            "prewarming Android {} with {} connections",
            self.pool_name, self.pool_size
        );
        let success_count = self.fill_to_target().await;
        info!(
            "Android {} prewarmed {} connections",
            self.pool_name, success_count
        );

        let pool = self.clone();
        tokio::spawn(async move {
            pool.refill_task().await;
        });
    }

    pub async fn get_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<ClientStream> {
        loop {
            let pooled = {
                let mut connections = self.connections.lock().await;
                connections.pop_front()
            };
            self.refill_notify.notify_one();

            match pooled {
                Some(pooled) if !pooled.is_expired() => {
                    debug!("using prewarmed Android {} connection", self.pool_name);
                    match pooled
                        .connection
                        .connect_to_target(address.clone(), transport)
                        .await
                    {
                        Ok((stream, _stream_id)) => return Ok(stream),
                        Err(err) => {
                            let message = err.to_string();
                            if message.starts_with("连接失败:") {
                                return Err(AndroidAgentError::Connection(message));
                            }
                            warn!(
                                "Android {} connection was unusable; retrying: {message}",
                                self.pool_name
                            );
                        }
                    }
                }
                Some(_) => {
                    debug!("discarding expired Android {} connection", self.pool_name);
                    continue;
                }
                None => {
                    debug!(
                        "Android {} empty; creating connection on demand",
                        self.pool_name
                    );
                    let connection = self.create_connection().await?;
                    let (stream, _stream_id) = connection
                        .connect_to_target(address, transport)
                        .await
                        .map_err(|err| AndroidAgentError::Connection(err.to_string()))?;
                    return Ok(stream);
                }
            }
        }
    }

    async fn refill_task(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = self.refill_notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            self.fill_to_target().await;
        }
    }

    async fn fill_to_target(&self) -> usize {
        if self.pool_size == 0 {
            return 0;
        }

        let current_size = self.connection_count().await;
        if current_size >= self.pool_size {
            return 0;
        }

        let to_create = self.pool_size - current_size;
        debug!(
            "refilling Android {}: creating {} connections (current={})",
            self.pool_name, to_create, current_size
        );

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_CONNECTS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..to_create {
            let config = self.config.clone();
            let semaphore = semaphore.clone();
            set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                create_pooled_connection(config).await
            });
        }

        let mut success_count = 0;
        while let Some(result) = set.join_next().await {
            match result {
                Ok(Ok(connection)) => {
                    if self.try_add_connection(connection).await {
                        success_count += 1;
                    } else {
                        set.abort_all();
                        break;
                    }
                }
                Ok(Err(err)) => {
                    warn!(
                        "failed to create Android {} connection: {err}",
                        self.pool_name
                    )
                }
                Err(err) if err.is_cancelled() => {}
                Err(err) => warn!("Android {} refill task join error: {err}", self.pool_name),
            }
        }
        success_count
    }

    async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    async fn try_add_connection(&self, connection: PooledConnection) -> bool {
        let mut connections = self.connections.lock().await;
        if connections.len() >= self.pool_size {
            return false;
        }
        connections.push_back(connection);
        true
    }

    async fn create_connection(&self) -> Result<AuthenticatedConnection> {
        AuthenticatedConnection::authenticate_only(self.config.as_ref())
            .await
            .map_err(|err| AndroidAgentError::Connection(err.to_string()))
    }
}

impl PooledConnection {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= POOL_MAX_CONNECTION_AGE
    }
}

async fn create_pooled_connection(
    config: Arc<AndroidAgentConfig>,
) -> std::io::Result<PooledConnection> {
    let connection = AuthenticatedConnection::authenticate_only(config.as_ref()).await?;
    Ok(PooledConnection {
        connection,
        created_at: Instant::now(),
    })
}
