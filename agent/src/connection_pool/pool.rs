use super::connected_stream::ConnectedStream;
use super::proxy_connection::ProxyConnection;
use crate::config::AgentConfig;
use crate::error::Result;
use deadpool::unmanaged::Pool;
use protocol::{Address, TransportProtocol};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;
use tracing::{debug, info, instrument, warn};

/// Connection pool using deadpool::unmanaged for prewarming connections
/// Connections are NOT reused - each connection is taken from the pool and consumed
pub struct ConnectionPool {
    /// The unmanaged pool of prewarmed connections
    pool: Pool<ProxyConnection>,
    config: Arc<AgentConfig>,
    /// Notification to request refill
    refill_notify: Arc<Notify>,
    /// Tracks number of available connections in the pool
    available: Arc<AtomicUsize>,
}

impl ConnectionPool {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        let pool_size = config.pool_size;

        // Create unmanaged pool with reasonable capacity (1.5x target size)
        let pool = Pool::new((pool_size as f32 * 1.5) as usize);

        // Create refill notification mechanism instead of channel
        let refill_notify = Arc::new(Notify::new());

        let pool_clone = pool.clone();
        let config_clone = config.clone();
        let available = Arc::new(AtomicUsize::new(0));
        let available_clone = available.clone();
        let refill_notify_clone = refill_notify.clone();

        // Spawn background refill task
        tokio::spawn(async move {
            Self::refill_task(
                refill_notify_clone,
                pool_clone,
                config_clone,
                available_clone,
                pool_size,
            )
            .await;
        });

        Self {
            pool,
            config,
            refill_notify,
            available,
        }
    }

    #[instrument(skip(refill_notify, pool, config, available))]
    async fn refill_task(
        refill_notify: Arc<Notify>,
        pool: Pool<ProxyConnection>,
        config: Arc<AgentConfig>,
        available: Arc<AtomicUsize>,
        target_size: usize,
    ) {
        loop {
            // Wait for refill request or periodic check
            tokio::select! {
                _ = refill_notify.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }

            // Check current pool size
            let current_size = available.load(Ordering::Acquire);

            // Refill if below target
            if current_size < target_size {
                let to_create = target_size - current_size;
                debug!(
                    "Refilling pool: creating {} connections (current: {})",
                    to_create, current_size
                );

                // Limit concurrency to avoid overwhelming the system or proxy
                const MAX_CONCURRENT_REFILL: usize = 10;
                let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REFILL));
                let mut set = tokio::task::JoinSet::new();

                for _ in 0..to_create {
                    let config = config.clone();
                    let semaphore = semaphore.clone();

                    set.spawn(async move {
                        let _permit = semaphore.acquire().await.ok();
                        ProxyConnection::new(&config).await
                    });
                }

                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(conn)) => {
                            if pool.try_add(conn).is_ok() {
                                available.fetch_add(1, Ordering::Release);
                                debug!("Added prewarmed connection to pool");
                            } else {
                                debug!("Pool is full, stopping refill");
                                // If pool is full, we can discard the rest of the tasks or let them finish and fail to add
                                // We'll let them finish but stop adding if pool is actually full (try_add fails)
                            }
                        }
                        Ok(Err(e)) => {
                            warn!("Failed to create prewarmed connection: {}", e);
                        }
                        Err(e) => {
                            warn!("Refill task join error: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Prewarm the pool with initial connections
    #[instrument(skip(self))]
    pub async fn prewarm(&self) {
        info!(
            "Prewarming connection pool with {} connections",
            self.config.pool_size
        );

        // Create connections concurrently
        let mut handles = Vec::with_capacity(self.config.pool_size);

        for i in 0..self.config.pool_size {
            let config = self.config.clone();
            let pool = self.pool.clone();
            let available = self.available.clone();
            handles.push(tokio::spawn(async move {
                match ProxyConnection::new(&config).await {
                    Ok(conn) => {
                        if pool.try_add(conn).is_ok() {
                            available.fetch_add(1, Ordering::Release);
                            debug!("Prewarmed connection {}", i + 1);
                            true
                        } else {
                            debug!("Pool full during prewarm");
                            false
                        }
                    }
                    Err(e) => {
                        warn!("Failed to prewarm connection {}: {}", i + 1, e);
                        false
                    }
                }
            }));
        }

        let mut success_count = 0;
        for handle in handles {
            if let Ok(true) = handle.await {
                success_count += 1;
            }
        }

        info!("Pool prewarmed with {} connections", success_count);
    }

    /// Get a connection and connect to target
    /// The connection is consumed (not returned to pool)
    #[instrument(skip(self))]
    pub async fn get_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<ConnectedStream> {
        // Request refill in background using notify
        self.refill_notify.notify_one();

        // Try to get a prewarmed connection from the pool
        let conn = match self.pool.try_remove() {
            Ok(conn) => {
                self.available.fetch_sub(1, Ordering::AcqRel);
                debug!("Using prewarmed connection from pool");
                conn
            }
            Err(_) => {
                debug!("No prewarmed connection available, creating new one");
                ProxyConnection::new(&self.config).await?
            }
        };

        // Connect to target (consumes the connection)
        conn.connect_target(address, transport).await
    }
}
