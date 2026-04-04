use super::connected_stream::ConnectedStream;
use super::proxy_connection::ProxyConnection;
use crate::config::AgentConfig;
use crate::error::Result;
use deadpool::unmanaged::Pool;
use protocol::{Address, TransportProtocol};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
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
    /// Maximum age a connection may sit in the pool before being discarded.
    /// Computed once from `config.pool_max_connection_age_secs` to avoid
    /// repeated conversions on the hot path.
    max_connection_age: Duration,
}

impl ConnectionPool {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        let pool_size = config.pool_size;

        // Create unmanaged pool with reasonable capacity (1.5x target size)
        let pool = Pool::new((pool_size as f32 * 1.5) as usize);

        // Create refill notification mechanism instead of channel
        let refill_notify = Arc::new(Notify::new());

        let available = Arc::new(AtomicUsize::new(0));

        let max_connection_age = Duration::from_secs(config.pool_max_connection_age_secs);

        // NOTE: The background refill task is NOT started here.
        // It is started by `prewarm()` after the initial connections are created,
        // preventing a race where both prewarm and the refill task create connections
        // simultaneously and overflow the pool.
        Self {
            pool,
            config,
            refill_notify,
            available,
            max_connection_age,
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
                                // Pool is already full — abort all remaining in-flight
                                // connection tasks so we don't create more connections to
                                // the proxy than the pool can hold (they would be
                                // immediately dropped, leaving the proxy with short-lived
                                // authenticated connections that waste resources).
                                debug!(
                                    "Pool is full during refill, aborting remaining tasks"
                                );
                                set.abort_all();
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            warn!("Failed to create prewarmed connection: {}", e);
                        }
                        Err(e) => {
                            if !e.is_cancelled() {
                                warn!("Refill task join error: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Prewarm the pool with initial connections, then start the background refill task.
    ///
    /// The refill task is started AFTER prewarm completes so that both do not create
    /// connections concurrently, which would overflow the pool and create unnecessary
    /// connections on the proxy side.
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

        // Start the background refill task AFTER prewarm has completed.
        // Starting it before prewarm would cause both to create connections at the same
        // time (if prewarm takes longer than the 5-second refill timer), leading to
        // double the expected connections on the proxy side.
        let pool_clone = self.pool.clone();
        let config_clone = self.config.clone();
        let available_clone = self.available.clone();
        let refill_notify_clone = self.refill_notify.clone();
        let pool_size = self.config.pool_size;
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
    }

    /// Get a connection and connect to target.
    /// The connection is consumed (not returned to pool).
    #[instrument(skip(self))]
    pub async fn get_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<ConnectedStream> {
        // Try to get a fresh prewarmed connection from the pool, discarding any
        // connections that are too old (the proxy may have already closed them due to
        // its own idle timeout).
        let conn = loop {
            match self.pool.try_remove() {
                Ok(conn) => {
                    self.available.fetch_sub(1, Ordering::AcqRel);
                    // Notify refill AFTER decrementing so the refill task reads an
                    // accurate count and creates exactly the right number of connections.
                    self.refill_notify.notify_one();

                    if conn.is_expired(self.max_connection_age) {
                        debug!("Discarding expired pooled connection, will try next or create new");
                        // conn is dropped here, closing the TCP connection gracefully
                        continue;
                    }
                    debug!("Using prewarmed connection from pool");
                    break conn;
                }
                Err(_) => {
                    // Pool is empty — signal refill and create a fresh connection directly.
                    self.refill_notify.notify_one();
                    debug!("No prewarmed connection available, creating new one");
                    break ProxyConnection::new(&self.config).await?;
                }
            }
        };

        // Connect to target (consumes the connection)
        conn.connect_target(address, transport).await
    }
}
