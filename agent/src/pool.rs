#![allow(dead_code)]
// NOTE: This module is deprecated and replaced by multiplexer.rs for connection pooling with multiplexing

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::proxy_connection::ProxyConnection;
use deadpool::managed::{Manager, Metrics, RecycleResult};
use std::sync::Arc;
use tracing::info;

pub struct ProxyConnectionManager {
    config: Arc<AgentConfig>,
}

impl ProxyConnectionManager {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        Self { config }
    }
}

impl Manager for ProxyConnectionManager {
    type Type = ProxyConnection;
    type Error = AgentError;

    fn create(
        &self,
    ) -> impl std::future::Future<Output = Result<ProxyConnection>> + Send {
        let config = self.config.clone();
        async move {
            // ProxyConnection::connect now handles both connection and authentication
            let conn = ProxyConnection::connect(&config).await?;
            info!("Created new proxy connection");
            Ok(conn)
        }
    }

    fn recycle(
        &self,
        _conn: &mut ProxyConnection,
        _metrics: &Metrics,
    ) -> impl std::future::Future<Output = RecycleResult<Self::Error>> + Send {
        async move {
            // For simplicity, always recycle connections
            // In production, you might want to send a heartbeat or check connection status
            Ok(())
        }
    }
}

pub type ProxyPool = deadpool::managed::Pool<ProxyConnectionManager>;

pub fn create_pool(config: Arc<AgentConfig>) -> ProxyPool {
    let manager = ProxyConnectionManager::new(config.clone());
    ProxyPool::builder(manager)
        .max_size(config.pool_size)
        .build()
        .expect("Failed to create connection pool")
}
