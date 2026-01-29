use crate::config::AgentConfig;
use anyhow::{anyhow, Result};
use common::{
    codec::MessageCodec,
    crypto::{self, hash_password},
    protocol::Message,
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::{
    net::TcpStream,
    sync::Mutex as TokioMutex,
};
use tokio_util::codec::Framed;
use tracing::info;

/// A single connection to the proxy server
pub struct ProxyConnection {
    stream: TokioMutex<Framed<TcpStream, MessageCodec>>,
    session_id: String,
    aes_key: [u8; 32],
    last_used: Mutex<Instant>,
}

impl ProxyConnection {
    async fn new(config: Arc<AgentConfig>) -> Result<Self> {
        let stream = TcpStream::connect(&config.proxy_addr).await?;
        info!("Connected to proxy: {}", config.proxy_addr);
        let framed = Framed::new(stream, MessageCodec::new());
        let mut framed = framed;

        // Generate AES key for this session
        let aes_key = crypto::generate_aes_key();

        // Encrypt AES key with proxy's public RSA key
        let encrypted_aes_key = crypto::rsa_encrypt(&config.proxy_rsa_public_key, &aes_key)?;

        // Send authentication request
        let password_hash = hash_password(&config.user.password);
        let auth_msg = Message::AuthRequest {
            username: config.user.username.clone(),
            password_hash,
            encrypted_aes_key: encrypted_aes_key.to_vec(),
        };

        framed
            .send(auth_msg)
            .await
            .map_err(|e| anyhow!("Failed to send auth message: {e}"))?;

        // Wait for authentication response
        let response = next_message(&mut framed).await?;

        match response {
            Message::AuthResponse {
                success,
                message,
                session_id,
            } => {
                if success {
                    let session_id = session_id.ok_or_else(|| anyhow!("No session ID provided"))?;
                    info!("Authentication successful, session: {}", session_id);
                    Ok(Self {
                        stream: TokioMutex::new(framed),
                        session_id,
                        aes_key,
                        last_used: Mutex::new(Instant::now()),
                    })
                } else {
                    Err(anyhow!("Authentication failed: {}", message))
                }
            }
            _ => Err(anyhow!("Unexpected response from proxy")),
        }
    }

    pub async fn send_data(
        &self,
        payload: &[u8],
        target_addr: Option<String>,
        target_port: Option<u16>,
    ) -> Result<Vec<u8>> {
        // Encrypt payload with AES
        let encrypted_payload = crypto::aes_encrypt(&self.aes_key, payload)?;

        let msg = Message::Data {
            session_id: self.session_id.clone(),
            encrypted_payload,
            target_addr,
            target_port,
        };

        let mut stream = self.stream.lock().await;
        stream
            .send(msg)
            .await
            .map_err(|e| anyhow!("Failed to send payload: {e}"))?;

        let response = next_message(&mut stream).await?;

        match response {
            Message::Response {
                encrypted_payload, ..
            } => {
                let decrypted = crypto::aes_decrypt(&self.aes_key, &encrypted_payload)?;
                *self.last_used.lock() = Instant::now();
                Ok(decrypted)
            }
            Message::Error { message } => Err(anyhow!("Proxy error: {}", message)),
            _ => Err(anyhow!("Unexpected response type")),
        }
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_used.lock().elapsed() > timeout
    }
}

/// Connection pool for proxy connections
pub struct ConnectionPool {
    config: Arc<AgentConfig>,
    connections: Arc<DashMap<String, Arc<ProxyConnection>>>,
}

impl ConnectionPool {
    pub async fn new(config: Arc<AgentConfig>) -> Result<Self> {
        let connections = Arc::new(DashMap::new());

        // Start cleanup task
        let _cleanup_handle = {
            let connections = connections.clone();
            let idle_timeout = Duration::from_secs(config.connection_pool.idle_timeout_secs);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    connections.retain(|_id, conn: &mut Arc<ProxyConnection>| {
                        !conn.is_expired(idle_timeout)
                    });
                }
            })
        };

        Ok(Self {
            config,
            connections,
        })
    }

    pub async fn get_connection(&self) -> Result<Arc<ProxyConnection>> {
        // Try to reuse an existing connection
        if self.connections.len() < self.config.connection_pool.max_size {
            // Create new connection
            let conn = ProxyConnection::new(self.config.clone()).await?;
            let conn = Arc::new(conn);
            self.connections
                .insert(conn.session_id.clone(), conn.clone());
            Ok(conn)
        } else {
            // Return a random existing connection
            if let Some(entry) = self.connections.iter().next() {
                Ok(entry.value().clone())
            } else {
                // Create new connection anyway
                let conn = ProxyConnection::new(self.config.clone()).await?;
                let conn = Arc::new(conn);
                self.connections
                    .insert(conn.session_id.clone(), conn.clone());
                Ok(conn)
            }
        }
    }
}

async fn next_message(
    stream: &mut Framed<TcpStream, MessageCodec>,
) -> Result<Message> {
    stream
        .next()
        .await
        .transpose()
        .map_err(|e| anyhow!("Codec error: {e}"))?
        .ok_or_else(|| anyhow!("Proxy connection closed"))
}
