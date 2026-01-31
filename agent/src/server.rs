use crate::config::AgentConfig;
use crate::connection_pool::ConnectionPool;
use crate::error::Result;
use crate::http_handler::handle_http_connection;
use crate::socks5_handler::handle_socks5_connection;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub struct AgentServer {
    config: Arc<AgentConfig>,
    pool: Arc<ConnectionPool>,
}

impl AgentServer {
    pub async fn new(config: AgentConfig) -> Result<Self> {
        let config = Arc::new(config);
        let pool = Arc::new(ConnectionPool::new(config.clone()));
        
        // Prewarm the pool
        pool.prewarm().await;

        Ok(Self { config, pool })
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!("Agent server listening on {}", self.config.listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Accepted connection from {}", addr);
                    let pool = self.pool.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, pool).await {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(stream: TcpStream, pool: Arc<ConnectionPool>) -> Result<()> {
    // Detect protocol by peeking at the first byte
    let mut buffer = [0u8; 1];
    stream.peek(&mut buffer).await?;

    match buffer[0] {
        // SOCKS5 version byte is 0x05
        0x05 => handle_socks5_connection(stream, pool).await,
        // HTTP methods start with letters (G, P, C, etc.)
        b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T' => handle_http_connection(stream, pool).await,
        _ => {
            error!("Unknown protocol, first byte: 0x{:02x}", buffer[0]);
            Ok(())
        }
    }
}
