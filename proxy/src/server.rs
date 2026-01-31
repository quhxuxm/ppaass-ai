use crate::api::ApiServer;
use crate::bandwidth::BandwidthMonitor;
use crate::config::ProxyConfig;
use crate::connection::ProxyConnection;
use crate::error::Result;
use crate::user_manager::UserManager;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub struct ProxyServer {
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
}

impl ProxyServer {
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        let config = Arc::new(config);

        // Initialize user manager
        let user_manager = Arc::new(UserManager::new(
            &config.users_config_path,
            &config.keys_dir,
        )?);

        // Initialize bandwidth monitor
        let bandwidth_monitor = Arc::new(BandwidthMonitor::new());

        // Register all users in bandwidth monitor
        for username in user_manager.list_users() {
            if let Some(user_config) = user_manager.get_user(&username) {
                bandwidth_monitor.register_user(username, user_config.bandwidth_limit_mbps);
            }
        }

        Ok(Self {
            config,
            user_manager,
            bandwidth_monitor,
        })
    }

    pub async fn run(self) -> Result<()> {
        // Start API server
        let api_server = ApiServer::new(
            self.config.clone(),
            self.user_manager.clone(),
            self.bandwidth_monitor.clone(),
        );

        let api_handle = tokio::spawn(async move {
            if let Err(e) = api_server.run().await {
                error!("API server error: {}", e);
            }
        });

        // Start proxy server
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!("Proxy server listening on {}", self.config.listen_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            info!("Accepted connection from {}", addr);
                            let user_manager = self.user_manager.clone();
                            let bandwidth_monitor = self.bandwidth_monitor.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, user_manager, bandwidth_monitor).await {
                                    error!("Error handling connection: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received shutdown signal");
                    break;
                }
            }
        }

        // Wait for API server to finish
        let _ = api_handle.await;

        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    user_manager: Arc<UserManager>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
) -> Result<()> {
    let mut connection = ProxyConnection::new(stream, bandwidth_monitor, user_manager.clone());

    // First, peek at the auth request to get the username
    let username = match connection.peek_auth_username().await {
        Ok(username) => username,
        Err(e) => {
            error!("Failed to get username from auth request: {}", e);
            return Err(e);
        }
    };

    info!("Authentication request from user: {}", username);

    // Look up the user config for this username
    let user_config = match user_manager.get_user(&username) {
        Some(config) => config,
        None => {
            error!("User not found: {}", username);
            connection.send_auth_error("User not found").await?;
            return Err(crate::error::ProxyError::UserNotFound(username));
        }
    };

    // Now authenticate with the correct user config
    connection.authenticate(user_config).await?;

    // Handle requests in a loop
    loop {
        match connection.handle_request().await {
            Ok(should_continue) => {
                if !should_continue {
                    break;
                }
            }
            Err(e) => {
                error!("Error handling request: {}", e);
                break;
            }
        }
    }

    Ok(())
}
