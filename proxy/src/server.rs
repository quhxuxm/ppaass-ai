use crate::bandwidth::BandwidthMonitor;
use crate::config::ProxyConfig;
use crate::connection::ServerConnection;
use crate::error::Result;
use crate::user_manager::UserManager;
use protocol::CompressionMode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, instrument, warn};

pub struct ProxyServer {
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
}

impl ProxyServer {
    #[instrument(skip(config))]
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        let config = Arc::new(config);

        // 使用用户配置文件初始化用户管理器
        let user_manager = Arc::new(UserManager::new(&config.users_path)?);

        // 初始化带宽监控器
        let bandwidth_monitor = Arc::new(BandwidthMonitor::new());

        // 将所有用户注册到带宽监控器
        for username in user_manager.as_ref().list_users().await? {
            if let Some(user_config) = user_manager.get_user(&username).await? {
                bandwidth_monitor.register_user(username, user_config.bandwidth_limit_mbps);
            }
        }

        Ok(Self {
            config,
            user_manager,
            bandwidth_monitor,
        })
    }

    #[instrument(skip(self))]
    pub async fn run(self) -> Result<()> {
        // 启动代理服务器
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!("代理服务器正在监听 {}", self.config.listen_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            info!("接受来自 {} 的连接", addr);
                            let user_manager = self.user_manager.clone();
                            let bandwidth_monitor = self.bandwidth_monitor.clone();
                            let compression_mode = self.config.get_compression_mode();
                            let proxy_config=self.config.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(&proxy_config, stream, user_manager, bandwidth_monitor, compression_mode).await {
                                    error!("处理连接时出错：{}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("接受连接失败：{}", e);
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("收到关闭信号");
                    break;
                }
            }
        }

        Ok(())
    }
}

#[instrument(skip(proxy_config, stream, user_manager, bandwidth_monitor))]
async fn handle_connection(
    proxy_config: &ProxyConfig,
    stream: TcpStream,
    user_manager: Arc<UserManager>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    compression_mode: CompressionMode,
) -> Result<()> {
    let mut connection = ServerConnection::new(
        stream,
        bandwidth_monitor,
        compression_mode,
        proxy_config.clone().into(),
    );

    // 将认证超时应用到整个认证阶段，防止 agent 打开 TCP 连接后
    // 一直不完成认证握手而留下僵尸连接（例如半开连接、端口扫描器或异常客户端）。
    let auth_timeout = Duration::from_secs(proxy_config.auth_timeout_secs);
    let username = match tokio::time::timeout(auth_timeout, async {
        // 先窥探认证请求以获取用户名
        let username = match connection.peek_auth_username().await {
            Ok(username) => username,
            Err(e) => {
                error!("从认证请求获取用户名失败：{}", e);
                return Err(e);
            }
        };

        info!("收到用户 {} 的认证请求", username);

        // 查找该用户名对应的用户配置
        let user_config = match user_manager.as_ref().get_user(&username).await {
            Ok(Some(config)) => config,
            Ok(None) => {
                error!("用户不存在：{}", username);
                connection.send_auth_error("User not found").await?;
                return Err(crate::error::ProxyError::UserNotFound(username));
            }
            Err(e) => {
                error!("查找用户配置时出错：{}", e);
                connection.send_auth_error("Internal error").await?;
                return Err(e);
            }
        };

        // 使用正确的用户配置执行认证
        connection.authenticate(proxy_config, user_config).await?;

        Ok(username)
    })
    .await
    {
        Ok(Ok(username)) => username,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            warn!(
                "连接在认证阶段超时（{} 秒），正在关闭僵尸连接",
                proxy_config.auth_timeout_secs
            );
            return Ok(());
        }
    };

    // 对 handle_request 应用空闲超时，防止预热连接从未发送连接请求导致连接泄漏
    let idle_timeout = Duration::from_secs(proxy_config.idle_connection_timeout_secs);
    match tokio::time::timeout(idle_timeout, connection.handle_request()).await {
        Ok(result) => result,
        Err(_) => {
            warn!(
                "用户 '{}' 的连接等待请求超时（{} 秒），正在关闭以防止泄漏",
                username, proxy_config.idle_connection_timeout_secs
            );
            Ok(())
        }
    }
}
