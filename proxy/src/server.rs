use crate::bandwidth::BandwidthMonitor;
use crate::config::ProxyConfig;
use crate::connection::{EgressState, ServerConnection};
use crate::connection_limiter::{ConnectionLimiter, GlobalConnectionPermit};
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
    egress_state: Arc<EgressState>,
    connection_limiter: ConnectionLimiter,
}

struct ConnectionContext {
    proxy_config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    egress_state: Arc<EgressState>,
    compression_mode: CompressionMode,
    connection_limiter: ConnectionLimiter,
}

impl ProxyServer {
    #[instrument(skip(config))]
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        let config = Arc::new(config);

        // 使用用户配置文件初始化用户管理器
        let user_manager = Arc::new(UserManager::new(&config.users_path)?);

        // 初始化带宽监控器
        let bandwidth_monitor = Arc::new(BandwidthMonitor::new());
        // 出站状态在启动时构建；auto 模式会在这里缓存路由表，避免每个连接重复读取。
        let egress_state = Arc::new(EgressState::new(config.outbound_interface.as_deref())?);
        let connection_limiter = ConnectionLimiter::new(&config);

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
            egress_state,
            connection_limiter,
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
                            let Some(connection_permit) = self.connection_limiter.try_acquire_global() else {
                                warn!(
                                    "proxy 全局连接数已达上限（当前={}，上限={}），拒绝来自 {} 的连接",
                                    self.connection_limiter.active_total(),
                                    self.config.max_connections,
                                    addr
                                );
                                drop(stream);
                                continue;
                            };
                            info!("接受来自 {} 的连接", addr);
                            // 每个连接共享启动时创建的出站状态，连接内只做目标地址匹配。
                            let context = ConnectionContext {
                                proxy_config: self.config.clone(),
                                user_manager: self.user_manager.clone(),
                                bandwidth_monitor: self.bandwidth_monitor.clone(),
                                egress_state: self.egress_state.clone(),
                                compression_mode: self.config.get_compression_mode(),
                                connection_limiter: self.connection_limiter.clone(),
                            };
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_connection(context, stream, connection_permit).await
                                {
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

#[instrument(skip(context, stream, _connection_permit))]
async fn handle_connection(
    context: ConnectionContext,
    stream: TcpStream,
    _connection_permit: GlobalConnectionPermit,
) -> Result<()> {
    let ConnectionContext {
        proxy_config,
        user_manager,
        bandwidth_monitor,
        egress_state,
        compression_mode,
        connection_limiter,
    } = context;

    // ServerConnection 持有共享 EgressState，后续 TCP/UDP 请求都通过它出站。
    let mut connection = ServerConnection::new(
        stream,
        bandwidth_monitor,
        compression_mode,
        proxy_config.clone(),
        egress_state,
        connection_limiter.clone(),
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
        connection
            .authenticate(proxy_config.as_ref(), user_config)
            .await?;

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

    let Some(_user_permit) = connection_limiter.try_acquire_user(&username) else {
        warn!(
            "用户 '{}' 连接数已达上限（{}），正在关闭新连接",
            username, proxy_config.max_connections_per_user
        );
        return Ok(());
    };

    let Some(idle_permit) = connection_limiter.try_acquire_idle(&username) else {
        warn!(
            "用户 '{}' 预热 idle 连接数已达上限（{}），正在关闭多余预热连接",
            username, proxy_config.max_idle_connections_per_user
        );
        return Ok(());
    };

    // 仅将空闲超时用于“已认证但尚未发送连接请求”的预热连接。
    // 连接请求到达后，后续中继不应再受该超时限制。
    let idle_timeout = Duration::from_secs(proxy_config.idle_connection_timeout_secs);
    connection
        .handle_request(idle_timeout, &username, Some(idle_permit))
        .await
}
