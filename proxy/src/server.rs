//! proxy 入站服务层。
//!
//! 这一层只关心 agent 到 proxy 的“外层 TCP 连接”：监听、全局限流、
//! 创建每连接上下文、执行认证阶段，然后把已认证连接交给 `ServerConnection`
//! 去处理具体的 CONNECT / relay / Yamux 生命周期。

use crate::bandwidth::BandwidthMonitor;
use crate::config::ProxyConfig;
use crate::connection::{EgressState, ServerConnection};
use crate::connection_limiter::{ConnectionLimiter, GlobalConnectionPermit};
use crate::error::Result;
use crate::user_manager::UserManager;
use common::spawn_guarded;
use protocol::CompressionMode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, instrument, warn};

const OVER_IDLE_LIMIT_IMMEDIATE_CONNECT_GRACE: Duration = Duration::from_secs(1);

pub struct ProxyServer {
    // 运行期共享配置；每个连接只读它，所以放进 Arc 后廉价 clone。
    config: Arc<ProxyConfig>,
    // 用户表在认证路径读取，内部用锁保证并发读安全。
    user_manager: Arc<UserManager>,
    // 按用户统计上下行字节，用于粗粒度限速判断。
    bandwidth_monitor: Arc<BandwidthMonitor>,
    // 出站连接状态在启动时初始化，避免每次 CONNECT 都重新解析出站策略。
    egress_state: Arc<EgressState>,
    // 入站 TCP 连接、用户连接、idle 连接、UDP relay flow 的统一保护阀。
    connection_limiter: ConnectionLimiter,
}

struct ConnectionContext {
    // 拆成 context 是为了让 accept loop 只负责接入，把连接生命周期移动到独立任务。
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
        // 出站状态在启动时构建；auto 模式会缓存初始路由表，并在默认路由不可用时刷新。
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
            // 同时等待新连接和 Ctrl-C。收到关闭信号后退出 accept loop，
            // 已经 spawn 出去的连接任务会按各自的 IO/idle 规则结束。
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
                            debug!("接受来自 {} 的连接", addr);
                            // 每个连接共享启动时创建的出站状态，连接内只做目标地址匹配。
                            let context = ConnectionContext {
                                proxy_config: self.config.clone(),
                                user_manager: self.user_manager.clone(),
                                bandwidth_monitor: self.bandwidth_monitor.clone(),
                                egress_state: self.egress_state.clone(),
                                compression_mode: self.config.get_compression_mode(),
                                connection_limiter: self.connection_limiter.clone(),
                            };
                            spawn_guarded("proxy inbound connection", async move {
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
    // 这个 permit 只要还活着，就代表全局连接数占用中。
    // 参数名前带下划线是为了说明后续不会显式使用它，释放靠 Drop 完成。
    if let Err(err) = stream.set_nodelay(true) {
        warn!("设置入站代理连接 TCP_NODELAY 失败，将继续使用默认 TCP 行为: {err}");
    }

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

        debug!("收到用户 {} 的认证请求", username);

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

    // 认证通过后再占用用户连接数，避免未知用户/认证失败连接污染用户计数。
    let Some(_user_permit) = connection_limiter.try_acquire_user(&username) else {
        warn!(
            "用户 '{}' 连接数已达上限（{}），正在关闭新连接",
            username, proxy_config.max_connections_per_user
        );
        return Ok(());
    };

    // idle permit 只覆盖“已认证但还没有第一个 Connect”的预热线路。
    let idle_permit = match connection_limiter.try_acquire_idle(&username) {
        Some(permit) => Some(permit),
        None => {
            warn!(
                "用户 '{}' 预热 idle 连接数已达上限（{}），仅等待即时 Connect 请求",
                username, proxy_config.max_idle_connections_per_user
            );
            None
        }
    };

    // 仅将空闲超时用于“已认证但尚未发送第一个 Connect”的预热连接。
    // Connect 到达后会释放 idle permit；legacy relay、UDP relay 和 Yamux 外层 session
    // 的生命周期分别由业务中继、UDP flow idle 或 Yamux keepalive 管理。
    let pre_connect_idle_timeout = if idle_permit.is_some() {
        Duration::from_secs(proxy_config.pre_connect_idle_timeout_secs)
    } else {
        OVER_IDLE_LIMIT_IMMEDIATE_CONNECT_GRACE
    };
    connection
        .handle_pre_connect_request(pre_connect_idle_timeout, &username, idle_permit)
        .await
}
