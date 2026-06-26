//! proxy 入站服务层。
//!
//! 这一层只关心 agent 到 proxy 的 raw TCP Yamux 外层连接：监听、维护 Yamux session，
//! 然后把每个子 stream 作为独立的加密 PPAASS 连接交给 `ServerConnection` 处理认证、
//! CONNECT 和 relay。

use crate::config::ProxyConfig;
use crate::connection::{EgressState, ServerConnection};
use crate::error::Result;
use crate::user_manager::UserManager;
use common::{
    DEFAULT_TCP_LISTEN_BACKLOG, bind_tcp_listener_with_backlog, configure_yamux_tcp_stream,
    spawn_guarded,
};
use futures::StreamExt;
use protocol::CompressionMode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_yamux::{session::Session, stream::StreamHandle};
use tracing::{debug, error, info, instrument, warn};

const YAMUX_SESSION_TASK_PRUNE_INTERVAL_SECS: u64 = 5;

pub struct ProxyServer {
    // 运行期共享配置；每个连接只读它，所以放进 Arc 后廉价 clone。
    config: Arc<ProxyConfig>,
    // 用户表在认证路径读取，内部用锁保证并发读安全。
    user_manager: Arc<UserManager>,
    // 出站连接状态在启动时初始化，避免每次 CONNECT 都重新解析出站策略。
    egress_state: Arc<EgressState>,
}

#[derive(Clone)]
struct ConnectionContext {
    // 拆成 context 是为了让 accept loop 只负责接入，把连接生命周期移动到独立任务。
    proxy_config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    egress_state: Arc<EgressState>,
    compression_mode: CompressionMode,
}

impl ProxyServer {
    #[instrument(skip(config))]
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        let config = Arc::new(config);

        // 使用用户配置文件初始化用户管理器
        let user_manager = Arc::new(UserManager::new(&config.users_path)?);

        // 出站状态在启动时构建；auto 模式会缓存初始路由表，并在默认路由不可用时刷新。
        let egress_state = Arc::new(EgressState::new(config.outbound_interface.as_deref())?);

        Ok(Self {
            config,
            user_manager,
            egress_state,
        })
    }

    #[instrument(skip(self))]
    pub async fn run(self) -> Result<()> {
        // 启动代理服务器
        let listener = bind_tcp_listener_with_backlog(
            self.config.listen_addr.as_str(),
            DEFAULT_TCP_LISTEN_BACKLOG,
        )?;
        info!("代理服务器正在监听 {}", self.config.listen_addr);

        loop {
            // 同时等待新连接和 Ctrl-C。收到关闭信号后退出 accept loop，
            // 已经 spawn 出去的连接任务会按各自的 IO/idle 规则结束。
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            debug!("接受来自 {} 的连接", addr);
                            // 每个连接共享启动时创建的出站状态，连接内只做目标地址匹配。
                            let context = ConnectionContext {
                                proxy_config: self.config.clone(),
                                user_manager: self.user_manager.clone(),
                                egress_state: self.egress_state.clone(),
                                compression_mode: self.config.get_compression_mode(),
                            };
                            spawn_guarded("proxy yamux session", async move {
                                if let Err(e) = handle_connection(context, stream).await {
                                    error!("处理 Yamux session 时出错：{}", e);
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

#[instrument(skip(context, stream))]
async fn handle_connection(context: ConnectionContext, stream: TcpStream) -> Result<()> {
    if let Err(err) = stream.set_nodelay(true) {
        warn!("设置入站代理连接 TCP_NODELAY 失败，将继续使用默认 TCP 行为: {err}");
    }
    if let Err(err) = configure_yamux_tcp_stream(&stream) {
        debug!("设置入站 Yamux TCP keepalive 失败：{err}");
    }

    let settings = context
        .proxy_config
        .yamux
        .merged_settings()
        .to_tokio_config();
    let mut session = Session::new_server(stream, settings);
    let mut stream_tasks = Vec::new();
    let session_idle_timeout = yamux_session_idle_timeout(&context.proxy_config);

    loop {
        prune_finished_stream_tasks(&mut stream_tasks);
        let idle_enabled = stream_tasks.is_empty() && session_idle_timeout.is_some();
        let idle_sleep = tokio::time::sleep(session_idle_timeout.unwrap_or(Duration::from_secs(1)));
        let prune_sleep =
            tokio::time::sleep(Duration::from_secs(YAMUX_SESSION_TASK_PRUNE_INTERVAL_SECS));
        tokio::pin!(idle_sleep);
        tokio::pin!(prune_sleep);

        let next_stream = tokio::select! {
            result = session.next() => result,
            _ = &mut idle_sleep, if idle_enabled => {
                let timeout = session_idle_timeout.expect("idle timeout is enabled");
                debug!(
                    "Yamux session 空闲超过 {} 秒且无活跃子 stream，主动关闭",
                    timeout.as_secs()
                );
                break;
            }
            _ = &mut prune_sleep, if !stream_tasks.is_empty() => {
                continue;
            }
        };

        let Some(result) = next_stream else {
            break;
        };

        match result {
            Ok(stream) => {
                prune_finished_stream_tasks(&mut stream_tasks);
                let context = context.clone();
                let task = spawn_guarded("proxy yamux substream", async move {
                    if let Err(err) = handle_yamux_substream(context, stream).await {
                        debug!("Yamux 子 stream 已结束：{err}");
                    }
                });
                stream_tasks.push(task);
            }
            Err(err) => {
                debug!("Yamux session 结束：{err}");
                break;
            }
        }
    }

    abort_stream_tasks(stream_tasks).await;
    Ok(())
}

fn yamux_session_idle_timeout(config: &ProxyConfig) -> Option<Duration> {
    if config.yamux_session_idle_timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(config.yamux_session_idle_timeout_secs))
    }
}

async fn handle_yamux_substream(context: ConnectionContext, stream: StreamHandle) -> Result<()> {
    let ConnectionContext {
        proxy_config,
        user_manager,
        egress_state,
        compression_mode,
    } = context;

    // ServerConnection 持有共享 EgressState，后续 TCP/UDP 请求都通过它出站。
    let mut connection =
        ServerConnection::new(stream, compression_mode, proxy_config.clone(), egress_state);

    // 将认证超时应用到每个 Yamux 子 stream 的认证阶段，防止异常客户端打开子流后悬挂。
    let auth_timeout = std::time::Duration::from_secs(proxy_config.auth_timeout_secs);
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
                "Yamux 子 stream 在认证阶段超时（{} 秒），正在关闭",
                proxy_config.auth_timeout_secs
            );
            return Ok(());
        }
    };

    connection.handle_connect_request(&username).await
}

fn prune_finished_stream_tasks(tasks: &mut Vec<tokio::task::JoinHandle<()>>) {
    tasks.retain(|task| !task.is_finished());
}

async fn abort_stream_tasks(tasks: Vec<tokio::task::JoinHandle<()>>) {
    if tasks.is_empty() {
        return;
    }

    warn!(
        "Yamux session 结束时仍有 {} 个活跃子 stream，正在关闭；这些请求的上层 HTTP body 可能被截断",
        tasks.len()
    );
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        match task.await {
            Ok(()) => {}
            Err(err) if err.is_cancelled() => {}
            Err(err) => debug!("Yamux 子 stream 任务回收时返回错误：{err}"),
        }
    }
}
