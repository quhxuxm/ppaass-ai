//! proxy 入站服务层。
//!
//! TCP 目标继续使用 framed TCP/Yamux 入站；UDP 目标使用同端口的
//! PPAASS 原生加密 UDP 入站，两条路径共享用户表和出站状态。

use crate::access_log::AccessRecorder;
use crate::config::ProxyConfig;
use crate::connection::{EgressState, ServerConnection};
use crate::control_plane::{AccessEventSink, RemoteControlPlane};
use crate::error::Result;
use crate::transport_identity::load_transport_identity_private_key;
use crate::user_manager::UserManager;
use common::{
    DEFAULT_TCP_LISTEN_BACKLOG, bind_tcp_listener_with_backlog, configure_proxy_tcp_stream,
    spawn_guarded,
};
use futures::StreamExt;
use protocol::{CompressionMode, RsaKeyPair};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio_yamux::{session::Session, stream::StreamHandle};
use tracing::{debug, error, info, instrument, warn};

mod protocol_detection;
mod task_cleanup;

use protocol_detection::{looks_like_yamux_header, peek_connection_header};
use task_cleanup::{abort_stream_tasks, prune_finished_stream_tasks};

const YAMUX_SESSION_TASK_PRUNE_INTERVAL_SECS: u64 = 5;

pub struct ProxyServer {
    // 运行期共享配置；每个连接只读它，所以放进 Arc 后廉价 clone。
    config: Arc<ProxyConfig>,
    // 用户表在认证路径读取，内部用锁保证并发读安全。
    user_manager: Arc<UserManager>,
    // TCP/Yamux 成功与失败认证响应由该独立传输身份签名；Agent pin 对应公钥。
    transport_identity: Arc<RsaKeyPair>,
    // 出站连接状态在启动时初始化，避免每次 CONNECT 都重新解析出站策略。
    egress_state: Arc<EgressState>,
    // 成功访问异步写入与用户主库物理隔离的 SQLite。
    access_recorder: AccessRecorder,
}

#[derive(Clone)]
struct ConnectionContext {
    // 拆成 context 是为了让 accept loop 只负责接入，把连接生命周期移动到独立任务。
    proxy_config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    transport_identity: Arc<RsaKeyPair>,
    egress_state: Arc<EgressState>,
    access_recorder: AccessRecorder,
    compression_mode: CompressionMode,
}

impl ProxyServer {
    #[instrument(skip(config))]
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        let config = Arc::new(config);
        let identity_path = config
            .transport_identity_private_key_path
            .as_deref()
            .ok_or_else(|| {
                crate::error::ProxyError::Configuration(
                    "必须配置 transport_identity_private_key_path".to_string(),
                )
            })?;
        let transport_identity = Arc::new(load_transport_identity_private_key(Path::new(
            identity_path,
        ))?);
        info!("已安全加载 Proxy TCP/Yamux 传输身份私钥");

        let transport_identity_public_key_pem =
            transport_identity.public_key_to_pem().map_err(|error| {
                crate::error::ProxyError::Configuration(format!(
                    "无法派生 Proxy 传输身份公钥：{error}"
                ))
            })?;
        let control_plane =
            RemoteControlPlane::connect(&config, &transport_identity_public_key_pem).await?;
        info!(
            entry_id = config.entry_id,
            registry_control_url = config.registry_control_url,
            "已启用远程 Registry 授权与访问记录控制面"
        );
        let access_recorder =
            AccessRecorder::start(control_plane.clone() as Arc<dyn AccessEventSink>);
        let user_manager = Arc::new(UserManager::new(control_plane));

        // 出站状态在启动时构建；auto 模式会缓存初始路由表，并在默认路由不可用时刷新。
        let egress_state = Arc::new(EgressState::new(
            config.outbound_interface.as_deref(),
            config.dns_upstream_addr.as_deref(),
        )?);

        Ok(Self {
            config,
            user_manager,
            transport_identity,
            egress_state,
            access_recorder,
        })
    }

    #[instrument(skip(self))]
    pub async fn run(self) -> Result<()> {
        // TCP 与原生 UDP 共用同一个端口号。TCP listener 保持原有 framed
        // TCP/Yamux 入站，UDP socket 只接受通过 PPAASS 认证和 AEAD 的数据报。
        let listener = bind_tcp_listener_with_backlog(
            self.config.listen_addr.as_str(),
            DEFAULT_TCP_LISTEN_BACKLOG,
        )?;
        let udp_socket = Arc::new(UdpSocket::bind(&self.config.listen_addr).await?);
        let udp_listener = crate::native_udp::run_listener(
            udp_socket,
            self.config.clone(),
            self.user_manager.clone(),
            self.transport_identity.clone(),
            self.egress_state.clone(),
            self.access_recorder.clone(),
        );
        tokio::pin!(udp_listener);
        info!(
            "代理服务器正在监听 {}（TCP + 原生加密 UDP）",
            self.config.listen_addr
        );

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
                                transport_identity: self.transport_identity.clone(),
                                egress_state: self.egress_state.clone(),
                                access_recorder: self.access_recorder.clone(),
                                compression_mode: self.config.get_compression_mode(),
                            };
                            spawn_guarded("proxy inbound connection", async move {
                                if let Err(e) = handle_connection(context, stream).await {
                                    error!("处理 proxy 入站连接时出错：{}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("接受连接失败：{}", e);
                        }
                    }
                }
                result = &mut udp_listener => {
                    return result;
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
    if let Err(err) = configure_proxy_tcp_stream(&stream) {
        debug!("设置入站代理 TCP keepalive 失败：{err}");
    }

    let header = match peek_connection_header(
        &stream,
        Duration::from_secs(context.proxy_config.auth_timeout_secs.max(1)),
    )
    .await
    {
        Ok(Some(header)) => header,
        Ok(None) => return Ok(()),
        Err(err) => {
            debug!("读取入站连接首包失败：{err}");
            return Ok(());
        }
    };

    if !looks_like_yamux_header(&header) {
        return handle_direct_connection(context, stream).await;
    }

    let settings = context.proxy_config.yamux.settings().to_tokio_config();
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

async fn handle_direct_connection(context: ConnectionContext, stream: TcpStream) -> Result<()> {
    handle_protocol_stream(context, stream, "direct TCP connection").await
}

fn yamux_session_idle_timeout(config: &ProxyConfig) -> Option<Duration> {
    if config.yamux_session_idle_timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(config.yamux_session_idle_timeout_secs))
    }
}

async fn handle_yamux_substream(context: ConnectionContext, stream: StreamHandle) -> Result<()> {
    handle_protocol_stream(context, stream, "Yamux sub stream").await
}

async fn handle_protocol_stream<S>(
    context: ConnectionContext,
    stream: S,
    stream_label: &'static str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let ConnectionContext {
        proxy_config,
        user_manager,
        transport_identity,
        egress_state,
        access_recorder,
        compression_mode,
    } = context;

    // ServerConnection 持有共享 EgressState，后续 TCP/UDP 请求都通过它出站。
    let mut connection = ServerConnection::new(
        stream,
        compression_mode,
        proxy_config.clone(),
        user_manager.clone(),
        transport_identity,
        egress_state,
        access_recorder,
    );

    // 将认证超时应用到每条 framed 连接/每个 Yamux 子 stream 的认证阶段，防止异常客户端悬挂。
    let auth_timeout = std::time::Duration::from_secs(proxy_config.auth_timeout_secs);
    let username = match tokio::time::timeout(auth_timeout, async {
        // 先窥探认证请求以获取用户名
        let username = match connection.peek_auth_username().await {
            Ok(username) => username,
            Err(e) => {
                error!("从 {stream_label} 认证请求获取用户名失败：{}", e);
                return Err(e);
            }
        };

        debug!("收到用户 {} 的认证请求", username);

        // 查找该用户名对应的用户配置
        let user_config = match user_manager.as_ref().get_user(&username).await {
            Ok(Some(config)) => config,
            Ok(None) => {
                error!("用户不存在：{}", username);
                connection.send_auth_error().await?;
                return Err(crate::error::ProxyError::UserNotFound(username));
            }
            Err(e) => {
                error!("查找用户配置时出错：{}", e);
                connection.send_auth_error().await?;
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
                "{stream_label} 在认证阶段超时（{} 秒），正在关闭",
                proxy_config.auth_timeout_secs
            );
            return Ok(());
        }
    };

    connection.handle_connect_request(&username).await
}

#[cfg(test)]
mod tests;
