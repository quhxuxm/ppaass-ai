//! Desktop Agent 本地服务层。
//!
//! 这一层负责监听本地端口，自动识别 SOCKS5/HTTP 客户端，并在需要时并行启动
//! TUN 模式。真正的目标连接不会在这里建立，而是交给传输会话管理器获取
//! 已认证的 agent->proxy 流，或由 `DirectAccessChecker` 决定直连。

use crate::config::AgentConfig;
use crate::direct_access::DirectAccessChecker;
use crate::error::Result;
use crate::http_handler::handle_http_connection;
use crate::socks5_handler::handle_socks5_connection;
use crate::tun_handler::run_tun_mode;
use crate::yamux_session::YamuxSessionManager;
use common::{DEFAULT_TCP_LISTEN_BACKLOG, bind_tcp_listener_with_backlog, spawn_guarded};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, warn};

const TUN_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(4);

pub struct AgentServer {
    // 全局只读配置；连接处理任务通过 Arc 克隆读取。
    config: Arc<AgentConfig>,
    // TCP 语义的 proxy 传输管理器，供 HTTP CONNECT、SOCKS CONNECT、TUN TCP 使用。
    tcp_sessions: Arc<YamuxSessionManager>,
    // UDP 语义的 proxy 传输管理器，供 SOCKS UDP、TUN UDP、DNS proxy 使用。
    udp_sessions: Arc<YamuxSessionManager>,
    // 直连规则：命中后绕过 proxy，直接使用本机网络出口连接目标。
    direct_access_checker: Arc<DirectAccessChecker>,
}

impl AgentServer {
    #[instrument(skip(config))]
    pub async fn new(config: AgentConfig) -> Result<Self> {
        // 直连规则在启动时解析成运行时结构，连接处理路径只做快速匹配。
        let direct_access_checker = Arc::new(DirectAccessChecker::new(&config.direct_access));
        let config = Arc::new(config);
        // QUIC 模式下 TCP/UDP 各复用一条连接；TCP 兼容模式保留原有连接策略。
        let tcp_sessions = Arc::new(YamuxSessionManager::new(config.clone()));
        let udp_sessions = Arc::new(YamuxSessionManager::new_udp(config.clone()));

        Ok(Self {
            config,
            tcp_sessions,
            udp_sessions,
            direct_access_checker,
        })
    }

    #[instrument(skip(self))]
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        // 本地 HTTP/SOCKS 入口始终启动。TUN 打开时作为额外入口并行运行，
        // 这样手动配置浏览器代理和系统 TUN 两种模式不会互相挤掉。
        let listener = bind_tcp_listener_with_backlog(
            self.config.listen_addr.as_str(),
            DEFAULT_TCP_LISTEN_BACKLOG,
        )?;
        info!("Agent 服务器正在监听 {}", self.config.listen_addr);

        let mut tun_tasks = JoinSet::new();
        let mut tun_task_running = false;
        if self.config.tun.enabled {
            info!(
                "TUN 模式已启用 — {} 上的 SOCKS5/HTTP 监听器保持可用",
                self.config.listen_addr
            );
            let tun_cfg = self.config.tun.clone();
            let proxy_addrs = self.config.proxy_addrs.clone();
            let tcp_sessions = self.tcp_sessions.clone();
            let udp_sessions = self.udp_sessions.clone();
            let direct_access_checker = self.direct_access_checker.clone();
            let tun_shutdown = shutdown.clone();
            tun_tasks.spawn(run_tun_mode(
                tun_cfg,
                proxy_addrs,
                tcp_sessions,
                udp_sessions,
                direct_access_checker,
                tun_shutdown,
            ));
            tun_task_running = true;
        }

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("收到关闭信号，停止监听");
                    break;
                }
                tun_result = tun_tasks.join_next(), if tun_task_running => {
                    tun_task_running = false;
                    match tun_result {
                        Some(Ok(Ok(()))) if shutdown.is_cancelled() => break,
                        Some(Ok(Ok(()))) => {
                            error!("TUN 模式转发器提前退出，HTTP/SOCKS 监听器继续运行");
                        }
                        Some(Ok(Err(e))) => {
                            error!("TUN 模式转发器异常停止，HTTP/SOCKS 监听器继续运行：{}", e);
                        }
                        Some(Err(e)) => {
                            error!("TUN 模式任务异常，HTTP/SOCKS 监听器继续运行：{}", e);
                        }
                        None => {}
                    }
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            debug!("接受来自 {} 的连接", addr);
                            // 本地浏览器到 agent 的连接多为 HTTP CONNECT/SOCKS 隧道。
                            // 关闭 Nagle 可以避免小的 TLS/HTTP2 控制帧在本地入口被延迟合并，
                            // 对视频分片这种频繁建连/窗口更新的场景更稳。
                            if let Err(err) = stream.set_nodelay(true) {
                                debug!("设置本地入口 TCP_NODELAY 失败，继续使用默认行为：{err}");
                            }
                            // 每个客户端连接独立处理，复用对应协议的 Yamux session 管理器和直连规则。
                            let tcp_sessions = self.tcp_sessions.clone();
                            let udp_sessions = self.udp_sessions.clone();
                            let direct_checker = self.direct_access_checker.clone();
                            spawn_guarded("desktop inbound connection", async move {
                                if let Err(e) =
                                    handle_connection(stream, tcp_sessions, udp_sessions, direct_checker).await
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
            }
        }

        if tun_task_running {
            match tokio::time::timeout(TUN_SHUTDOWN_TIMEOUT, tun_tasks.join_next()).await {
                Ok(Some(result)) => match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => error!("TUN 模式转发器停止时返回错误：{}", e),
                    Err(e) => error!("TUN 模式任务停止时异常：{}", e),
                },
                Ok(None) => {}
                Err(_) => {
                    warn!(
                        "TUN 模式任务停止超时（超过 {} 秒），正在中止后台任务",
                        TUN_SHUTDOWN_TIMEOUT.as_secs()
                    );
                    tun_tasks.abort_all();
                }
            }
        }

        Ok(())
    }
}

#[instrument(skip(stream, tcp_sessions, udp_sessions, direct_checker))]
async fn handle_connection(
    stream: TcpStream,
    tcp_sessions: Arc<YamuxSessionManager>,
    udp_sessions: Arc<YamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    // 通过窥探第一个字节来检测协议类型。
    // 同一个 listen_addr 同时服务 SOCKS5 和 HTTP 代理，减少用户配置成本。
    let mut buffer = [0u8; 1];
    stream.peek(&mut buffer).await?;

    // peek 不消费字节，后续 SOCKS5/HTTP 处理器仍能从完整流开始解析。
    match buffer[0] {
        // SOCKS5 版本号为 0x05
        0x05 => handle_socks5_connection(stream, tcp_sessions, udp_sessions, direct_checker).await,
        // HTTP 方法首字母（G、P、C 等）
        b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T' => {
            handle_http_connection(stream, tcp_sessions, direct_checker).await
        }
        _ => {
            error!("未知协议，首字节：0x{:02x}", buffer[0]);
            Ok(())
        }
    }
}
