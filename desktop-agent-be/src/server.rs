use crate::config::AgentConfig;
use crate::connection_pool::ConnectionPool;
use crate::direct_access::DirectAccessChecker;
use crate::error::Result;
use crate::http_handler::handle_http_connection;
use crate::socks5_handler::handle_socks5_connection;
use crate::tun_handler::run_tun_mode;
use common::spawn_guarded;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument};

pub struct AgentServer {
    config: Arc<AgentConfig>,
    tcp_pool: Arc<ConnectionPool>,
    udp_pool: Arc<ConnectionPool>,
    direct_access_checker: Arc<DirectAccessChecker>,
}

impl AgentServer {
    #[instrument(skip(config))]
    pub async fn new(config: AgentConfig) -> Result<Self> {
        // 直连规则在启动时解析成运行时结构，连接处理路径只做快速匹配。
        let direct_access_checker = Arc::new(DirectAccessChecker::new(&config.direct_access));
        let config = Arc::new(config);
        // TCP/UDP 分别维护到 proxy 的已认证预热连接，避免两类流量互相挤占。
        let tcp_pool = Arc::new(ConnectionPool::new(config.clone()));
        let udp_pool = Arc::new(ConnectionPool::new_with_size(
            config.clone(),
            config.udp_pool_size,
            "udp_pool",
        ));

        Ok(Self {
            config,
            tcp_pool,
            udp_pool,
            direct_access_checker,
        })
    }

    #[instrument(skip(self))]
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        // 本地 HTTP/SOCKS 入口始终启动。TUN 打开时作为额外入口并行运行，
        // 这样手动配置浏览器代理和系统 TUN 两种模式不会互相挤掉。
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
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
            let tcp_pool = self.tcp_pool.clone();
            let udp_pool = self.udp_pool.clone();
            let direct_access_checker = self.direct_access_checker.clone();
            let tun_shutdown = shutdown.clone();
            tun_tasks.spawn(async move {
                run_tun_mode(
                    tun_cfg,
                    proxy_addrs,
                    tcp_pool,
                    udp_pool,
                    direct_access_checker,
                    tun_shutdown,
                )
                .await
            });
            tun_task_running = true;
        } else {
            // 纯代理模式可以直接预热连接池；TUN 模式会在路由就绪后预热。
            self.tcp_pool.prewarm().await;
            self.udp_pool.prewarm().await;
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
                            // 每个客户端连接独立处理，复用对应协议的连接池和直连规则。
                            let tcp_pool = self.tcp_pool.clone();
                            let udp_pool = self.udp_pool.clone();
                            let direct_checker = self.direct_access_checker.clone();
                            spawn_guarded("desktop inbound connection", async move {
                                if let Err(e) =
                                    handle_connection(stream, tcp_pool, udp_pool, direct_checker).await
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
            if let Some(result) = tun_tasks.join_next().await {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => error!("TUN 模式转发器停止时返回错误：{}", e),
                    Err(e) => error!("TUN 模式任务停止时异常：{}", e),
                }
            }
        }

        Ok(())
    }
}

#[instrument(skip(stream, tcp_pool, udp_pool, direct_checker))]
async fn handle_connection(
    stream: TcpStream,
    tcp_pool: Arc<ConnectionPool>,
    udp_pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    // 通过窥探第一个字节来检测协议类型
    let mut buffer = [0u8; 1];
    stream.peek(&mut buffer).await?;

    // peek 不消费字节，后续 SOCKS5/HTTP 处理器仍能从完整流开始解析。
    match buffer[0] {
        // SOCKS5 版本号为 0x05
        0x05 => handle_socks5_connection(stream, tcp_pool, udp_pool, direct_checker).await,
        // HTTP 方法首字母（G、P、C 等）
        b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T' => {
            handle_http_connection(stream, tcp_pool, direct_checker).await
        }
        _ => {
            error!("未知协议，首字节：0x{:02x}", buffer[0]);
            Ok(())
        }
    }
}
