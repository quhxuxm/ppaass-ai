use crate::config::AgentConfig;
use crate::connection_pool::ConnectionPool;
use crate::direct_access::DirectAccessChecker;
use crate::error::Result;
use crate::http_handler::handle_http_connection;
use crate::socks5_handler::handle_socks5_connection;
use crate::tun_handler::run_tun_mode;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, instrument};

pub struct AgentServer {
    config: Arc<AgentConfig>,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
}

impl AgentServer {
    #[instrument(skip(config))]
    pub async fn new(config: AgentConfig) -> Result<Self> {
        let direct_checker = Arc::new(DirectAccessChecker::new(&config.direct_access));
        let config = Arc::new(config);
        let pool = Arc::new(ConnectionPool::new(config.clone()));

        Ok(Self {
            config,
            pool,
            direct_checker,
        })
    }

    #[instrument(skip(self))]
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        // TUN 模式启用时完全替代 SOCKS5/HTTP 监听器：
        // 所有流量通过 TUN 设备捕获并转发到代理。
        if self.config.tun.enabled {
            info!(
                "TUN 模式已启用 — {} 上的 SOCKS5/HTTP 监听器将不会启动",
                self.config.listen_addr
            );
            let tun_cfg = self.config.tun.clone();
            let proxy_addrs = self.config.proxy_addrs.clone();
            let pool = self.pool.clone();
            let checker = self.direct_checker.clone();
            if let Err(e) = run_tun_mode(tun_cfg, proxy_addrs, pool, checker, shutdown).await {
                error!("TUN 模式转发器异常停止：{}", e);
                return Err(e);
            }
            return Ok(());
        }

        // 非 TUN 模式可以直接预热连接池。
        self.pool.prewarm().await;

        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!("Agent 服务器正在监听 {}", self.config.listen_addr);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("收到关闭信号，停止监听");
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            info!("接受来自 {} 的连接", addr);
                            let pool = self.pool.clone();
                            let direct_checker = self.direct_checker.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, pool, direct_checker).await {
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

        Ok(())
    }
}

#[instrument(skip(stream, pool, direct_checker))]
async fn handle_connection(
    stream: TcpStream,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    // 通过窥探第一个字节来检测协议类型
    let mut buffer = [0u8; 1];
    stream.peek(&mut buffer).await?;

    match buffer[0] {
        // SOCKS5 版本号为 0x05
        0x05 => handle_socks5_connection(stream, pool, direct_checker).await,
        // HTTP 方法首字母（G、P、C 等）
        b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T' => {
            handle_http_connection(stream, pool, direct_checker).await
        }
        _ => {
            error!("未知协议，首字节：0x{:02x}", buffer[0]);
            Ok(())
        }
    }
}
