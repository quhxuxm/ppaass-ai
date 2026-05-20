use super::connected_stream::ConnectedStream;
use super::proxy_connection::ProxyConnection;
use crate::config::AgentConfig;
use crate::error::Result;
use common::BindInterface;
use deadpool::unmanaged::Pool;
use protocol::{Address, TransportProtocol};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{debug, info, instrument, warn};

const MAX_CONCURRENT_POOL_CONNECTS: usize = 10;

/// 使用 deadpool::unmanaged 的连接池，用于预热代理连接。
/// 连接不会被复用 — 每条连接取出后即消费。
pub struct ConnectionPool {
    /// 预热连接的非托管池
    pool: Pool<ProxyConnection>,
    config: Arc<AgentConfig>,
    /// 请求补充连接的通知机制
    refill_notify: Arc<Notify>,
    /// 追踪池中可用连接数
    available: Arc<AtomicUsize>,
    /// 连接在池中停留的最长时间
    max_connection_age: Duration,
    /// TUN 模式激活时保存物理网卡的 IP 地址。
    /// 每个新建的代理 TCP 连接都会绑定到该 IP，确保流量从物理接口出，
    /// 而不会回环进入 TUN 设备。
    proxy_bind_ip: Arc<std::sync::RwLock<Option<IpAddr>>>,
    /// TUN 模式激活时保存物理出口接口。
    proxy_bind_interface: Arc<std::sync::RwLock<Option<BindInterface>>>,
}

impl ConnectionPool {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        let pool_size = config.pool_size;
        // unmanaged pool 容量略大于目标值，给并发补充和消费留出余量。
        let pool = Pool::new((pool_size as f32 * 1.5) as usize);
        let refill_notify = Arc::new(Notify::new());
        let available = Arc::new(AtomicUsize::new(0));
        let max_connection_age = Duration::from_secs(config.pool_max_connection_age_secs);
        Self {
            pool,
            config,
            refill_notify,
            available,
            max_connection_age,
            proxy_bind_ip: Arc::new(std::sync::RwLock::new(None)),
            proxy_bind_interface: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    // ── 绑定 IP 管理（TUN 模式）──────────────────────────────────────────────

    /// 设置代理连接应当绑定的物理网卡 IP。
    /// 应在安装 TUN 路由规则之前调用，确保后续所有代理连接
    /// （包括补充任务创建的连接）都绕过 TUN。
    pub fn set_proxy_bind_ip(&self, ip: Option<IpAddr>) {
        // TUN 模式启动/退出时会切换此值，后台补充任务创建新连接时读取它。
        if let Ok(mut guard) = self.proxy_bind_ip.write() {
            *guard = ip;
        }
    }

    /// 设置代理连接应当绑定的物理出口接口。
    pub fn set_proxy_bind_interface(&self, interface: Option<BindInterface>) {
        if let Ok(mut guard) = self.proxy_bind_interface.write() {
            *guard = interface;
        }
    }

    fn get_proxy_bind_ip(&self) -> Option<IpAddr> {
        // 读取失败时保守退回不绑定，让连接错误暴露给上层日志。
        self.proxy_bind_ip.read().ok().and_then(|g| *g)
    }

    fn get_proxy_bind_interface(&self) -> Option<BindInterface> {
        self.proxy_bind_interface
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    // ── 内部辅助 ─────────────────────────────────────────────────────────────

    #[instrument(skip(
        refill_notify,
        pool,
        config,
        available,
        proxy_bind_ip,
        proxy_bind_interface
    ))]
    async fn refill_task(
        refill_notify: Arc<Notify>,
        pool: Pool<ProxyConnection>,
        config: Arc<AgentConfig>,
        available: Arc<AtomicUsize>,
        target_size: usize,
        proxy_bind_ip: Arc<std::sync::RwLock<Option<IpAddr>>>,
        proxy_bind_interface: Arc<std::sync::RwLock<Option<BindInterface>>>,
    ) {
        loop {
            // 补充任务既响应显式通知，也周期性自检，避免通知丢失后池子长期为空。
            tokio::select! {
                _ = refill_notify.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }

            let current_size = available.load(Ordering::Acquire);
            if current_size < target_size {
                // available 只记录可消费连接数；过期或取出的连接会触发补充。
                let to_create = target_size - current_size;
                debug!(
                    "正在补充连接池：创建 {} 条连接（当前：{}）",
                    to_create, current_size
                );

                // 限制并发认证连接数，防止 proxy 短时间内被补充任务打满。
                let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_CONNECTS));
                let mut set = tokio::task::JoinSet::new();

                for _ in 0..to_create {
                    let config = config.clone();
                    let semaphore = semaphore.clone();
                    let bind_ip = proxy_bind_ip.read().ok().and_then(|g| *g);
                    let bind_interface = proxy_bind_interface.read().ok().and_then(|g| g.clone());
                    set.spawn(async move {
                        // permit 生命周期覆盖整个认证过程。
                        let _permit = semaphore.acquire().await.ok();
                        ProxyConnection::new(&config, bind_ip, bind_interface).await
                    });
                }

                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(conn)) => {
                            // try_add 失败说明 pool 容量已满，剩余创建任务没有意义。
                            if pool.try_add(conn).is_ok() {
                                available.fetch_add(1, Ordering::Release);
                                debug!("已向池中添加预热连接");
                            } else {
                                debug!("补充时池已满，中止剩余任务");
                                set.abort_all();
                                break;
                            }
                        }
                        Ok(Err(e)) => warn!("创建预热连接失败：{}", e),
                        Err(e) => {
                            if !e.is_cancelled() {
                                warn!("补充任务 join 错误：{}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// 用初始连接预热连接池，然后启动后台补充任务。
    #[instrument(skip(self))]
    pub async fn prewarm(&self) {
        info!("正在预热连接池，目标 {} 条连接", self.config.pool_size);

        // 初始预热并发执行，但限制认证连接并发，避免启动瞬间打满 proxy。
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_CONNECTS));
        let mut set = tokio::task::JoinSet::new();
        for i in 0..self.config.pool_size {
            let config = self.config.clone();
            let pool = self.pool.clone();
            let available = self.available.clone();
            let bind_ip = self.get_proxy_bind_ip();
            let bind_interface = self.get_proxy_bind_interface();
            let semaphore = semaphore.clone();
            set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                match ProxyConnection::new(&config, bind_ip, bind_interface).await {
                    Ok(conn) => {
                        if pool.try_add(conn).is_ok() {
                            available.fetch_add(1, Ordering::Release);
                            debug!("已预热连接 {}", i + 1);
                            true
                        } else {
                            debug!("预热时池已满");
                            false
                        }
                    }
                    Err(e) => {
                        warn!("预热连接 {} 失败：{}", i + 1, e);
                        false
                    }
                }
            });
        }

        let mut success_count = 0;
        while let Some(result) = set.join_next().await {
            match result {
                Ok(true) => success_count += 1,
                Ok(false) => {}
                Err(e) if e.is_cancelled() => {}
                Err(e) => warn!("预热任务 join 错误：{}", e),
            }
        }
        info!("连接池已预热 {} 条连接", success_count);

        // 预热完成后启动后台补充任务。
        // 若在预热之前启动，两者会并发创建连接导致溢出。
        let pool_clone = self.pool.clone();
        let config_clone = self.config.clone();
        let available_clone = self.available.clone();
        let refill_notify_clone = self.refill_notify.clone();
        let pool_size = self.config.pool_size;
        let proxy_bind_ip_clone = self.proxy_bind_ip.clone();
        let proxy_bind_interface_clone = self.proxy_bind_interface.clone();
        tokio::spawn(async move {
            Self::refill_task(
                refill_notify_clone,
                pool_clone,
                config_clone,
                available_clone,
                pool_size,
                proxy_bind_ip_clone,
                proxy_bind_interface_clone,
            )
            .await;
        });
    }

    /// 从池中获取连接并连接到目标。
    /// 连接被消费（不归还池）。
    #[instrument(skip(self))]
    pub async fn get_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<ConnectedStream> {
        loop {
            let (conn, from_pool) = match self.pool.try_remove() {
                Ok(conn) => {
                    // 取出的连接会被本次请求消费，不再归还池中。
                    self.available.fetch_sub(1, Ordering::AcqRel);
                    self.refill_notify.notify_one();
                    // 丢弃过期连接，避免拿到 proxy 已经按 idle timeout 关闭的连接。
                    if conn.is_expired(self.max_connection_age) {
                        debug!("丢弃过期的池连接，尝试下一条或创建新连接");
                        continue;
                    }
                    debug!("使用池中的预热连接");
                    (conn, true)
                }
                Err(_) => {
                    // 池为空时走按需创建，保证请求不依赖预热成功。
                    self.refill_notify.notify_one();
                    debug!("无可用预热连接，创建新连接");
                    (
                        ProxyConnection::new(
                            &self.config,
                            self.get_proxy_bind_ip(),
                            self.get_proxy_bind_interface(),
                        )
                        .await?,
                        false,
                    )
                }
            };

            let connect_result = conn.connect_target(address.clone(), transport).await;
            match connect_result {
                Ok(stream) => return Ok(stream),
                Err(err) if from_pool && should_retry_pooled_connect_error(&err) => {
                    warn!("预热代理连接不可用，已丢弃并重试：{}", err);
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
    }
}

fn should_retry_pooled_connect_error(err: &crate::error::AgentError) -> bool {
    match err {
        // 代理明确返回 ConnectResponse 失败时，多半是目标不可达、带宽限制或上游错误，
        // 重试同一个目标不会修复这类业务失败。
        crate::error::AgentError::Connection(message) => !message.starts_with("连接失败:"),
        crate::error::AgentError::Io(_) | crate::error::AgentError::Protocol(_) => true,
        _ => false,
    }
}
