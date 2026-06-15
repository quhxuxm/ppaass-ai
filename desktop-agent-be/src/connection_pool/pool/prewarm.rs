//! legacy 连接池预热与后台补充。
//!
//! 预热连接只完成 agent->proxy 认证，不携带目标地址。上层真正需要连接目标时，
//! 才从池中取出一条连接发送 `ConnectRequest`。这能把用户请求路径上的认证延迟
//! 提前摊到后台。

use super::*;

struct RefillTaskContext {
    // 后台补充任务需要的字段集中放在 context，避免 spawn 时捕获整个 ConnectionPool。
    refill_notify: Arc<Notify>,
    pool: Pool<ProxyConnection>,
    config: Arc<AgentConfig>,
    available: Arc<AtomicUsize>,
    pool_name: &'static str,
    target_size: usize,
    proxy_bind_ip: Arc<std::sync::RwLock<Option<IpAddr>>>,
    proxy_bind_interface: Arc<std::sync::RwLock<Option<BindInterface>>>,
}

impl ConnectionPool {
    #[instrument(skip(context), fields(pool_name = context.pool_name, target_size = context.target_size))]
    async fn refill_task(context: RefillTaskContext) {
        loop {
            // 补充任务既响应显式通知，也周期性自检，避免通知丢失后池子长期为空。
            tokio::select! {
                _ = context.refill_notify.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }

            let current_size = context.available.load(Ordering::Acquire);
            if current_size < context.target_size {
                // available 只记录可消费连接数；过期或取出的连接会触发补充。
                let to_create = context.target_size - current_size;
                debug!(
                    "正在补充 {} 连接池：创建 {} 条连接（当前：{}）",
                    context.pool_name, to_create, current_size
                );

                // 限制并发认证连接数，防止 proxy 短时间内被补充任务打满。
                let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_CONNECTS));
                let mut set = tokio::task::JoinSet::new();

                for _ in 0..to_create {
                    let config = context.config.clone();
                    let semaphore = semaphore.clone();
                    let bind_ip = match context.proxy_bind_ip.read() {
                        Ok(guard) => *guard,
                        Err(_) => None,
                    };
                    let bind_interface = match context.proxy_bind_interface.read() {
                        Ok(guard) => guard.clone(),
                        Err(_) => None,
                    };
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
                            if context.pool.try_add(conn).is_ok() {
                                context.available.fetch_add(1, Ordering::Release);
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
        info!(
            "正在预热 {} 连接池，目标 {} 条连接",
            self.pool_name, self.pool_size
        );

        if self.use_yamux {
            // Yamux 模式下预热的是长期 session，不需要 legacy 的一次性连接池。
            match self.ensure_yamux_sessions(self.yamux_target_size()).await {
                Ok(success_count) => {
                    info!(
                        "{} Yamux 连接池已预热 {} 条连接",
                        self.pool_name, success_count
                    );
                    return;
                }
                Err(err) if self.yamux_mode == Some(TcpTransportMode::Auto) => {
                    warn!(
                        "{} Yamux 连接池预热失败，将回退到 legacy：{}",
                        self.pool_name, err
                    );
                }
                Err(err) => {
                    warn!("{} Yamux 连接池预热失败：{}", self.pool_name, err);
                    return;
                }
            }
        }

        // 初始预热并发执行，但限制认证连接并发，避免启动瞬间打满 proxy。
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_CONNECTS));
        let mut set = tokio::task::JoinSet::new();
        for i in 0..self.pool_size {
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
        info!("{} 连接池已预热 {} 条连接", self.pool_name, success_count);

        // 预热完成后启动后台补充任务。
        // 若在预热之前启动，两者会并发创建连接导致溢出。
        let refill_context = RefillTaskContext {
            refill_notify: self.refill_notify.clone(),
            pool: self.pool.clone(),
            config: self.config.clone(),
            available: self.available.clone(),
            pool_name: self.pool_name,
            target_size: self.pool_size,
            proxy_bind_ip: self.proxy_bind_ip.clone(),
            proxy_bind_interface: self.proxy_bind_interface.clone(),
        };
        spawn_guarded("desktop connection pool refill", async move {
            Self::refill_task(refill_context).await;
        });
    }
}
