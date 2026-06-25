use super::*;
use common::spawn_guarded;

impl ConnectionPool {
    pub fn spawn_prewarm_once(self: &Arc<Self>, task_name: &'static str) {
        if self.prewarm_started.swap(true, Ordering::AcqRel) {
            debug!("{} Yamux 连接池预热已启动，跳过重复请求", self.pool_name);
            return;
        }

        let pool = self.clone();
        spawn_guarded(task_name, async move {
            pool.prewarm().await;
        });
    }

    #[instrument(skip(self))]
    pub async fn prewarm(&self) {
        let target_size = self.yamux_target_size();
        info!(
            "正在预热 {} raw Yamux session 池，目标 {} 条 session",
            self.pool_name, target_size
        );

        match self.ensure_yamux_sessions(target_size).await {
            Ok(success_count) => {
                info!(
                    "{} raw Yamux session 池已预热 {} 条新 session",
                    self.pool_name, success_count
                );
            }
            Err(err) => {
                warn!("{} raw Yamux session 池预热失败：{}", self.pool_name, err);
            }
        }
    }
}
