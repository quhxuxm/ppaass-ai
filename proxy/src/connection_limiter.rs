//! proxy 资源保护阀。
//!
//! 所有限制都用“获取 permit，Drop 自动释放”的方式表达：连接/flow/缓冲数据只要还活着，
//! 对应 permit 就还占用计数。这样正常返回、错误返回、任务取消都会走 Drop，减少手动减计数遗漏。

use crate::config::ProxyConfig;
use dashmap::DashMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct ConnectionLimiter {
    inner: Arc<ConnectionLimiterInner>,
}

struct ConnectionLimiterInner {
    // 全局连接数用 Semaphore 做硬上限；0 表示不启用该限制。
    global: Option<Arc<Semaphore>>,
    // active_total 单独记录当前值，便于日志输出，即使 global 为 None 也能统计。
    active_total: AtomicUsize,
    // 用户维度的 total/idle 计数按需创建，避免启动时为所有用户预分配。
    users: DashMap<String, Arc<UserConnectionCounters>>,
    max_connections_per_user: usize,
    max_idle_connections_per_user: usize,
    udp_relay_flows: AtomicUsize,
    max_udp_relay_flows: usize,
    udp_relay_buffered_bytes: AtomicUsize,
    max_udp_relay_buffered_bytes: usize,
}

struct UserConnectionCounters {
    total: AtomicUsize,
    idle: AtomicUsize,
}

pub struct GlobalConnectionPermit {
    // 有全局上限时持有 semaphore permit；无限制时为 None，但 active_total 仍会统计。
    _permit: Option<OwnedSemaphorePermit>,
    limiter: Arc<ConnectionLimiterInner>,
}

pub struct UserConnectionPermit {
    // max_connections_per_user 为 0 时不占用用户计数，因此 counters 为 None。
    counters: Option<Arc<UserConnectionCounters>>,
}

pub struct IdleConnectionPermit {
    // max_idle_connections_per_user 为 0 时不占用 idle 计数，因此 counters 为 None。
    counters: Option<Arc<UserConnectionCounters>>,
}

pub struct UdpRelayFlowPermit {
    limiter: Arc<ConnectionLimiterInner>,
}

pub struct UdpRelayBufferedBytesPermit {
    limiter: Arc<ConnectionLimiterInner>,
    bytes: usize,
}

impl ConnectionLimiter {
    pub fn new(config: &ProxyConfig) -> Self {
        let global = if config.max_connections == 0 {
            None
        } else {
            Some(Arc::new(Semaphore::new(config.max_connections)))
        };

        Self {
            inner: Arc::new(ConnectionLimiterInner {
                global,
                active_total: AtomicUsize::new(0),
                users: DashMap::new(),
                max_connections_per_user: config.max_connections_per_user,
                max_idle_connections_per_user: config.max_idle_connections_per_user,
                udp_relay_flows: AtomicUsize::new(0),
                max_udp_relay_flows: config.max_udp_relay_flows,
                udp_relay_buffered_bytes: AtomicUsize::new(0),
                max_udp_relay_buffered_bytes: config.max_udp_relay_buffered_bytes,
            }),
        }
    }

    pub fn try_acquire_global(&self) -> Option<GlobalConnectionPermit> {
        // 先获取 semaphore，再增加 active_total；获取失败时不污染统计值。
        let permit = match &self.inner.global {
            Some(semaphore) => Some(semaphore.clone().try_acquire_owned().ok()?),
            None => None,
        };
        self.inner.active_total.fetch_add(1, Ordering::AcqRel);
        Some(GlobalConnectionPermit {
            _permit: permit,
            limiter: self.inner.clone(),
        })
    }

    pub fn try_acquire_user(&self, username: &str) -> Option<UserConnectionPermit> {
        if self.inner.max_connections_per_user == 0 {
            return Some(UserConnectionPermit { counters: None });
        }
        let counters = self.user_counters(username);
        increment_limited(&counters.total, self.inner.max_connections_per_user)?;
        Some(UserConnectionPermit {
            counters: Some(counters),
        })
    }

    pub fn try_acquire_idle(&self, username: &str) -> Option<IdleConnectionPermit> {
        if self.inner.max_idle_connections_per_user == 0 {
            return Some(IdleConnectionPermit { counters: None });
        }
        let counters = self.user_counters(username);
        increment_limited(&counters.idle, self.inner.max_idle_connections_per_user)?;
        Some(IdleConnectionPermit {
            counters: Some(counters),
        })
    }

    pub fn active_total(&self) -> usize {
        self.inner.active_total.load(Ordering::Acquire)
    }

    pub fn try_acquire_udp_relay_flow(&self) -> Option<UdpRelayFlowPermit> {
        increment_limited(&self.inner.udp_relay_flows, self.inner.max_udp_relay_flows)?;
        Some(UdpRelayFlowPermit {
            limiter: self.inner.clone(),
        })
    }

    pub fn active_udp_relay_flows(&self) -> usize {
        self.inner.udp_relay_flows.load(Ordering::Acquire)
    }

    pub fn try_acquire_udp_relay_buffered_bytes(
        &self,
        bytes: usize,
    ) -> Option<UdpRelayBufferedBytesPermit> {
        // bytes 为 0 或配置 0 表示不限制缓冲字节；仍返回一个空 permit 统一调用方逻辑。
        if bytes == 0 || self.inner.max_udp_relay_buffered_bytes == 0 {
            return Some(UdpRelayBufferedBytesPermit {
                limiter: self.inner.clone(),
                bytes: 0,
            });
        }
        increment_limited_by(
            &self.inner.udp_relay_buffered_bytes,
            self.inner.max_udp_relay_buffered_bytes,
            bytes,
        )?;
        Some(UdpRelayBufferedBytesPermit {
            limiter: self.inner.clone(),
            bytes,
        })
    }

    pub fn active_udp_relay_buffered_bytes(&self) -> usize {
        self.inner.udp_relay_buffered_bytes.load(Ordering::Acquire)
    }

    fn user_counters(&self, username: &str) -> Arc<UserConnectionCounters> {
        self.inner
            .users
            .entry(username.to_string())
            .or_insert_with(|| {
                Arc::new(UserConnectionCounters {
                    total: AtomicUsize::new(0),
                    idle: AtomicUsize::new(0),
                })
            })
            .clone()
    }
}

impl Drop for GlobalConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active_total.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for UserConnectionPermit {
    fn drop(&mut self) {
        if let Some(counters) = &self.counters {
            counters.total.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl Drop for IdleConnectionPermit {
    fn drop(&mut self) {
        if let Some(counters) = &self.counters {
            counters.idle.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl Drop for UdpRelayFlowPermit {
    fn drop(&mut self) {
        self.limiter.udp_relay_flows.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for UdpRelayBufferedBytesPermit {
    fn drop(&mut self) {
        if self.bytes != 0 {
            self.limiter
                .udp_relay_buffered_bytes
                .fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

fn increment_limited(counter: &AtomicUsize, limit: usize) -> Option<()> {
    increment_limited_by(counter, limit, 1)
}

fn increment_limited_by(counter: &AtomicUsize, limit: usize, amount: usize) -> Option<()> {
    if amount == 0 {
        return Some(());
    }
    loop {
        // CAS 循环保证并发场景下不会超过上限；checked_add 防止 usize 溢出。
        let current = counter.load(Ordering::Acquire);
        let next = current.checked_add(amount)?;
        if limit != 0 && next > limit {
            return None;
        }
        if counter
            .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(
        max_connections: usize,
        max_connections_per_user: usize,
        max_idle_connections_per_user: usize,
    ) -> ProxyConfig {
        ProxyConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            users_path: "users.toml".to_string(),
            async_runtime_stack_size_mb: 4,
            log_level: "info".to_string(),
            log_dir: None,
            log_file: "proxy.log".to_string(),
            runtime_threads: None,
            compression_mode: "none".to_string(),
            tcp_relay_buffer_size_kb: common::default_stream_relay_buffer_size_kb(),
            replay_attack_tolerance: 300,
            transport: common::TransportConfig::default(),
            yamux: common::YamuxServerConfig::default(),
            forward_mode: false,
            upstream_proxy_addrs: None,
            upstream_username: None,
            upstream_private_key_path: None,
            outbound_interface: None,
            dns_upstream_addr: None,
            connect_timeout_secs: 30,
            pre_connect_idle_timeout_secs: 120,
            tcp_relay_idle_timeout_secs: 300,
            yamux_tcp_relay_idle_timeout_secs: 0,
            auth_timeout_secs: 30,
            max_connections,
            max_connections_per_user,
            max_idle_connections_per_user,
            max_udp_relay_flows_per_connection: 2048,
            max_udp_relay_flows: 4096,
            udp_relay_idle_timeout_secs: 60,
            udp_relay_channel_size: 256,
            max_udp_relay_buffered_bytes: 64 * 1024 * 1024,
        }
    }

    #[test]
    fn global_limit_releases_on_drop() {
        let limiter = ConnectionLimiter::new(&config(1, 0, 0));

        let permit = limiter.try_acquire_global().unwrap();
        assert!(limiter.try_acquire_global().is_none());
        assert_eq!(limiter.active_total(), 1);

        drop(permit);
        assert_eq!(limiter.active_total(), 0);
        assert!(limiter.try_acquire_global().is_some());
    }

    #[test]
    fn user_total_limit_is_per_user() {
        let limiter = ConnectionLimiter::new(&config(0, 1, 0));

        let alice = limiter.try_acquire_user("alice").unwrap();
        assert!(limiter.try_acquire_user("alice").is_none());
        assert!(limiter.try_acquire_user("bob").is_some());

        drop(alice);
        assert!(limiter.try_acquire_user("alice").is_some());
    }

    #[test]
    fn idle_limit_releases_on_drop() {
        let limiter = ConnectionLimiter::new(&config(0, 0, 1));

        let idle = limiter.try_acquire_idle("alice").unwrap();
        assert!(limiter.try_acquire_idle("alice").is_none());

        drop(idle);
        assert!(limiter.try_acquire_idle("alice").is_some());
    }

    #[test]
    fn zero_limits_are_unlimited() {
        let limiter = ConnectionLimiter::new(&config(0, 0, 0));

        assert!(limiter.try_acquire_global().is_some());
        assert!(limiter.try_acquire_global().is_some());
        assert!(limiter.try_acquire_user("alice").is_some());
        assert!(limiter.try_acquire_user("alice").is_some());
        assert!(limiter.try_acquire_idle("alice").is_some());
        assert!(limiter.try_acquire_idle("alice").is_some());
        assert_eq!(limiter.inner.users.len(), 0);
    }

    #[test]
    fn udp_relay_flow_limit_releases_on_drop() {
        let mut config = config(0, 0, 0);
        config.max_udp_relay_flows = 1;
        let limiter = ConnectionLimiter::new(&config);

        let flow = limiter.try_acquire_udp_relay_flow().unwrap();
        assert!(limiter.try_acquire_udp_relay_flow().is_none());
        assert_eq!(limiter.active_udp_relay_flows(), 1);

        drop(flow);
        assert_eq!(limiter.active_udp_relay_flows(), 0);
        assert!(limiter.try_acquire_udp_relay_flow().is_some());
    }

    #[test]
    fn udp_relay_buffered_bytes_limit_releases_on_drop() {
        let mut config = config(0, 0, 0);
        config.max_udp_relay_buffered_bytes = 10;
        let limiter = ConnectionLimiter::new(&config);

        let first = limiter.try_acquire_udp_relay_buffered_bytes(6).unwrap();
        assert!(limiter.try_acquire_udp_relay_buffered_bytes(5).is_none());
        assert_eq!(limiter.active_udp_relay_buffered_bytes(), 6);

        drop(first);
        assert_eq!(limiter.active_udp_relay_buffered_bytes(), 0);
        assert!(limiter.try_acquire_udp_relay_buffered_bytes(10).is_some());
    }
}
