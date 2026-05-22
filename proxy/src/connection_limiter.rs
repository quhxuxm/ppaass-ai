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
    global: Option<Arc<Semaphore>>,
    active_total: AtomicUsize,
    users: DashMap<String, Arc<UserConnectionCounters>>,
    max_connections_per_user: usize,
    max_idle_connections_per_user: usize,
    udp_relay_flows: AtomicUsize,
    max_udp_relay_flows: usize,
}

struct UserConnectionCounters {
    total: AtomicUsize,
    idle: AtomicUsize,
}

pub struct GlobalConnectionPermit {
    _permit: Option<OwnedSemaphorePermit>,
    limiter: Arc<ConnectionLimiterInner>,
}

pub struct UserConnectionPermit {
    counters: Arc<UserConnectionCounters>,
}

pub struct IdleConnectionPermit {
    counters: Arc<UserConnectionCounters>,
}

pub struct UdpRelayFlowPermit {
    limiter: Arc<ConnectionLimiterInner>,
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
            }),
        }
    }

    pub fn try_acquire_global(&self) -> Option<GlobalConnectionPermit> {
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
        let counters = self.user_counters(username);
        increment_limited(&counters.total, self.inner.max_connections_per_user)?;
        Some(UserConnectionPermit { counters })
    }

    pub fn try_acquire_idle(&self, username: &str) -> Option<IdleConnectionPermit> {
        let counters = self.user_counters(username);
        increment_limited(&counters.idle, self.inner.max_idle_connections_per_user)?;
        Some(IdleConnectionPermit { counters })
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
        self.counters.total.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for IdleConnectionPermit {
    fn drop(&mut self) {
        self.counters.idle.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for UdpRelayFlowPermit {
    fn drop(&mut self) {
        self.limiter.udp_relay_flows.fetch_sub(1, Ordering::AcqRel);
    }
}

fn increment_limited(counter: &AtomicUsize, limit: usize) -> Option<()> {
    loop {
        let current = counter.load(Ordering::Acquire);
        if limit != 0 && current >= limit {
            return None;
        }
        if counter
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
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
            auth_timeout_secs: 30,
            max_connections,
            max_connections_per_user,
            max_idle_connections_per_user,
            max_udp_relay_flows_per_connection: 2048,
            max_udp_relay_flows: 4096,
            udp_relay_idle_timeout_secs: 60,
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
}
