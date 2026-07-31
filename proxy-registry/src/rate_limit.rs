use axum::http::{HeaderMap, StatusCode, header};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;

const MAX_CONCURRENT_DEVICE_AUTHORIZATIONS: usize = 32;
const MAX_TRACKED_CLIENTS: usize = 4_096;
const CLIENT_BUCKET_IDLE_SECONDS: f64 = 15.0 * 60.0;

const START_GLOBAL_CAPACITY: f64 = 40.0;
const START_GLOBAL_REFILL_PER_SECOND: f64 = 4.0;
const START_CLIENT_CAPACITY: f64 = 5.0;
const START_CLIENT_REFILL_PER_SECOND: f64 = 0.2;

const POLL_GLOBAL_CAPACITY: f64 = 400.0;
const POLL_GLOBAL_REFILL_PER_SECOND: f64 = 100.0;
const POLL_CLIENT_CAPACITY: f64 = 40.0;
const POLL_CLIENT_REFILL_PER_SECOND: f64 = 10.0;
const LOGIN_GLOBAL_CAPACITY: f64 = 80.0;
const LOGIN_GLOBAL_REFILL_PER_SECOND: f64 = 8.0;
pub(crate) const LOGIN_CLIENT_CAPACITY: f64 = 10.0;
const LOGIN_CLIENT_REFILL_PER_SECOND: f64 = 0.5;
pub(crate) const LOGIN_ACCOUNT_CAPACITY: f64 = 6.0;
const LOGIN_ACCOUNT_REFILL_PER_SECOND: f64 = 0.2;
const REGISTRATION_GLOBAL_CAPACITY: f64 = 20.0;
const REGISTRATION_GLOBAL_REFILL_PER_SECOND: f64 = 0.5;
pub(crate) const REGISTRATION_CLIENT_CAPACITY: f64 = 3.0;
const REGISTRATION_CLIENT_REFILL_PER_SECOND: f64 = 1.0 / 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthorizationEndpoint {
    Start,
    Poll,
    Registration,
}

#[derive(Clone)]
pub struct AgentDeviceAuthorizationGuard {
    inner: Arc<GuardInner>,
}

struct GuardInner {
    concurrency: Arc<Semaphore>,
    state: Mutex<RateLimitState>,
    started_at: Instant,
    trust_proxy_headers: bool,
}

#[doc(hidden)]
pub struct RateLimitState {
    start: EndpointBuckets,
    poll: EndpointBuckets,
    login: LoginBuckets,
    registration: EndpointBuckets,
}

struct EndpointBuckets {
    config: BucketConfig,
    global: TokenBucket,
    clients: HashMap<IpAddr, TokenBucket>,
    last_pruned_at: f64,
}

struct LoginBuckets {
    endpoint: EndpointBuckets,
    account_capacity: f64,
    account_refill_per_second: f64,
    accounts: HashMap<[u8; 32], TokenBucket>,
    last_pruned_at: f64,
}

#[derive(Clone, Copy)]
struct BucketConfig {
    global_capacity: f64,
    global_refill_per_second: f64,
    client_capacity: f64,
    client_refill_per_second: f64,
}

mod client_ip;
mod token_bucket;

pub use client_ip::resolve_client_ip;
use token_bucket::TokenBucket;

#[derive(Debug)]
pub struct DeviceAuthorizationPermit {
    _permit: OwnedSemaphorePermit,
}

impl AgentDeviceAuthorizationGuard {
    pub fn new(trust_proxy_headers: bool) -> Self {
        Self::with_concurrency_limit(trust_proxy_headers, MAX_CONCURRENT_DEVICE_AUTHORIZATIONS)
    }

    #[doc(hidden)]
    pub fn with_concurrency_limit(trust_proxy_headers: bool, concurrency_limit: usize) -> Self {
        Self {
            inner: Arc::new(GuardInner {
                concurrency: Arc::new(Semaphore::new(concurrency_limit.max(1))),
                state: Mutex::new(RateLimitState::new()),
                started_at: Instant::now(),
                trust_proxy_headers,
            }),
        }
    }

    #[doc(hidden)]
    pub fn enter(
        &self,
        endpoint: DeviceAuthorizationEndpoint,
        headers: &HeaderMap,
        peer: Option<SocketAddr>,
    ) -> Result<DeviceAuthorizationPermit, ApiError> {
        let permit = self
            .inner
            .concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| rate_limited(1))?;
        let now = self.inner.started_at.elapsed().as_secs_f64();
        let client_ip = resolve_client_ip(self.inner.trust_proxy_headers, headers, peer);
        let retry_after = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(endpoint, client_ip, now);
        if let Some(retry_after) = retry_after {
            return Err(rate_limited(retry_after));
        }
        Ok(DeviceAuthorizationPermit { _permit: permit })
    }

    /// 登录同时按可信客户端 IP 和规范化登录名限速。登录名仅以摘要形式保存在内存，
    /// 避免攻击者通过构造登录名让限流状态持有敏感或超长输入。
    pub(crate) fn enter_login(
        &self,
        headers: &HeaderMap,
        peer: Option<SocketAddr>,
        normalized_login_name: &str,
    ) -> Result<DeviceAuthorizationPermit, ApiError> {
        let permit = self
            .inner
            .concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| rate_limited(1))?;
        let now = self.inner.started_at.elapsed().as_secs_f64();
        let client_ip = resolve_client_ip(self.inner.trust_proxy_headers, headers, peer);
        let login_digest: [u8; 32] = Sha256::digest(normalized_login_name.as_bytes()).into();
        let retry_after = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .login
            .check(client_ip, login_digest, now);
        if let Some(retry_after) = retry_after {
            return Err(rate_limited(retry_after));
        }
        Ok(DeviceAuthorizationPermit { _permit: permit })
    }
}

impl Default for AgentDeviceAuthorizationGuard {
    fn default() -> Self {
        Self::new(false)
    }
}

impl RateLimitState {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            start: EndpointBuckets::new(BucketConfig {
                global_capacity: START_GLOBAL_CAPACITY,
                global_refill_per_second: START_GLOBAL_REFILL_PER_SECOND,
                client_capacity: START_CLIENT_CAPACITY,
                client_refill_per_second: START_CLIENT_REFILL_PER_SECOND,
            }),
            poll: EndpointBuckets::new(BucketConfig {
                global_capacity: POLL_GLOBAL_CAPACITY,
                global_refill_per_second: POLL_GLOBAL_REFILL_PER_SECOND,
                client_capacity: POLL_CLIENT_CAPACITY,
                client_refill_per_second: POLL_CLIENT_REFILL_PER_SECOND,
            }),
            login: LoginBuckets::new(
                BucketConfig {
                    global_capacity: LOGIN_GLOBAL_CAPACITY,
                    global_refill_per_second: LOGIN_GLOBAL_REFILL_PER_SECOND,
                    client_capacity: LOGIN_CLIENT_CAPACITY,
                    client_refill_per_second: LOGIN_CLIENT_REFILL_PER_SECOND,
                },
                LOGIN_ACCOUNT_CAPACITY,
                LOGIN_ACCOUNT_REFILL_PER_SECOND,
            ),
            registration: EndpointBuckets::new(BucketConfig {
                global_capacity: REGISTRATION_GLOBAL_CAPACITY,
                global_refill_per_second: REGISTRATION_GLOBAL_REFILL_PER_SECOND,
                client_capacity: REGISTRATION_CLIENT_CAPACITY,
                client_refill_per_second: REGISTRATION_CLIENT_REFILL_PER_SECOND,
            }),
        }
    }

    #[doc(hidden)]
    pub fn check(
        &mut self,
        endpoint: DeviceAuthorizationEndpoint,
        client_ip: Option<IpAddr>,
        now: f64,
    ) -> Option<u32> {
        match endpoint {
            DeviceAuthorizationEndpoint::Start => self.start.check(client_ip, now),
            DeviceAuthorizationEndpoint::Poll => self.poll.check(client_ip, now),
            DeviceAuthorizationEndpoint::Registration => self.registration.check(client_ip, now),
        }
    }

    #[doc(hidden)]
    pub fn check_login(
        &mut self,
        client_ip: Option<IpAddr>,
        account_digest: [u8; 32],
        now: f64,
    ) -> Option<u32> {
        self.login.check(client_ip, account_digest, now)
    }
}

impl EndpointBuckets {
    fn new(config: BucketConfig) -> Self {
        Self {
            config,
            global: TokenBucket::full(config.global_capacity),
            clients: HashMap::new(),
            last_pruned_at: 0.0,
        }
    }

    fn check(&mut self, client_ip: Option<IpAddr>, now: f64) -> Option<u32> {
        let global_retry = self.global.retry_after(
            now,
            self.config.global_capacity,
            self.config.global_refill_per_second,
        );
        if let Some(retry_after) = global_retry {
            return Some(retry_after);
        }

        let client_retry = client_ip.and_then(|client_ip| {
            self.prune_clients(now);
            if !self.clients.contains_key(&client_ip) && self.clients.len() >= MAX_TRACKED_CLIENTS {
                return Some(1);
            }
            self.clients
                .entry(client_ip)
                .or_insert_with(|| TokenBucket::full(self.config.client_capacity))
                .retry_after(
                    now,
                    self.config.client_capacity,
                    self.config.client_refill_per_second,
                )
        });
        if let Some(retry_after) = client_retry {
            return Some(retry_after);
        }

        self.global.consume();
        if let Some(client_ip) = client_ip
            && let Some(bucket) = self.clients.get_mut(&client_ip)
        {
            bucket.consume();
        }
        None
    }

    fn prune_clients(&mut self, now: f64) {
        if now - self.last_pruned_at < 60.0 && self.clients.len() < MAX_TRACKED_CLIENTS {
            return;
        }
        let cutoff = now - CLIENT_BUCKET_IDLE_SECONDS;
        self.clients
            .retain(|_, bucket| bucket.last_seen_at >= cutoff);
        self.last_pruned_at = now;
    }
}

impl LoginBuckets {
    fn new(
        endpoint_config: BucketConfig,
        account_capacity: f64,
        account_refill_per_second: f64,
    ) -> Self {
        Self {
            endpoint: EndpointBuckets::new(endpoint_config),
            account_capacity,
            account_refill_per_second,
            accounts: HashMap::new(),
            last_pruned_at: 0.0,
        }
    }

    fn check(
        &mut self,
        client_ip: Option<IpAddr>,
        account_digest: [u8; 32],
        now: f64,
    ) -> Option<u32> {
        self.endpoint.prune_clients(now);
        self.prune_accounts(now);
        if client_ip.is_some_and(|client_ip| {
            !self.endpoint.clients.contains_key(&client_ip)
                && self.endpoint.clients.len() >= MAX_TRACKED_CLIENTS
        }) || (!self.accounts.contains_key(&account_digest)
            && self.accounts.len() >= MAX_TRACKED_CLIENTS)
        {
            return Some(1);
        }

        let global_retry = self.endpoint.global.retry_after(
            now,
            self.endpoint.config.global_capacity,
            self.endpoint.config.global_refill_per_second,
        );
        let client_retry = client_ip.and_then(|client_ip| {
            self.endpoint
                .clients
                .entry(client_ip)
                .or_insert_with(|| TokenBucket::full(self.endpoint.config.client_capacity))
                .retry_after(
                    now,
                    self.endpoint.config.client_capacity,
                    self.endpoint.config.client_refill_per_second,
                )
        });
        let account_retry = self
            .accounts
            .entry(account_digest)
            .or_insert_with(|| TokenBucket::full(self.account_capacity))
            .retry_after(now, self.account_capacity, self.account_refill_per_second);
        let retry_after = [global_retry, client_retry, account_retry]
            .into_iter()
            .flatten()
            .max();
        if retry_after.is_some() {
            return retry_after;
        }

        self.endpoint.global.consume();
        if let Some(client_ip) = client_ip
            && let Some(bucket) = self.endpoint.clients.get_mut(&client_ip)
        {
            bucket.consume();
        }
        if let Some(bucket) = self.accounts.get_mut(&account_digest) {
            bucket.consume();
        }
        None
    }

    fn prune_accounts(&mut self, now: f64) {
        if now - self.last_pruned_at < 60.0 && self.accounts.len() < MAX_TRACKED_CLIENTS {
            return;
        }
        let cutoff = now - CLIENT_BUCKET_IDLE_SECONDS;
        self.accounts
            .retain(|_, bucket| bucket.last_seen_at >= cutoff);
        self.last_pruned_at = now;
    }
}

fn rate_limited(retry_after_seconds: u32) -> ApiError {
    ApiError::device_authorization_error(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "请求过于频繁，请稍后重试",
        Some(retry_after_seconds),
    )
}
