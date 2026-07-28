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
pub(crate) enum DeviceAuthorizationEndpoint {
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

struct RateLimitState {
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

struct TokenBucket {
    tokens: f64,
    updated_at: f64,
    last_seen_at: f64,
}

#[derive(Debug)]
pub(crate) struct DeviceAuthorizationPermit {
    _permit: OwnedSemaphorePermit,
}

impl AgentDeviceAuthorizationGuard {
    pub fn new(trust_proxy_headers: bool) -> Self {
        Self::with_concurrency_limit(trust_proxy_headers, MAX_CONCURRENT_DEVICE_AUTHORIZATIONS)
    }

    fn with_concurrency_limit(trust_proxy_headers: bool, concurrency_limit: usize) -> Self {
        Self {
            inner: Arc::new(GuardInner {
                concurrency: Arc::new(Semaphore::new(concurrency_limit.max(1))),
                state: Mutex::new(RateLimitState::new()),
                started_at: Instant::now(),
                trust_proxy_headers,
            }),
        }
    }

    pub(crate) fn enter(
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
    fn new() -> Self {
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

    fn check(
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

impl TokenBucket {
    fn full(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            updated_at: 0.0,
            last_seen_at: 0.0,
        }
    }

    fn retry_after(&mut self, now: f64, capacity: f64, refill_per_second: f64) -> Option<u32> {
        let elapsed = (now - self.updated_at).max(0.0);
        self.tokens = (self.tokens + elapsed * refill_per_second).min(capacity);
        self.updated_at = now;
        self.last_seen_at = now;
        if self.tokens >= 1.0 {
            None
        } else {
            Some((((1.0 - self.tokens) / refill_per_second).ceil() as u32).max(1))
        }
    }

    fn consume(&mut self) {
        self.tokens = (self.tokens - 1.0).max(0.0);
    }
}

fn resolve_client_ip(
    trust_proxy_headers: bool,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<IpAddr> {
    let peer_ip = peer.map(|peer| normalize_ip(peer.ip()));
    if trust_proxy_headers && peer_ip.is_some_and(|ip| ip.is_loopback()) {
        forwarded_for(headers).or(peer_ip)
    } else {
        peer_ip
    }
}

fn forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .rfind(|value| !value.is_empty())
        .and_then(parse_forwarded_ip)
        .or_else(|| {
            headers
                .get(header::FORWARDED)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.rsplit(',').next())
                .and_then(|hop| {
                    hop.split(';').find_map(|parameter| {
                        let (name, value) = parameter.trim().split_once('=')?;
                        name.eq_ignore_ascii_case("for")
                            .then_some(value.trim().trim_matches('"'))
                    })
                })
                .and_then(parse_forwarded_ip)
        })
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .or_else(|| {
            value
                .strip_prefix('[')
                .and_then(|value| value.split_once(']'))
                .and_then(|(ip, _)| ip.parse::<IpAddr>().ok())
        })
        .map(normalize_ip)
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_is_time_controllable_and_refills() {
        let mut state = RateLimitState::new();
        let client = Some("203.0.113.10".parse().unwrap());
        for _ in 0..START_CLIENT_CAPACITY as usize {
            assert_eq!(
                state.check(DeviceAuthorizationEndpoint::Start, client, 0.0),
                None
            );
        }
        assert_eq!(
            state.check(DeviceAuthorizationEndpoint::Start, client, 0.0),
            Some(5)
        );
        assert_eq!(
            state.check(DeviceAuthorizationEndpoint::Start, client, 5.0),
            None
        );
    }

    #[test]
    fn forwarded_address_is_used_only_for_explicit_loopback_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.3, 203.0.113.9".parse().unwrap(),
        );
        let loopback = Some("127.0.0.1:32100".parse().unwrap());
        let remote = Some("192.0.2.8:32100".parse().unwrap());
        assert_eq!(
            resolve_client_ip(true, &headers, loopback),
            Some("203.0.113.9".parse().unwrap())
        );
        assert_eq!(
            resolve_client_ip(false, &headers, loopback),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            resolve_client_ip(true, &headers, remote),
            Some("192.0.2.8".parse().unwrap())
        );
    }

    #[test]
    fn concurrency_gate_rejects_without_waiting() {
        let guard = AgentDeviceAuthorizationGuard::with_concurrency_limit(false, 1);
        let headers = HeaderMap::new();
        let first = guard
            .enter(DeviceAuthorizationEndpoint::Start, &headers, None)
            .unwrap();
        let error = guard
            .enter(DeviceAuthorizationEndpoint::Start, &headers, None)
            .unwrap_err();
        assert_eq!(
            axum::response::IntoResponse::into_response(error).status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(first);
        assert!(
            guard
                .enter(DeviceAuthorizationEndpoint::Start, &headers, None)
                .is_ok()
        );
    }

    #[test]
    fn login_is_limited_by_account_across_client_addresses() {
        let mut state = RateLimitState::new();
        let account_digest: [u8; 32] = Sha256::digest(b"alice").into();
        for index in 0..LOGIN_ACCOUNT_CAPACITY as u8 {
            let client = Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, index)));
            assert_eq!(state.login.check(client, account_digest, 0.0), None);
        }
        assert_eq!(
            state
                .login
                .check(Some("198.51.100.1".parse().unwrap()), account_digest, 0.0),
            Some(5)
        );
        assert_eq!(
            state
                .login
                .check(Some("198.51.100.1".parse().unwrap()), account_digest, 5.0),
            None
        );
    }

    #[test]
    fn registration_has_a_strict_per_client_budget() {
        let mut state = RateLimitState::new();
        let client = Some("203.0.113.22".parse().unwrap());
        for _ in 0..REGISTRATION_CLIENT_CAPACITY as usize {
            assert_eq!(
                state.check(DeviceAuthorizationEndpoint::Registration, client, 0.0),
                None
            );
        }
        assert_eq!(
            state.check(DeviceAuthorizationEndpoint::Registration, client, 0.0),
            Some(60)
        );
        assert_eq!(
            state.check(DeviceAuthorizationEndpoint::Registration, client, 60.0),
            None
        );
    }
}
