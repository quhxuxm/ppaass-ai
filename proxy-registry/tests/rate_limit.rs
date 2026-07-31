use axum::http::{HeaderMap, StatusCode};
use proxy_registry::{
    AgentDeviceAuthorizationGuard, DeviceAuthorizationEndpoint, RateLimitState, resolve_client_ip,
};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

const START_CLIENT_CAPACITY: f64 = 5.0;
const LOGIN_ACCOUNT_CAPACITY: f64 = 6.0;
const REGISTRATION_CLIENT_CAPACITY: f64 = 3.0;

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
        assert_eq!(state.check_login(client, account_digest, 0.0), None);
    }
    assert_eq!(
        state.check_login(Some("198.51.100.1".parse().unwrap()), account_digest, 0.0),
        Some(5)
    );
    assert_eq!(
        state.check_login(Some("198.51.100.1".parse().unwrap()), account_digest, 5.0),
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
