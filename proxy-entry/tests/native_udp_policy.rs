use proxy_entry::error::ProxyError;
use proxy_entry::native_udp::listener::username_session_limit_reached;
use proxy_entry::native_udp::session::admission::{
    AuthorizationFreshness, FlowAdmission, FlowCreationBudget, FlowOpenDecision,
    classify_flow_admission, decide_flow_open,
};
use proxy_entry::native_udp::session::{
    FLOW_CREATION_BURST, duration_until_expiry, session_expired_at,
};
use std::cell::Cell;
use std::time::{Duration, UNIX_EPOCH};
use tokio::time::Instant;

#[test]
fn per_username_session_limit_is_exact_and_does_not_count_other_users() {
    let limit = 64;
    let mut usernames = vec!["bob"; 20];
    usernames.extend(std::iter::repeat_n("alice", limit - 1));
    assert!(!username_session_limit_reached(
        usernames.iter().copied(),
        "alice",
        limit,
    ));
    usernames.push("alice");
    assert!(username_session_limit_reached(
        usernames.iter().copied(),
        "alice",
        limit,
    ));
}

#[test]
fn existing_flow_remains_idempotent_when_session_is_full() {
    assert_eq!(
        classify_flow_admission(true, 256, 256),
        FlowAdmission::Existing
    );
}

#[test]
fn new_flow_is_rejected_at_limit_without_off_by_one() {
    assert_eq!(
        classify_flow_admission(false, 255, 256),
        FlowAdmission::Create
    );
    assert_eq!(
        classify_flow_admission(false, 256, 256),
        FlowAdmission::AtCapacity
    );
    assert_eq!(
        classify_flow_admission(false, 257, 256),
        FlowAdmission::AtCapacity
    );
}

#[test]
fn zero_flow_limit_disables_new_flow_creation() {
    assert_eq!(
        classify_flow_admission(false, 0, 0),
        FlowAdmission::AtCapacity
    );
}

#[tokio::test]
async fn only_create_admission_revalidates_and_successes_are_coalesced() {
    let start = Instant::now();
    let mut budget = FlowCreationBudget::new(start);
    let mut freshness = AuthorizationFreshness::default();
    let queries = Cell::new(0_u32);

    for admission in [FlowAdmission::Existing, FlowAdmission::AtCapacity] {
        let decision = decide_flow_open(admission, &mut budget, &mut freshness, start, || async {
            queries.set(queries.get() + 1);
            Ok::<(), ProxyError>(())
        })
        .await
        .unwrap();
        assert_ne!(decision, FlowOpenDecision::Create);
    }
    assert_eq!(queries.get(), 0);

    for (now, expected_queries) in [
        (start, 1),
        (start + Duration::from_millis(500), 1),
        (start + Duration::from_secs(1), 2),
    ] {
        assert_eq!(
            decide_flow_open(
                FlowAdmission::Create,
                &mut budget,
                &mut freshness,
                now,
                || async {
                    queries.set(queries.get() + 1);
                    Ok::<(), ProxyError>(())
                },
            )
            .await
            .unwrap(),
            FlowOpenDecision::Create
        );
        assert_eq!(queries.get(), expected_queries);
    }
}

#[tokio::test]
async fn flow_creation_budget_has_a_bounded_burst_and_refill() {
    let start = Instant::now();
    let mut budget = FlowCreationBudget::new(start);
    let mut freshness = AuthorizationFreshness::default();
    for _ in 0..FLOW_CREATION_BURST as usize {
        assert_eq!(
            decide_flow_open(
                FlowAdmission::Create,
                &mut budget,
                &mut freshness,
                start,
                || async { Ok(()) },
            )
            .await
            .unwrap(),
            FlowOpenDecision::Create
        );
    }
    assert_eq!(
        decide_flow_open(
            FlowAdmission::Create,
            &mut budget,
            &mut freshness,
            start,
            || async { Ok(()) },
        )
        .await
        .unwrap(),
        FlowOpenDecision::RateLimited
    );
    assert_eq!(
        decide_flow_open(
            FlowAdmission::Create,
            &mut budget,
            &mut freshness,
            start + Duration::from_secs(1),
            || async { Ok(()) },
        )
        .await
        .unwrap(),
        FlowOpenDecision::Create
    );
}

#[tokio::test]
async fn failed_flow_revalidation_is_not_cached_and_fails_closed() {
    let start = Instant::now();
    let mut budget = FlowCreationBudget::new(start);
    let mut freshness = AuthorizationFreshness::default();
    let result = decide_flow_open(
        FlowAdmission::Create,
        &mut budget,
        &mut freshness,
        start,
        || async {
            Err(ProxyError::Authentication(
                "revoked during test".to_string(),
            ))
        },
    )
    .await;
    assert!(result.is_err());
    assert!(freshness.requires_recheck(start + Duration::from_millis(1)));
}

#[test]
fn absolute_expiry_uses_the_epoch_boundary_without_second_rounding() {
    let half_second_before = UNIX_EPOCH + Duration::from_millis(99_500);
    assert_eq!(
        duration_until_expiry(100, half_second_before),
        Some(Duration::from_millis(500))
    );
    assert_eq!(
        duration_until_expiry(-1, half_second_before),
        Some(Duration::ZERO)
    );
    assert!(!session_expired_at(Some(100), half_second_before));
    assert!(session_expired_at(
        Some(100),
        UNIX_EPOCH + Duration::from_secs(100)
    ));
    assert!(session_expired_at(Some(-1), UNIX_EPOCH));
    assert!(!session_expired_at(None, UNIX_EPOCH));
}
