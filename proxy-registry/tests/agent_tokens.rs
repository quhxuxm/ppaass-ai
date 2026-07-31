use proxy_registry::{
    AGENT_ACCESS_TOKEN_TTL_SECONDS, AGENT_PROFILE_REFRESH_SECONDS, AgentAccessTokenClaims,
    AgentAccessTokenError, AgentAccessTokenService,
};

const MASTER_SECRET: &str = "test-only-agent-token-secret-with-32-bytes";

#[test]
fn profile_refresh_interval_keeps_permission_changes_prompt() {
    assert_eq!(AGENT_PROFILE_REFRESH_SECONDS, 60);
}

#[test]
fn token_survives_service_recreation_and_rejects_tampering() {
    let service = AgentAccessTokenService::new(MASTER_SECRET).unwrap();
    let issued = service.issue_at("acc_alice", 1_000).unwrap();
    let recreated = AgentAccessTokenService::new(MASTER_SECRET).unwrap();
    assert_eq!(
        recreated.verify_at(&issued.token, 1_001).unwrap(),
        AgentAccessTokenClaims {
            account_id: "acc_alice".to_string(),
            expires_at: 1_000 + AGENT_ACCESS_TOKEN_TTL_SECONDS,
        }
    );

    let mut tampered = issued.token.into_bytes();
    let last = tampered.last_mut().unwrap();
    *last = if *last == b'A' { b'B' } else { b'A' };
    assert!(
        recreated
            .verify_at(std::str::from_utf8(&tampered).unwrap(), 1_001)
            .is_err()
    );
}

#[test]
fn token_expires_and_another_master_secret_cannot_read_it() {
    let service = AgentAccessTokenService::new(MASTER_SECRET).unwrap();
    let issued = service.issue_at("acc_alice", 1_000).unwrap();
    assert!(matches!(
        service.verify_at(&issued.token, issued.expires_at),
        Err(AgentAccessTokenError::Expired)
    ));
    let other = AgentAccessTokenService::new("different-agent-token-secret-with-32-bytes").unwrap();
    assert!(other.verify_at(&issued.token, 1_001).is_err());
}
