use android_agent::{
    AUTHENTICATION_UNCONFIRMED, AUTHENTICATION_USER_DISABLED, AUTHENTICATION_USER_EXPIRED,
    AUTHENTICATION_VERIFIED_ACTIVE, VerifiedAuthenticationState,
};

#[test]
fn verified_status_can_recover_after_expiration() {
    let state = VerifiedAuthenticationState::default();
    state.record_status_for_username("alice", "alice", AUTHENTICATION_USER_EXPIRED);
    assert_eq!(state.status(), AUTHENTICATION_USER_EXPIRED);
    state.record_status_for_username("alice", "alice", AUTHENTICATION_VERIFIED_ACTIVE);
    assert_eq!(state.status(), AUTHENTICATION_VERIFIED_ACTIVE);
}

#[test]
fn verified_status_for_another_login_is_ignored() {
    let state = VerifiedAuthenticationState::default();
    state.record_status_for_username("new-login", "old-login", AUTHENTICATION_USER_EXPIRED);
    assert_eq!(state.status(), AUTHENTICATION_UNCONFIRMED);

    state.record_status_for_username("new-login", "new-login", AUTHENTICATION_USER_DISABLED);
    assert_eq!(state.status(), AUTHENTICATION_USER_DISABLED);
}
