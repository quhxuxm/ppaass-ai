use protocol::{AuthConnectResponse, AuthFailureCode};
use proxy_entry::connection::{GENERIC_AUTH_FAILURE_MESSAGE, terminal_auth_failure_response};

#[test]
fn terminal_failures_only_expose_verified_account_state() {
    for (code, message) in [
        (AuthFailureCode::UserExpired, "User expired"),
        (AuthFailureCode::UserDisabled, "User disabled"),
    ] {
        let response = terminal_auth_failure_response(code, message).unwrap();
        assert!(!response.success);
        assert_eq!(response.failure_code, Some(code));
        response.validate_shape().unwrap();
    }
    assert!(
        terminal_auth_failure_response(AuthFailureCode::Other, GENERIC_AUTH_FAILURE_MESSAGE)
            .is_err()
    );
}

#[test]
fn generic_auth_connect_failure_carries_no_session_material() {
    let response = AuthConnectResponse::failure(GENERIC_AUTH_FAILURE_MESSAGE);
    assert_eq!(response.failure_code, None);
    response.validate_shape().unwrap();
}
