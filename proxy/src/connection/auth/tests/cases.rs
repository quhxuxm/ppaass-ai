use super::*;

#[tokio::test]
async fn forged_proof_cannot_distinguish_active_disabled_or_expired_users() {
    let legitimate_key = RsaKeyPair::generate(2048).unwrap();
    let attacker_key = RsaKeyPair::generate(2048).unwrap();
    let user_public_key = legitimate_key.public_key_to_pem().unwrap();
    let transport_identity = Arc::new(RsaKeyPair::generate(2048).unwrap());
    let proxy_config = test_proxy_config();
    let (_directory, user_manager) = test_user_manager().await;
    let now = common::current_timestamp();
    let users = [
        user_config(&user_public_key, true, None),
        user_config(&user_public_key, false, None),
        user_config(&user_public_key, true, Some(now - 1)),
    ];

    for (index, user) in users.into_iter().enumerate() {
        let request = auth_request("alice", now, index as u8 + 1, &attacker_key);
        let (result, response) = authenticate_request(
            request,
            user,
            proxy_config.clone(),
            user_manager.clone(),
            transport_identity.clone(),
        )
        .await;

        assert!(matches!(
            result,
            Err(ProxyError::Authentication(ref message))
                if message == "Invalid authentication proof"
        ));
        assert_unsigned_generic_failure(&response);
    }
}

#[tokio::test]
async fn unknown_user_receives_only_the_same_unsigned_generic_failure() {
    let attacker_key = RsaKeyPair::generate(2048).unwrap();
    let transport_identity = Arc::new(RsaKeyPair::generate(2048).unwrap());
    let (_directory, user_manager) = test_user_manager().await;
    let request = auth_request(
        "missing-user",
        common::current_timestamp(),
        10,
        &attacker_key,
    );

    let response = send_unknown_user_failure(
        request,
        test_proxy_config(),
        user_manager,
        transport_identity,
    )
    .await;
    assert_unsigned_generic_failure(&response);
}

#[tokio::test]
async fn expired_challenge_cannot_distinguish_user_state() {
    let user_key = RsaKeyPair::generate(2048).unwrap();
    let user_public_key = user_key.public_key_to_pem().unwrap();
    let transport_identity = Arc::new(RsaKeyPair::generate(2048).unwrap());
    let proxy_config = test_proxy_config();
    let (_directory, user_manager) = test_user_manager().await;
    let now = common::current_timestamp();
    let stale_timestamp = now - proxy_config.replay_attack_tolerance - 1;
    let users = [
        user_config(&user_public_key, true, None),
        user_config(&user_public_key, false, None),
        user_config(&user_public_key, true, Some(now - 1)),
    ];

    for (index, user) in users.into_iter().enumerate() {
        let request = auth_request("alice", stale_timestamp, index as u8 + 11, &user_key);
        let (result, response) = authenticate_request(
            request,
            user,
            proxy_config.clone(),
            user_manager.clone(),
            transport_identity.clone(),
        )
        .await;

        assert!(matches!(
            result,
            Err(ProxyError::Authentication(ref message))
                if message == "Timestamp expired"
        ));
        assert_unsigned_generic_failure(&response);
    }
}

#[tokio::test]
async fn replayed_terminal_request_receives_only_unsigned_generic_failure() {
    let user_key = RsaKeyPair::generate(2048).unwrap();
    let user_public_key = user_key.public_key_to_pem().unwrap();
    let transport_identity = Arc::new(RsaKeyPair::generate(2048).unwrap());
    let proxy_public_key_pem = transport_identity.public_key_to_pem().unwrap();
    let proxy_config = test_proxy_config();
    let (_directory, user_manager) = test_user_manager().await;
    let request = auth_request("alice", common::current_timestamp(), 20, &user_key);
    let disabled_user = user_config(&user_public_key, false, None);

    let (first_result, first_response) = authenticate_request(
        request.clone(),
        disabled_user.clone(),
        proxy_config.clone(),
        user_manager.clone(),
        transport_identity.clone(),
    )
    .await;
    assert!(matches!(
        first_result,
        Err(ProxyError::Authentication(ref message)) if message == "User disabled"
    ));
    assert_signed_failure(
        &request,
        &first_response,
        &proxy_public_key_pem,
        AuthFailureCode::UserDisabled,
        "User disabled",
    );

    let (replay_result, replay_response) = authenticate_request(
        request,
        disabled_user,
        proxy_config,
        user_manager,
        transport_identity,
    )
    .await;
    assert!(matches!(
        replay_result,
        Err(ProxyError::Authentication(ref message))
            if message == "Authentication request replayed"
    ));
    assert_unsigned_generic_failure(&replay_response);
}

#[tokio::test]
async fn valid_proof_receives_signed_account_status() {
    let user_key = RsaKeyPair::generate(2048).unwrap();
    let user_public_key = user_key.public_key_to_pem().unwrap();
    let transport_identity = Arc::new(RsaKeyPair::generate(2048).unwrap());
    let proxy_public_key_pem = transport_identity.public_key_to_pem().unwrap();
    let proxy_config = test_proxy_config();
    let (_directory, user_manager) = test_user_manager().await;
    let now = common::current_timestamp();

    for (nonce_marker, user, expected_code, expected_message) in [
        (
            21,
            user_config(&user_public_key, false, None),
            AuthFailureCode::UserDisabled,
            "User disabled",
        ),
        (
            22,
            user_config(&user_public_key, true, Some(now - 1)),
            AuthFailureCode::UserExpired,
            "User expired",
        ),
    ] {
        let request = auth_request("alice", now, nonce_marker, &user_key);
        let (result, response) = authenticate_request(
            request.clone(),
            user,
            proxy_config.clone(),
            user_manager.clone(),
            transport_identity.clone(),
        )
        .await;

        assert!(result.is_err());
        assert_signed_failure(
            &request,
            &response,
            &proxy_public_key_pem,
            expected_code,
            expected_message,
        );
    }

    let active_request = auth_request("alice", now, 23, &user_key);
    let (result, response) = authenticate_request(
        active_request,
        user_config(&user_public_key, true, None),
        proxy_config,
        user_manager,
        transport_identity,
    )
    .await;
    result.unwrap();
    assert!(response.success);
    assert_eq!(response.failure_code, None);
}
