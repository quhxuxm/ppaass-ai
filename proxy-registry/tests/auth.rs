use axum::http::{HeaderMap, HeaderValue, header};
use proxy_registry::{
    PasswordError, PasswordService, SessionStore, session_token, validate_password,
};

const SESSION_TTL_SECONDS: i64 = 12 * 60 * 60;

#[tokio::test]
async fn hashes_and_verifies_passwords_without_plaintext_storage() {
    let passwords = PasswordService::new(1).await.unwrap();
    let encoded = passwords
        .hash_password("correct horse battery staple".to_string())
        .await
        .unwrap();
    assert!(encoded.starts_with("$argon2id$"));
    assert!(!encoded.contains("correct horse"));
    assert!(
        passwords
            .verify_password(
                "correct horse battery staple".to_string(),
                Some(encoded.clone())
            )
            .await
            .unwrap()
    );
    assert!(
        !passwords
            .verify_password("wrong password".to_string(), Some(encoded))
            .await
            .unwrap()
    );
    assert!(
        !passwords
            .verify_password("anything".to_string(), None)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn password_hashing_enforces_the_eight_character_minimum() {
    let passwords = PasswordService::new(1).await.unwrap();
    assert!(matches!(
        passwords.hash_password("1234567".to_string()).await,
        Err(PasswordError::TooShort)
    ));

    let encoded = passwords
        .hash_password("12345678".to_string())
        .await
        .unwrap();
    assert!(
        passwords
            .verify_password("12345678".to_string(), Some(encoded))
            .await
            .unwrap()
    );
}

#[test]
fn password_minimum_counts_unicode_characters_instead_of_utf8_bytes() {
    assert!(matches!(
        validate_password("一二三四五六七"),
        Err(PasswordError::TooShort)
    ));
    assert!(validate_password("一二三四五六七八").is_ok());
}

#[test]
fn parses_cookie_without_matching_prefixes() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("other=1; ppaass_session=expected; suffix=2"),
    );
    assert_eq!(session_token(&headers), Some("expected"));
}

#[test]
fn session_store_evicts_oldest_sessions_at_account_and_global_limits() {
    let sessions = SessionStore::with_limits(false, 3, 2);
    let (alice_one, _) = sessions.issue_at("alice", 1, 1_000);
    let (alice_two, _) = sessions.issue_at("alice", 1, 1_001);
    let (alice_three, _) = sessions.issue_at("alice", 1, 1_002);
    assert!(!sessions.is_active(&alice_one));
    assert!(sessions.is_active(&alice_two));
    assert!(sessions.is_active(&alice_three));

    let (bob_one, _) = sessions.issue_at("bob", 1, 1_003);
    let (bob_two, _) = sessions.issue_at("bob", 1, 1_004);
    assert_eq!(sessions.active_session_count(), 3);
    assert!(!sessions.is_active(&alice_two));
    assert!(sessions.is_active(&alice_three));
    assert!(sessions.is_active(&bob_one));
    assert!(sessions.is_active(&bob_two));
}

#[test]
fn session_store_prunes_expired_entries_before_capacity_eviction() {
    let sessions = SessionStore::with_limits(false, 2, 2);
    let (expired, _) = sessions.issue_at("alice", 1, 0);
    let (current, _) = sessions.issue_at("bob", 1, SESSION_TTL_SECONDS + 1);
    assert!(!sessions.is_active(&expired));
    assert!(sessions.is_active(&current));
    assert_eq!(sessions.active_session_count(), 1);
}
