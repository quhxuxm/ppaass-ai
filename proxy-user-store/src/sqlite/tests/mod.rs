use super::*;
use crate::default_proxy_permissions;
use protocol::RsaKeyPair;
use tempfile::TempDir;

pub(super) async fn test_store() -> (TempDir, SqliteUserRepository) {
    let directory = TempDir::new().unwrap();
    let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    (directory, store)
}

pub(super) fn public_key() -> String {
    RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap()
}

pub(super) fn managed_user(
    account_id: &str,
    login_name: &str,
    username: &str,
    role: AccountRole,
    external_identity: Option<ExternalIdentity>,
) -> NewManagedUser {
    NewManagedUser {
        account_id: account_id.to_string(),
        login_name: login_name.to_string(),
        password_hash: Some("$argon2id$test".to_string()),
        role,
        status: AccountStatus::Active,
        display_name: Some(login_name.to_string()),
        email: None,
        avatar_url: None,
        profile: NewUser::new(username, public_key(), UserOrigin::Admin),
        encrypted_private_key: b"encrypted-private-key".to_vec(),
        external_identity,
    }
}

pub(super) fn user_account(account_id: &str, login_name: &str) -> NewUserAccount {
    NewUserAccount {
        account_id: account_id.to_string(),
        login_name: login_name.to_string(),
        password_hash: Some("$argon2id$test".to_string()),
        display_name: Some(login_name.to_string()),
        email: None,
        avatar_url: None,
        external_identity: None,
    }
}

pub(super) async fn create_admin(store: &SqliteUserRepository, account_id: &str) {
    let outcome = store
        .bootstrap_admin_if_absent(NewAdminAccount {
            account_id: account_id.to_string(),
            login_name: account_id.to_string(),
            password_hash: Some("$argon2id$test".to_string()),
            display_name: None,
            email: None,
            avatar_url: None,
        })
        .await
        .unwrap();
    assert!(matches!(outcome, BootstrapOutcome::Created(_)));
}

pub(super) fn initial_approval(
    request_id: &str,
    reviewer_account_id: &str,
    username: &str,
    expires_at: i64,
) -> KeyRequestApproval {
    KeyRequestApproval {
        request_id: request_id.to_string(),
        reviewer_account_id: reviewer_account_id.to_string(),
        expires_at,
        material: ApprovedKeyMaterial::Initial {
            profile: NewUser::new(username, public_key(), UserOrigin::Local),
            encrypted_private_key: b"encrypted-private-key".to_vec(),
        },
    }
}

mod access;
mod account_creation;
mod account_security;
mod device_authorization;
mod key_binding;
mod key_requests;
mod key_requests_admin;
mod migrations;
mod permissions;
mod read_only;
mod users;
