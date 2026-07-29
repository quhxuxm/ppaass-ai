use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use protocol::AuthFailureCode;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::debug;

/// An authentication failure asserted by the pinned Proxy identity.
///
/// This error is only constructed after verifying a signature that binds the
/// current Agent authentication request, the stable code and the message.
/// Callers may downcast the inner error of [`std::io::Error`] to this type.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("Proxy authentication failed for {username} ({code:?}): {message}")]
pub struct AuthenticationFailure {
    pub(super) username: String,
    pub(super) code: AuthFailureCode,
    pub(super) message: String,
}

impl AuthenticationFailure {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn code(&self) -> AuthFailureCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Current Proxy account status established by a pinned, signed TCP
/// authentication response.
///
/// Consumers should use this only for status display. Agent connectivity and
/// stored credentials remain active so a later successful authentication can
/// recover automatically after an administrator renews the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedProxyAuthStatus {
    Active { username: String },
    UserExpired { username: String },
    UserDisabled { username: String },
}

impl VerifiedProxyAuthStatus {
    pub fn username(&self) -> &str {
        match self {
            Self::Active { username }
            | Self::UserExpired { username }
            | Self::UserDisabled { username } => username,
        }
    }
}

const VERIFIED_AUTH_STATUS_CHANNEL_CAPACITY: usize = 32;
static VERIFIED_AUTH_STATUSES: OnceLock<broadcast::Sender<VerifiedProxyAuthStatus>> =
    OnceLock::new();
static VERIFIED_AUTH_STATUS_ORDERING: OnceLock<Mutex<VerifiedAuthStatusOrdering>> = OnceLock::new();

#[derive(Default)]
struct VerifiedAuthStatusOrdering {
    next_sequence: u128,
    users: HashMap<String, UserAuthStatusOrdering>,
}

#[derive(Default)]
struct UserAuthStatusOrdering {
    active_attempts: usize,
    max_published_sequence: Option<u128>,
}

pub(super) struct VerifiedAuthAttempt {
    username: String,
    sequence: u128,
}

impl VerifiedAuthAttempt {
    pub(super) fn begin(username: String) -> Self {
        let mut ordering = lock_verified_auth_status_ordering();
        let sequence = ordering.next_sequence;
        // A process cannot perform 2^128 authentication attempts during its
        // lifetime, so exhaustion indicates an internal invariant violation.
        ordering.next_sequence = ordering
            .next_sequence
            .checked_add(1)
            .expect("verified authentication attempt sequence exhausted");
        let user = ordering.users.entry(username.clone()).or_default();
        // Every live attempt owns memory and a future, so usize concurrent
        // attempts cannot be reached before the process exhausts resources.
        user.active_attempts = user
            .active_attempts
            .checked_add(1)
            .expect("active authentication attempt count exhausted");
        Self { username, sequence }
    }

    pub(super) fn publish(&self, status: VerifiedProxyAuthStatus) -> bool {
        debug_assert_eq!(status.username(), self.username);
        let mut ordering = lock_verified_auth_status_ordering();
        let Some(user) = ordering.users.get_mut(&self.username) else {
            debug_assert!(false, "authentication attempt ordering state is missing");
            return false;
        };
        if user
            .max_published_sequence
            .is_some_and(|published| self.sequence < published)
        {
            debug!(
                username = %self.username,
                attempt_sequence = self.sequence,
                max_published_sequence = ?user.max_published_sequence,
                "忽略晚于新认证结果返回的旧认证状态"
            );
            return false;
        }
        user.max_published_sequence = Some(self.sequence);
        // Keep ordering validation and broadcast publication in the same
        // critical section so receivers observe the same sequence ordering.
        let _ = verified_auth_status_sender().send(status);
        true
    }
}

impl Drop for VerifiedAuthAttempt {
    fn drop(&mut self) {
        let mut ordering = lock_verified_auth_status_ordering();
        let remove_user = if let Some(user) = ordering.users.get_mut(&self.username) {
            debug_assert!(user.active_attempts > 0);
            user.active_attempts = user.active_attempts.saturating_sub(1);
            user.active_attempts == 0
        } else {
            debug_assert!(false, "authentication attempt ordering state is missing");
            false
        };
        if remove_user {
            // No older attempt remains that could publish late. A future
            // attempt receives a greater process-wide sequence, so retaining
            // inactive usernames is unnecessary.
            ordering.users.remove(&self.username);
        }
    }
}

fn verified_auth_status_ordering() -> &'static Mutex<VerifiedAuthStatusOrdering> {
    VERIFIED_AUTH_STATUS_ORDERING.get_or_init(|| Mutex::new(VerifiedAuthStatusOrdering::default()))
}

fn lock_verified_auth_status_ordering() -> std::sync::MutexGuard<'static, VerifiedAuthStatusOrdering>
{
    verified_auth_status_ordering()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn verified_auth_status_sender() -> &'static broadcast::Sender<VerifiedProxyAuthStatus> {
    VERIFIED_AUTH_STATUSES.get_or_init(|| {
        let (sender, _) = broadcast::channel(VERIFIED_AUTH_STATUS_CHANNEL_CAPACITY);
        sender
    })
}

/// Subscribe to account status established with the configured pinned Proxy
/// transport identity.
///
/// No event is emitted for network errors, unsigned responses, invalid
/// signatures, or signed non-terminal `Other` failures.
pub fn subscribe_verified_proxy_auth_statuses() -> broadcast::Receiver<VerifiedProxyAuthStatus> {
    verified_auth_status_sender().subscribe()
}

/// Extract a verified authentication failure code from the `io::Error`
/// returned directly by [`AuthenticatedConnection::authenticate_stream`].
pub fn auth_failure_code(error: &std::io::Error) -> Option<AuthFailureCode> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<AuthenticationFailure>())
        .map(AuthenticationFailure::code)
}

pub(super) fn publish_verified_failure_status(
    attempt: &VerifiedAuthAttempt,
    failure: &AuthenticationFailure,
) {
    let status = match failure.code {
        AuthFailureCode::UserExpired => VerifiedProxyAuthStatus::UserExpired {
            username: failure.username.clone(),
        },
        AuthFailureCode::UserDisabled => VerifiedProxyAuthStatus::UserDisabled {
            username: failure.username.clone(),
        },
        AuthFailureCode::Other => return,
    };
    attempt.publish(status);
}

pub(super) fn publish_verified_active_status(attempt: &VerifiedAuthAttempt, username: &str) {
    attempt.publish(VerifiedProxyAuthStatus::Active {
        username: username.to_string(),
    });
}
