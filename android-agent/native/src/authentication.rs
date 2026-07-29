use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use common::VerifiedProxyAuthStatus;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

pub(crate) const AUTHENTICATION_UNCONFIRMED: u8 = 0;
pub(crate) const AUTHENTICATION_USER_EXPIRED: u8 = 1;
pub(crate) const AUTHENTICATION_USER_DISABLED: u8 = 2;
pub(crate) const AUTHENTICATION_VERIFIED_ACTIVE: u8 = 3;

#[derive(Default)]
pub(crate) struct VerifiedAuthenticationState {
    status: AtomicU8,
}

impl VerifiedAuthenticationState {
    pub(crate) fn status(&self) -> u8 {
        self.status.load(Ordering::Acquire)
    }

    fn record(&self, expected_username: &str, status: &VerifiedProxyAuthStatus) {
        let next_status = match status {
            VerifiedProxyAuthStatus::Active { .. } => AUTHENTICATION_VERIFIED_ACTIVE,
            VerifiedProxyAuthStatus::UserExpired { .. } => AUTHENTICATION_USER_EXPIRED,
            VerifiedProxyAuthStatus::UserDisabled { .. } => AUTHENTICATION_USER_DISABLED,
        };
        self.record_status_for_username(expected_username, status.username(), next_status);
    }

    fn record_status_for_username(
        &self,
        expected_username: &str,
        status_username: &str,
        next_status: u8,
    ) {
        if status_username != expected_username {
            debug!(
                expected_username,
                status_username,
                "Ignoring a verified Proxy authentication status for another Agent login"
            );
            return;
        }
        let previous_status = self.status.swap(next_status, Ordering::AcqRel);
        if previous_status != next_status {
            warn!(
                previous_status,
                next_status, "Proxy identity confirmed a new Android Agent account status"
            );
        }
    }
}

pub(crate) async fn monitor_verified_authentication_statuses(
    state: Arc<VerifiedAuthenticationState>,
    expected_username: String,
    mut statuses: broadcast::Receiver<VerifiedProxyAuthStatus>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            received = statuses.recv() => match received {
                Ok(status) => state.record(&expected_username, &status),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        skipped,
                        "Android Agent authentication monitor lagged behind verified Proxy statuses"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
    debug!("Android Agent verified authentication monitor stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
