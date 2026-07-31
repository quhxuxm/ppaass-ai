use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use common::VerifiedProxyAuthStatus;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

pub const AUTHENTICATION_UNCONFIRMED: u8 = 0;
pub const AUTHENTICATION_USER_EXPIRED: u8 = 1;
pub const AUTHENTICATION_USER_DISABLED: u8 = 2;
pub const AUTHENTICATION_VERIFIED_ACTIVE: u8 = 3;

#[derive(Default)]
pub struct VerifiedAuthenticationState {
    status: AtomicU8,
}

impl VerifiedAuthenticationState {
    pub fn status(&self) -> u8 {
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

    #[doc(hidden)]
    pub fn record_status_for_username(
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
                next_status, "Proxy reported a new Android Agent account status"
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
