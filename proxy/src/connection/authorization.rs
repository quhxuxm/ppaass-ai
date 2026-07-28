//! 已认证连接的持续授权上下文。
//!
//! 握手只证明连接建立时持有对应私钥。SQLite 用户随后可能被停用、撤权、
//! 提前过期或轮换密钥，因此 active relay 还必须周期性重验。

use super::*;
use crate::user_manager::UserManager;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

const MIN_AUTHORIZATION_RECHECK_SECS: u64 = 1;
const MAX_AUTHORIZATION_RECHECK_SECS: u64 = 5;

#[derive(Clone)]
pub(crate) struct ConnectionAuthorization {
    user_manager: Arc<UserManager>,
    username: String,
    authenticated_public_key_pem: String,
    authenticated_key_version: Option<i64>,
    authenticated_expires_at: Option<i64>,
}

impl ConnectionAuthorization {
    pub(crate) fn new(user_manager: Arc<UserManager>, user: &UserConfig) -> Result<Self> {
        Ok(Self {
            user_manager,
            username: user.username.clone(),
            authenticated_public_key_pem: user.public_key_pem.clone(),
            authenticated_key_version: user.key_version,
            authenticated_expires_at: user.expires_at_unix_timestamp()?,
        })
    }

    pub(crate) async fn validate(&self, permission: &str) -> Result<()> {
        let user = self
            .user_manager
            .get_user(&self.username)
            .await?
            .ok_or_else(|| {
                ProxyError::Authentication("Authenticated user no longer exists".to_string())
            })?;

        if user.username != self.username {
            return Err(ProxyError::Authentication(
                "Authenticated username changed".to_string(),
            ));
        }
        if user.public_key_pem != self.authenticated_public_key_pem {
            return Err(ProxyError::Authentication(
                "Authenticated user key was rotated".to_string(),
            ));
        }
        // SQLite 的 key_version 单调递增。除公钥内容比较外再比较版本，可防止
        // key A -> key B -> key A 后旧连接因 PEM 内容相同而重新获得授权（ABA）。
        if let Some(authenticated_key_version) = self.authenticated_key_version
            && user.key_version != Some(authenticated_key_version)
        {
            return Err(ProxyError::Authentication(
                "Authenticated user key version changed".to_string(),
            ));
        }
        if !user.enabled {
            return Err(ProxyError::Authentication(
                "Authenticated user was disabled".to_string(),
            ));
        }
        if !user.has_permission(permission) {
            return Err(ProxyError::Authentication(format!(
                "Permission denied: {permission}"
            )));
        }
        if user.is_expired_at(common::current_timestamp())? {
            return Err(ProxyError::Authentication(
                "Authenticated user expired".to_string(),
            ));
        }
        Ok(())
    }

    /// 守护一条 active relay。该 future 正常情况下不会成功返回；绝对过期或
    /// 周期重验失败时返回错误，relay 的外层 biased select 会立即关闭连接。
    pub(crate) async fn enforce(&self, permission: &'static str, recheck_secs: u64) -> Result<()> {
        let period = Duration::from_secs(recheck_secs.clamp(
            MIN_AUTHORIZATION_RECHECK_SECS,
            MAX_AUTHORIZATION_RECHECK_SECS,
        ));
        let mut recheck = tokio::time::interval_at(Instant::now() + period, period);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let absolute_expiry = wait_until_expired(self.authenticated_expires_at);
        tokio::pin!(absolute_expiry);

        loop {
            tokio::select! {
                biased;
                _ = &mut absolute_expiry => {
                    return Err(ProxyError::Authentication(
                        "Authenticated connection expired".to_string(),
                    ));
                }
                _ = recheck.tick() => {
                    // DAO 查询本身也可能等待；绝对 expiry 不能因为一次慢查询被推迟。
                    let validation = self.validate(permission);
                    tokio::pin!(validation);
                    tokio::select! {
                        biased;
                        _ = &mut absolute_expiry => {
                            return Err(ProxyError::Authentication(
                                "Authenticated connection expired".to_string(),
                            ));
                        }
                        result = &mut validation => result?,
                    }
                }
            }
        }
    }
}

impl ServerConnection {
    pub(super) fn authorization_context(&self) -> Result<ConnectionAuthorization> {
        self.authorization.clone().ok_or_else(|| {
            ProxyError::Authentication(
                "Authenticated connection is missing authorization context".to_string(),
            )
        })
    }

    pub(super) async fn validate_authorization(&self, permission: &'static str) -> Result<()> {
        self.authorization_context()?.validate(permission).await
    }

    pub(super) fn authorization_recheck_secs(&self) -> u64 {
        self.proxy_config
            .udp_session_authorization_recheck_secs
            .clamp(
                MIN_AUTHORIZATION_RECHECK_SECS,
                MAX_AUTHORIZATION_RECHECK_SECS,
            )
    }
}

async fn wait_until_expired(expires_at: Option<i64>) {
    let Some(expires_at) = expires_at else {
        std::future::pending::<()>().await;
        return;
    };
    let delay = duration_until_expiry(expires_at, SystemTime::now());
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

fn duration_until_expiry(expires_at: i64, now: SystemTime) -> Duration {
    let Ok(expires_at) = u64::try_from(expires_at) else {
        return Duration::ZERO;
    };
    let Some(deadline) = UNIX_EPOCH.checked_add(Duration::from_secs(expires_at)) else {
        return Duration::MAX;
    };
    deadline.duration_since(now).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PERMISSION_PROXY_CONNECT_TCP;
    use protocol::RsaKeyPair;
    use proxy_user_store::{SqliteUserRepository, UserRepository, UserUpdate};
    use tempfile::TempDir;

    #[tokio::test]
    async fn absolute_expiry_closes_idle_sqlite_connection() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
                .await
                .unwrap(),
        );
        let expires_at = common::current_timestamp() + 30;
        let public_key = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        store
            .create_user("alice", &public_key, Some(expires_at))
            .await
            .unwrap();
        let manager = Arc::new(UserManager::new(store as Arc<dyn UserRepository>));
        let user = manager.get_user("alice").await.unwrap().unwrap();
        let authorization = ConnectionAuthorization::new(manager, &user).unwrap();

        tokio::time::pause();
        let guard =
            tokio::spawn(
                async move { authorization.enforce(PERMISSION_PROXY_CONNECT_TCP, 5).await },
            );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(!guard.is_finished());

        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(guard.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn sqlite_key_version_rejects_public_key_aba() {
        let directory = TempDir::new().unwrap();
        let database_path = directory.path().join("users.sqlite3");
        let store = Arc::new(SqliteUserRepository::connect(&database_path).await.unwrap());
        let manager = Arc::new(UserManager::new(store.clone() as Arc<dyn UserRepository>));
        let public_key_a = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        let public_key_b = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        let created = store
            .create_user("alice", &public_key_a, Some(i64::MAX))
            .await
            .unwrap();
        let user = manager.get_user("alice").await.unwrap().unwrap();
        let authorization = ConnectionAuthorization::new(manager, &user).unwrap();

        store
            .update_user(
                "alice",
                UserUpdate {
                    public_key_pem: Some(public_key_b),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        store
            .update_user(
                "alice",
                UserUpdate {
                    public_key_pem: Some(created.public_key_pem),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();

        assert!(
            authorization
                .validate(PERMISSION_PROXY_CONNECT_TCP)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn periodic_recheck_closes_disabled_connection_within_five_seconds() {
        let directory = TempDir::new().unwrap();
        let database_path = directory.path().join("users.sqlite3");
        let store = Arc::new(SqliteUserRepository::connect(&database_path).await.unwrap());
        let manager = Arc::new(UserManager::new(store.clone() as Arc<dyn UserRepository>));
        let public_key = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        store
            .create_user("alice", &public_key, Some(i64::MAX))
            .await
            .unwrap();
        let user = manager.get_user("alice").await.unwrap().unwrap();
        let authorization = ConnectionAuthorization::new(manager, &user).unwrap();

        // 模拟 ConnectSuccess 刚发送后管理员停用账号。guard 的周期不受 relay
        // activity/idle timer 影响，最迟第五秒独立唤醒并关闭。
        store
            .update_user(
                "alice",
                UserUpdate {
                    enabled: Some(false),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        tokio::time::pause();
        let guard =
            tokio::spawn(
                async move { authorization.enforce(PERMISSION_PROXY_CONNECT_TCP, 5).await },
            );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(!guard.is_finished());

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(guard.await.unwrap().is_err());
    }
}
