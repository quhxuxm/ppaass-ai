use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use proxy_user_store::{AccountRepository, AccountStatus, WebAccount};
use rand::RngExt;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::warn;
use zeroize::Zeroizing;

use crate::error::ApiError;

pub const SESSION_COOKIE_NAME: &str = "ppaass_session";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const PASSWORD_MIN_CHARS: usize = 8;
const PASSWORD_MAX_BYTES: usize = 256;
const MAX_ACTIVE_SESSIONS: usize = 10_000;
const MAX_SESSIONS_PER_ACCOUNT: usize = 8;

#[derive(Clone)]
pub struct PasswordService {
    semaphore: Arc<Semaphore>,
    dummy_hash: Arc<str>,
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("密码至少需要 {PASSWORD_MIN_CHARS} 个字符")]
    TooShort,

    #[error("密码不能超过 {PASSWORD_MAX_BYTES} 个 UTF-8 字节")]
    TooLong,

    #[error("密码处理任务失败")]
    TaskFailed,

    #[error("密码哈希失败")]
    HashFailed,
}

impl PasswordService {
    pub async fn new(max_parallel_hashes: usize) -> Result<Self, PasswordError> {
        let semaphore = Arc::new(Semaphore::new(max_parallel_hashes.max(1)));
        let service = Self {
            semaphore,
            dummy_hash: Arc::from(""),
        };
        let dummy_hash = service
            .hash_password("dummy-password-never-used".to_string())
            .await?;
        Ok(Self {
            dummy_hash: Arc::from(dummy_hash),
            ..service
        })
    }

    pub async fn hash_password(&self, password: String) -> Result<String, PasswordError> {
        validate_password(&password)?;
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| PasswordError::TaskFailed)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let password = Zeroizing::new(password);
            let mut salt_bytes = [0_u8; 16];
            rand::rng().fill(&mut salt_bytes);
            let salt =
                SaltString::encode_b64(&salt_bytes).map_err(|_| PasswordError::HashFailed)?;
            argon2()
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| PasswordError::HashFailed)
        })
        .await
        .map_err(|_| PasswordError::TaskFailed)?
    }

    /// 即使账号不存在也验证 dummy hash，避免通过响应时间枚举登录名。
    pub async fn verify_password(
        &self,
        password: String,
        expected_hash: Option<String>,
    ) -> Result<bool, PasswordError> {
        if password.len() > PASSWORD_MAX_BYTES {
            return Ok(false);
        }
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| PasswordError::TaskFailed)?;
        let dummy_hash = self.dummy_hash.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let password = Zeroizing::new(password);
            let is_real_hash = expected_hash.is_some();
            let encoded = expected_hash.as_deref().unwrap_or(&dummy_hash);
            let Ok(hash) = PasswordHash::new(encoded) else {
                return false;
            };
            is_real_hash && argon2().verify_password(password.as_bytes(), &hash).is_ok()
        })
        .await
        .map_err(|_| PasswordError::TaskFailed)
    }
}

fn argon2() -> Argon2<'static> {
    // OWASP 的交互式登录基线：约 19 MiB、2 次迭代、单通道 Argon2id。
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("固定 Argon2 参数必须有效");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn validate_password(password: &str) -> Result<(), PasswordError> {
    if password.chars().count() < PASSWORD_MIN_CHARS {
        return Err(PasswordError::TooShort);
    }
    if password.len() > PASSWORD_MAX_BYTES {
        return Err(PasswordError::TooLong);
    }
    Ok(())
}

#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, Session>>,
    issue_lock: Arc<Mutex<()>>,
    next_issue_sequence: Arc<AtomicU64>,
    max_sessions: usize,
    max_sessions_per_account: usize,
    secure_cookies: bool,
}

#[derive(Debug, Clone)]
struct Session {
    account_id: String,
    csrf_token: String,
    expires_at: i64,
    issue_sequence: u64,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub token: String,
    pub account: WebAccount,
    pub csrf_token: String,
    pub expires_at: i64,
}

impl SessionStore {
    pub fn new(secure_cookies: bool) -> Self {
        Self::with_limits(
            secure_cookies,
            MAX_ACTIVE_SESSIONS,
            MAX_SESSIONS_PER_ACCOUNT,
        )
    }

    fn with_limits(
        secure_cookies: bool,
        max_sessions: usize,
        max_sessions_per_account: usize,
    ) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            issue_lock: Arc::new(Mutex::new(())),
            next_issue_sequence: Arc::new(AtomicU64::new(1)),
            max_sessions: max_sessions.max(1),
            max_sessions_per_account: max_sessions_per_account.max(1),
            secure_cookies,
        }
    }

    pub fn issue(&self, account_id: &str) -> (AuthenticatedSessionToken, HeaderValue) {
        self.issue_at(account_id, now())
    }

    fn issue_at(
        &self,
        account_id: &str,
        issued_at: i64,
    ) -> (AuthenticatedSessionToken, HeaderValue) {
        // 只有 issue 会增加集合大小。串行化这一小段内存操作，确保并发成功登录
        // 也绝不会越过全局或单账号硬上限。
        let _issue_guard = self
            .issue_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune_expired_at(issued_at);
        while self.account_session_count(account_id) >= self.max_sessions_per_account {
            let Some(token) = self.oldest_session(Some(account_id)) else {
                break;
            };
            self.sessions.remove(&token);
        }
        while self.sessions.len() >= self.max_sessions {
            let Some(token) = self.oldest_session(None) else {
                break;
            };
            self.sessions.remove(&token);
        }

        let token = random_token(32);
        let csrf_token = random_token(32);
        let expires_at = issued_at + SESSION_TTL.as_secs() as i64;
        let issue_sequence = self.next_issue_sequence.fetch_add(1, Ordering::Relaxed);
        self.sessions.insert(
            token.clone(),
            Session {
                account_id: account_id.to_string(),
                csrf_token: csrf_token.clone(),
                expires_at,
                issue_sequence,
            },
        );
        (
            AuthenticatedSessionToken {
                _token: token.clone(),
                csrf_token,
                expires_at,
            },
            session_cookie(&token, SESSION_TTL, self.secure_cookies),
        )
    }

    pub fn clear(&self, headers: &HeaderMap) -> HeaderValue {
        if let Some(token) = session_token(headers) {
            self.sessions.remove(token);
        }
        clear_session_cookie(self.secure_cookies)
    }

    pub fn revoke_issued(&self, session: &AuthenticatedSessionToken) {
        self.sessions.remove(session._token.as_str());
    }

    pub async fn authenticate(
        &self,
        accounts: &dyn AccountRepository,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedSession, ApiError> {
        let token = session_token(headers).ok_or_else(ApiError::unauthorized)?;
        let Some(session) = self.sessions.get(token).map(|value| value.clone()) else {
            return Err(ApiError::unauthorized());
        };
        if session.expires_at <= now() {
            self.sessions.remove(token);
            return Err(ApiError::unauthorized());
        }
        let account = accounts
            .get_account_by_id(&session.account_id)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        if account.status != AccountStatus::Active {
            self.sessions.remove(token);
            return Err(ApiError::forbidden("账号已停用"));
        }
        Ok(AuthenticatedSession {
            token: token.to_string(),
            account,
            csrf_token: session.csrf_token,
            expires_at: session.expires_at,
        })
    }

    pub fn require_csrf(
        &self,
        session: &AuthenticatedSession,
        headers: &HeaderMap,
    ) -> Result<(), ApiError> {
        let supplied = headers
            .get(CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::forbidden("缺少 CSRF 校验信息"))?;
        if !constant_time_eq(supplied.as_bytes(), session.csrf_token.as_bytes()) {
            warn!(account_id = session.account.account_id, "CSRF 校验失败");
            return Err(ApiError::forbidden("CSRF 校验失败"));
        }
        Ok(())
    }

    fn prune_expired_at(&self, current: i64) {
        self.sessions
            .retain(|_, session| session.expires_at > current);
    }

    fn account_session_count(&self, account_id: &str) -> usize {
        self.sessions
            .iter()
            .filter(|entry| entry.account_id == account_id)
            .count()
    }

    fn oldest_session(&self, account_id: Option<&str>) -> Option<String> {
        self.sessions
            .iter()
            .filter(|entry| account_id.is_none_or(|account_id| entry.account_id == account_id))
            .min_by_key(|entry| entry.issue_sequence)
            .map(|entry| entry.key().clone())
    }

    #[cfg(test)]
    pub(crate) fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSessionToken {
    pub csrf_token: String,
    pub expires_at: i64,
    _token: String,
}

pub fn append_set_cookie(headers: &mut HeaderMap, cookie: HeaderValue) {
    headers.append(header::SET_COOKIE, cookie);
}

fn session_cookie(token: &str, max_age: Duration, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        max_age.as_secs(),
        secure
    ))
    .expect("随机 session token 可安全用于 Cookie")
}

fn clear_session_cookie(secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
    ))
    .expect("固定 Cookie header 必须有效")
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, SESSION_COOKIE_NAME)
}

pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
}

pub fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill(value.as_mut_slice());
    URL_SAFE_NO_PAD.encode(value)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (alice_one, _) = sessions.issue_at("alice", 1_000);
        let (alice_two, _) = sessions.issue_at("alice", 1_001);
        let (alice_three, _) = sessions.issue_at("alice", 1_002);
        assert!(!sessions.sessions.contains_key(&alice_one._token));
        assert!(sessions.sessions.contains_key(&alice_two._token));
        assert!(sessions.sessions.contains_key(&alice_three._token));

        let (bob_one, _) = sessions.issue_at("bob", 1_003);
        let (bob_two, _) = sessions.issue_at("bob", 1_004);
        assert_eq!(sessions.active_session_count(), 3);
        assert!(!sessions.sessions.contains_key(&alice_two._token));
        assert!(sessions.sessions.contains_key(&alice_three._token));
        assert!(sessions.sessions.contains_key(&bob_one._token));
        assert!(sessions.sessions.contains_key(&bob_two._token));
    }

    #[test]
    fn session_store_prunes_expired_entries_before_capacity_eviction() {
        let sessions = SessionStore::with_limits(false, 2, 2);
        let (expired, _) = sessions.issue_at("alice", 0);
        let (current, _) = sessions.issue_at("bob", SESSION_TTL.as_secs() as i64 + 1);
        assert!(!sessions.sessions.contains_key(&expired._token));
        assert!(sessions.sessions.contains_key(&current._token));
        assert_eq!(sessions.active_session_count(), 1);
    }
}
