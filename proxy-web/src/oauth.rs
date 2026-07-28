use axum::http::{HeaderMap, HeaderValue};
use dashmap::DashMap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{env, sync::Arc, time::Duration};
use thiserror::Error;
use url::Url;

use crate::{
    auth::{cookie_value, random_token},
    error::ApiError,
};

const OAUTH_STATE_COOKIE: &str = "ppaass_oauth_state";
const OAUTH_STATE_TTL_SECONDS: i64 = 10 * 60;

#[derive(Clone)]
pub struct OAuthService {
    http: reqwest::Client,
    google: Option<Arc<GoogleConfig>>,
    wechat: Option<Arc<WechatConfig>>,
    pending: Arc<DashMap<String, PendingAuthorization>>,
    secure_cookies: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProvider {
    Google,
    Wechat,
}

impl OAuthProvider {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "google" => Some(Self::Google),
            "wechat" => Some(Self::Wechat),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Wechat => "wechat",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OAuthStart {
    pub authorization_url: String,
    pub state_cookie: HeaderValue,
}

#[derive(Debug, Clone)]
pub struct OAuthIdentity {
    pub provider: String,
    pub subject: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug)]
struct PendingAuthorization {
    provider: OAuthProvider,
    pkce_verifier: Option<String>,
    expires_at: i64,
}

#[derive(Debug, Clone)]
struct GoogleConfig {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

#[derive(Debug, Clone)]
struct WechatConfig {
    app_id: String,
    app_secret: String,
    redirect_uri: String,
}

#[derive(Debug, Error)]
pub enum OAuthConfigError {
    #[error("{provider} OAuth 配置不完整：必须同时设置 {variables}")]
    Partial {
        provider: &'static str,
        variables: &'static str,
    },

    #[error("{provider} OAuth redirect URI 无效")]
    InvalidRedirectUri { provider: &'static str },

    #[error("无法创建 OAuth HTTP 客户端")]
    HttpClient,
}

impl OAuthService {
    pub fn from_env(secure_cookies: bool) -> Result<Self, OAuthConfigError> {
        let google = read_complete_env(
            "Google",
            &[
                "PPAASS_GOOGLE_CLIENT_ID",
                "PPAASS_GOOGLE_CLIENT_SECRET",
                "PPAASS_GOOGLE_REDIRECT_URI",
            ],
        )?
        .map(|values| {
            validate_redirect_uri("Google", &values[2])?;
            Ok::<_, OAuthConfigError>(Arc::new(GoogleConfig {
                client_id: values[0].clone(),
                client_secret: values[1].clone(),
                redirect_uri: values[2].clone(),
            }))
        })
        .transpose()?;

        let wechat = read_complete_env(
            "微信",
            &[
                "PPAASS_WECHAT_APP_ID",
                "PPAASS_WECHAT_APP_SECRET",
                "PPAASS_WECHAT_REDIRECT_URI",
            ],
        )?
        .map(|values| {
            validate_redirect_uri("微信", &values[2])?;
            Ok::<_, OAuthConfigError>(Arc::new(WechatConfig {
                app_id: values[0].clone(),
                app_secret: values[1].clone(),
                redirect_uri: values[2].clone(),
            }))
        })
        .transpose()?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("ppaass-proxy-web/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| OAuthConfigError::HttpClient)?;

        Ok(Self {
            http,
            google,
            wechat,
            pending: Arc::new(DashMap::new()),
            secure_cookies,
        })
    }

    #[cfg(test)]
    pub(crate) fn disabled(secure_cookies: bool) -> Self {
        Self {
            http: reqwest::Client::new(),
            google: None,
            wechat: None,
            pending: Arc::new(DashMap::new()),
            secure_cookies,
        }
    }

    pub const fn local_registration_enabled_default(is_loopback: bool) -> bool {
        is_loopback
    }

    pub fn is_enabled(&self, provider: OAuthProvider) -> bool {
        match provider {
            OAuthProvider::Google => self.google.is_some(),
            OAuthProvider::Wechat => self.wechat.is_some(),
        }
    }

    pub fn start(&self, provider: OAuthProvider) -> Result<OAuthStart, ApiError> {
        self.prune();
        let state = random_token(32);
        let (authorization_url, pkce_verifier) = match provider {
            OAuthProvider::Google => {
                let config = self
                    .google
                    .as_ref()
                    .ok_or_else(|| ApiError::not_found("Google 登录未配置"))?;
                let verifier = random_token(48);
                let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
                let mut url = Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                    .map_err(|_| ApiError::internal())?;
                url.query_pairs_mut()
                    .append_pair("client_id", &config.client_id)
                    .append_pair("redirect_uri", &config.redirect_uri)
                    .append_pair("response_type", "code")
                    .append_pair("scope", "openid email profile")
                    .append_pair("state", &state)
                    .append_pair("code_challenge", &challenge)
                    .append_pair("code_challenge_method", "S256");
                (url.to_string(), Some(verifier))
            }
            OAuthProvider::Wechat => {
                let config = self
                    .wechat
                    .as_ref()
                    .ok_or_else(|| ApiError::not_found("微信登录未配置"))?;
                let mut url = Url::parse("https://open.weixin.qq.com/connect/qrconnect")
                    .map_err(|_| ApiError::internal())?;
                url.query_pairs_mut()
                    .append_pair("appid", &config.app_id)
                    .append_pair("redirect_uri", &config.redirect_uri)
                    .append_pair("response_type", "code")
                    .append_pair("scope", "snsapi_login")
                    .append_pair("state", &state);
                // 微信要求 URL 末尾带 fragment。
                url.set_fragment(Some("wechat_redirect"));
                (url.to_string(), None)
            }
        };
        self.pending.insert(
            state.clone(),
            PendingAuthorization {
                provider,
                pkce_verifier,
                expires_at: unix_timestamp() + OAUTH_STATE_TTL_SECONDS,
            },
        );
        Ok(OAuthStart {
            authorization_url,
            state_cookie: oauth_state_cookie(&state, OAUTH_STATE_TTL_SECONDS, self.secure_cookies),
        })
    }

    pub async fn finish(
        &self,
        provider: OAuthProvider,
        code: &str,
        state: &str,
        headers: &HeaderMap,
    ) -> Result<OAuthIdentity, ApiError> {
        let cookie_state = cookie_value(headers, OAUTH_STATE_COOKIE)
            .ok_or_else(|| ApiError::bad_request("OAuth 状态 Cookie 已失效"))?;
        if cookie_state != state {
            return Err(ApiError::bad_request("OAuth state 校验失败"));
        }
        let (_, pending) = self
            .pending
            .remove(state)
            .ok_or_else(|| ApiError::bad_request("OAuth 登录请求已失效或已使用"))?;
        if pending.expires_at <= unix_timestamp() || pending.provider != provider {
            return Err(ApiError::bad_request("OAuth 登录请求已失效"));
        }
        if code.is_empty() || code.len() > 4096 {
            return Err(ApiError::bad_request("OAuth authorization code 无效"));
        }

        match provider {
            OAuthProvider::Google => {
                self.finish_google(code, pending.pkce_verifier.as_deref())
                    .await
            }
            OAuthProvider::Wechat => self.finish_wechat(code).await,
        }
    }

    pub fn clear_state_cookie(&self) -> HeaderValue {
        oauth_state_cookie("", 0, self.secure_cookies)
    }

    async fn finish_google(
        &self,
        code: &str,
        verifier: Option<&str>,
    ) -> Result<OAuthIdentity, ApiError> {
        let config = self.google.as_ref().ok_or_else(ApiError::internal)?;
        let mut form = vec![
            ("code", code),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ];
        if let Some(verifier) = verifier {
            form.push(("code_verifier", verifier));
        }
        let token: GoogleTokenResponse = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&form)
            .send()
            .await
            .map_err(oauth_upstream)?
            .error_for_status()
            .map_err(oauth_upstream)?
            .json()
            .await
            .map_err(oauth_upstream)?;
        let profile: GoogleUserInfo = self
            .http
            .get("https://openidconnect.googleapis.com/v1/userinfo")
            .bearer_auth(token.access_token)
            .send()
            .await
            .map_err(oauth_upstream)?
            .error_for_status()
            .map_err(oauth_upstream)?
            .json()
            .await
            .map_err(oauth_upstream)?;
        if profile.sub.is_empty() {
            return Err(ApiError::bad_gateway("Google 未返回稳定用户标识"));
        }
        Ok(OAuthIdentity {
            provider: provider_name(OAuthProvider::Google),
            subject: profile.sub,
            display_name: profile.name,
            email: profile.email,
            avatar_url: profile.picture,
        })
    }

    async fn finish_wechat(&self, code: &str) -> Result<OAuthIdentity, ApiError> {
        let config = self.wechat.as_ref().ok_or_else(ApiError::internal)?;
        let token: WechatTokenResponse = self
            .http
            .get("https://api.weixin.qq.com/sns/oauth2/access_token")
            .query(&[
                ("appid", config.app_id.as_str()),
                ("secret", config.app_secret.as_str()),
                ("code", code),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(oauth_upstream)?
            .error_for_status()
            .map_err(oauth_upstream)?
            .json()
            .await
            .map_err(oauth_upstream)?;
        if let Some(error) = token.errcode {
            tracing::warn!(errcode = error, "微信 OAuth token 交换失败");
            return Err(ApiError::bad_gateway("微信登录暂时不可用"));
        }
        let access_token = token
            .access_token
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApiError::bad_gateway("微信未返回 access token"))?;
        let openid = token
            .openid
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApiError::bad_gateway("微信未返回用户标识"))?;
        let profile: WechatUserInfo = self
            .http
            .get("https://api.weixin.qq.com/sns/userinfo")
            .query(&[
                ("access_token", access_token.as_str()),
                ("openid", openid.as_str()),
                ("lang", "zh_CN"),
            ])
            .send()
            .await
            .map_err(oauth_upstream)?
            .error_for_status()
            .map_err(oauth_upstream)?
            .json()
            .await
            .map_err(oauth_upstream)?;
        if let Some(error) = profile.errcode {
            tracing::warn!(errcode = error, "微信 OAuth userinfo 获取失败");
            return Err(ApiError::bad_gateway("微信登录暂时不可用"));
        }
        let subject = profile
            .unionid
            .filter(|value| !value.is_empty())
            .unwrap_or(openid);
        Ok(OAuthIdentity {
            provider: provider_name(OAuthProvider::Wechat),
            subject,
            display_name: profile.nickname,
            email: None,
            avatar_url: profile.headimgurl,
        })
    }

    fn prune(&self) {
        let current = unix_timestamp();
        self.pending
            .retain(|_, pending| pending.expires_at > current);
    }
}

fn provider_name(provider: OAuthProvider) -> String {
    provider.as_str().to_string()
}

fn read_complete_env<const N: usize>(
    provider: &'static str,
    names: &[&'static str; N],
) -> Result<Option<[String; N]>, OAuthConfigError> {
    let values = names.map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()));
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    if values.iter().any(Option::is_none) {
        return Err(OAuthConfigError::Partial {
            provider,
            variables: match provider {
                "Google" => {
                    "PPAASS_GOOGLE_CLIENT_ID、PPAASS_GOOGLE_CLIENT_SECRET、PPAASS_GOOGLE_REDIRECT_URI"
                }
                _ => "PPAASS_WECHAT_APP_ID、PPAASS_WECHAT_APP_SECRET、PPAASS_WECHAT_REDIRECT_URI",
            },
        });
    }
    Ok(Some(
        values.map(|value| value.expect("已经检查所有 OAuth 环境变量")),
    ))
}

fn validate_redirect_uri(
    provider: &'static str,
    redirect_uri: &str,
) -> Result<(), OAuthConfigError> {
    let url =
        Url::parse(redirect_uri).map_err(|_| OAuthConfigError::InvalidRedirectUri { provider })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(OAuthConfigError::InvalidRedirectUri { provider });
    }
    Ok(())
}

fn oauth_state_cookie(state: &str, max_age: i64, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{OAUTH_STATE_COOKIE}={state}; Path=/api/v1/auth/oauth; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
    .expect("OAuth state 是 cookie-safe base64url")
}

fn oauth_upstream(error: reqwest::Error) -> ApiError {
    tracing::warn!(%error, "OAuth 上游请求失败");
    ApiError::bad_gateway("第三方登录服务暂时不可用")
}

fn unix_timestamp() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    sub: String,
    name: Option<String>,
    email: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WechatTokenResponse {
    access_token: Option<String>,
    openid: Option<String>,
    errcode: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct WechatUserInfo {
    nickname: Option<String>,
    headimgurl: Option<String>,
    unionid: Option<String>,
    errcode: Option<i64>,
}

// OAuth PKCE uses base64url without padding as required by RFC 7636.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_are_stable() {
        assert_eq!(OAuthProvider::parse("google"), Some(OAuthProvider::Google));
        assert_eq!(OAuthProvider::parse("wechat"), Some(OAuthProvider::Wechat));
        assert_eq!(OAuthProvider::parse("unknown"), None);
    }

    #[test]
    fn state_cookie_is_http_only_and_same_site() {
        let cookie = oauth_state_cookie("state", 60, true);
        let value = cookie.to_str().unwrap();
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(value.contains("Secure"));
    }
}
