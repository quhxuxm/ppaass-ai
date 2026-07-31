use std::collections::HashSet;

use proxy_control_protocol::AuthorizationSnapshot;
use sqlx::{Row, sqlite::SqliteRow};

use crate::{
    config::UserConfig,
    error::{ProxyError, Result},
};

pub(super) fn validate_authorizations(authorizations: &[AuthorizationSnapshot]) -> Result<()> {
    let mut usernames = HashSet::with_capacity(authorizations.len());
    for authorization in authorizations {
        if authorization.username.is_empty() {
            return Err(ProxyError::ControlPlane(
                "Registry 授权快照包含空用户名".to_string(),
            ));
        }
        if !usernames.insert(authorization.username.as_str()) {
            return Err(ProxyError::ControlPlane(format!(
                "Registry 授权快照包含重复用户：{}",
                authorization.username
            )));
        }
        validate_key(
            &authorization.username,
            &authorization.public_key_pem,
            authorization.key_version,
        )?;
    }
    Ok(())
}

fn validate_key(username: &str, public_key_pem: &str, key_version: i64) -> Result<()> {
    if key_version < 1 {
        return Err(ProxyError::ControlPlane(format!(
            "Registry 授权快照中的用户 {username} key_version 必须大于等于 1"
        )));
    }
    protocol::RsaKeyPair::from_public_key_pem(public_key_pem).map_err(|error| {
        ProxyError::ControlPlane(format!(
            "Registry 授权快照中的用户 {username} 公钥无效：{error}"
        ))
    })?;
    Ok(())
}

pub(super) fn user_from_row(row: &SqliteRow) -> Result<UserConfig> {
    let username = row.try_get::<String, _>("username").map_err(row_error)?;
    let public_key_pem = row
        .try_get::<String, _>("public_key_pem")
        .map_err(row_error)?;
    let key_version = row.try_get::<i64, _>("key_version").map_err(row_error)?;
    validate_key(&username, &public_key_pem, key_version)?;
    let permissions_json = row
        .try_get::<String, _>("permissions_json")
        .map_err(row_error)?;
    let permissions = serde_json::from_str::<Vec<String>>(&permissions_json).map_err(|error| {
        ProxyError::ControlPlane(format!("本地授权快照中的用户 {username} 权限无效：{error}"))
    })?;
    Ok(UserConfig {
        username,
        public_key_pem,
        expires_at: row
            .try_get::<Option<i64>, _>("expires_at")
            .map_err(row_error)?
            .map(|value| value.to_string()),
        permissions,
        enabled: row.try_get::<bool, _>("enabled").map_err(row_error)?,
        key_version: Some(key_version),
    })
}

fn row_error(error: sqlx::Error) -> ProxyError {
    ProxyError::ControlPlane(format!("本地授权快照行无效：{error}"))
}
