use super::client::{RemoteControlPlane, control_status_error};
use crate::error::{ProxyError, Result};
use proxy_control_protocol::{
    AUTHORIZATION_SNAPSHOT_PATH, AuthorizationSnapshotQuery, AuthorizationSnapshotResponse,
    MAX_AUTHORIZATION_SNAPSHOT_ENTRIES, MAX_AUTHORIZATION_SNAPSHOT_LIMIT,
};
use reqwest::{StatusCode, header};
use std::{sync::atomic::Ordering, time::Duration};
const SNAPSHOT_LIMIT: u16 = MAX_AUTHORIZATION_SNAPSHOT_LIMIT;
const MAX_SNAPSHOT_PAGES: usize =
    MAX_AUTHORIZATION_SNAPSHOT_ENTRIES.div_ceil(MAX_AUTHORIZATION_SNAPSHOT_LIMIT as usize);
const REVISION_CONFLICT_RETRIES: usize = 3;
enum SyncRoundError {
    RevisionConflict,
    Failed(ProxyError),
}
impl RemoteControlPlane {
    pub async fn refresh_authorizations(&self) -> Result<u64> {
        let _refresh_guard = self.authorization_refresh.lock().await;
        let mut last_error = None;
        for attempt in 0..REVISION_CONFLICT_RETRIES {
            self.authorization_store.clear_staging().await?;
            match self.synchronize_snapshot_round().await {
                Ok(revision) => {
                    self.last_event_id.store(revision, Ordering::Release);
                    return Ok(revision);
                }
                Err(SyncRoundError::RevisionConflict) => {
                    last_error = Some(ProxyError::ControlPlane(
                        "Registry 授权快照分页期间 revision 已变化".to_string(),
                    ));
                    if attempt + 1 < REVISION_CONFLICT_RETRIES {
                        tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
                    }
                }
                Err(SyncRoundError::Failed(error)) => {
                    let _ = self.authorization_store.clear_staging().await;
                    return Err(error);
                }
            }
        }
        let _ = self.authorization_store.clear_staging().await;
        Err(last_error
            .unwrap_or_else(|| ProxyError::ControlPlane("Registry 授权快照同步失败".to_string())))
    }
    async fn synchronize_snapshot_round(&self) -> std::result::Result<u64, SyncRoundError> {
        let mut cursor = None;
        let mut revision = None;
        let mut total_entries = 0_usize;
        for page_number in 1..=MAX_SNAPSHOT_PAGES {
            let response = self.fetch_snapshot_page(cursor.clone(), revision).await?;
            if let Some(expected) = revision {
                if response.revision != expected {
                    return Err(SyncRoundError::RevisionConflict);
                }
            } else {
                revision = Some(response.revision);
            }
            validate_page(&response, cursor.as_deref()).map_err(SyncRoundError::Failed)?;
            total_entries = total_entries
                .checked_add(response.authorizations.len())
                .filter(|total| *total <= MAX_AUTHORIZATION_SNAPSHOT_ENTRIES)
                .ok_or_else(|| {
                    SyncRoundError::Failed(ProxyError::ControlPlane(format!(
                        "Registry 授权快照超过 {MAX_AUTHORIZATION_SNAPSHOT_ENTRIES} 个用户"
                    )))
                })?;
            self.authorization_store
                .stage_page(&response.authorizations)
                .await
                .map_err(SyncRoundError::Failed)?;
            let Some(next_cursor) = response.next_cursor else {
                let revision = revision.expect("首个快照分页必须设置 revision");
                self.authorization_store
                    .activate_staging(revision)
                    .await
                    .map_err(SyncRoundError::Failed)?;
                return Ok(revision);
            };
            if page_number == MAX_SNAPSHOT_PAGES {
                return Err(SyncRoundError::Failed(ProxyError::ControlPlane(format!(
                    "Registry 授权快照分页超过 {MAX_SNAPSHOT_PAGES} 页"
                ))));
            }
            cursor = Some(next_cursor);
        }
        Err(SyncRoundError::Failed(ProxyError::ControlPlane(
            "Registry 授权快照分页未正常结束".to_string(),
        )))
    }
    async fn fetch_snapshot_page(
        &self,
        after_username: Option<String>,
        revision: Option<u64>,
    ) -> std::result::Result<AuthorizationSnapshotResponse, SyncRoundError> {
        let response = self
            .client
            .get(
                self.endpoint(AUTHORIZATION_SNAPSHOT_PATH)
                    .map_err(SyncRoundError::Failed)?,
            )
            .header(header::AUTHORIZATION, self.bearer_value())
            .query(&AuthorizationSnapshotQuery {
                after_username,
                revision,
                limit: Some(SNAPSHOT_LIMIT),
            })
            .send()
            .await
            .map_err(|error| {
                SyncRoundError::Failed(ProxyError::ControlPlane(format!(
                    "获取 Registry 授权快照分页失败：{error}"
                )))
            })?;
        if response.status() == StatusCode::CONFLICT {
            return Err(SyncRoundError::RevisionConflict);
        }
        if response.status() != StatusCode::OK {
            return Err(SyncRoundError::Failed(control_status_error(
                "获取授权快照分页",
                response.status(),
            )));
        }
        response
            .json::<AuthorizationSnapshotResponse>()
            .await
            .map_err(|error| {
                SyncRoundError::Failed(ProxyError::ControlPlane(format!(
                    "Registry 授权快照分页响应无效：{error}"
                )))
            })
    }
}
fn validate_page(response: &AuthorizationSnapshotResponse, after: Option<&str>) -> Result<()> {
    if response.authorizations.len() > SNAPSHOT_LIMIT as usize {
        return Err(ProxyError::ControlPlane(format!(
            "Registry 单页授权超过 {SNAPSHOT_LIMIT} 条"
        )));
    }
    if response.authorizations.is_empty() && response.next_cursor.is_some() {
        return Err(ProxyError::ControlPlane(
            "Registry 空授权分页不能包含 next_cursor".to_string(),
        ));
    }
    if let Some(next_cursor) = response.next_cursor.as_deref() {
        if response.authorizations.len() != SNAPSHOT_LIMIT as usize {
            return Err(ProxyError::ControlPlane(format!(
                "Registry 非末页授权必须包含 {SNAPSHOT_LIMIT} 条"
            )));
        }
        let last_username = response
            .authorizations
            .last()
            .map(|authorization| authorization.username.as_str());
        if last_username != Some(next_cursor) || after == Some(next_cursor) {
            return Err(ProxyError::ControlPlane(
                "Registry 授权分页 next_cursor 未严格前进".to_string(),
            ));
        }
    }
    Ok(())
}
