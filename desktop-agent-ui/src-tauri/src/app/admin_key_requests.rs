use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri_plugin_notification::NotificationExt;

use super::*;

const ADMIN_KEY_REQUEST_POLL_SECONDS: u64 = 60;
const MAX_APPROVAL_PROXY_ADDRESSES: usize = 128;

pub(crate) fn start_agent_admin_key_request_polling(
    app: tauri::AppHandle,
    runtime: Arc<AgentRuntime>,
) {
    tauri::async_runtime::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(ADMIN_KEY_REQUEST_POLL_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = runtime.admin_key_request_poll_notify.notified() => {}
            }
            if let Err(error) = poll_agent_admin_key_requests_once(&app, &runtime).await {
                warn!("{error}");
                runtime.logs.push(error);
            }
        }
    });
}

#[tauri::command]
pub(crate) fn get_agent_admin_key_request_inbox(
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentAdminKeyRequestInbox, String> {
    if active_admin_session(runtime.inner())?.is_none() {
        runtime.clear_admin_key_request_inbox()?;
    }
    runtime.admin_key_request_inbox()
}

#[tauri::command]
pub(crate) async fn refresh_agent_admin_key_requests(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
) -> Result<AgentAdminKeyRequestInbox, String> {
    poll_agent_admin_key_requests_once(&app, runtime.inner())
        .await
        .map(|update| update.inbox)
}

#[tauri::command]
pub(crate) async fn approve_agent_admin_key_request_command(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    request: AgentAdminKeyRequestApproval,
) -> Result<AgentAdminKeyRequestInbox, String> {
    validate_approval(&request, runtime.inner())?;
    let session = require_active_admin_session(runtime.inner())?;
    let token = session
        .agent_access_token
        .as_ref()
        .ok_or_else(|| "管理员 Agent 审批凭据缺失，请重新登录".to_string())?;
    let result = approve_agent_admin_key_request(
        &session.proxy_web_url,
        token.value.as_str(),
        &request.request_id,
        request.expires_at,
        &request.proxy_address_ids,
    )
    .await;
    finish_decision(
        &app,
        runtime.inner(),
        &request.request_id,
        result,
        "密钥申请已批准",
    )
    .await
}

#[tauri::command]
pub(crate) async fn reject_agent_admin_key_request_command(
    app: tauri::AppHandle,
    runtime: tauri::State<'_, Arc<AgentRuntime>>,
    request: AgentAdminKeyRequestRejection,
) -> Result<AgentAdminKeyRequestInbox, String> {
    validate_request_id(&request.request_id)?;
    let reason = normalize_rejection_reason(request.reason)?;
    let session = require_active_admin_session(runtime.inner())?;
    let token = session
        .agent_access_token
        .as_ref()
        .ok_or_else(|| "管理员 Agent 审批凭据缺失，请重新登录".to_string())?;
    let result = reject_agent_admin_key_request(
        &session.proxy_web_url,
        token.value.as_str(),
        &request.request_id,
        reason.as_deref(),
    )
    .await;
    finish_decision(
        &app,
        runtime.inner(),
        &request.request_id,
        result,
        "密钥申请已拒绝",
    )
    .await
}

pub(crate) async fn poll_agent_admin_key_requests_once(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
) -> Result<AgentAdminKeyRequestUpdate, String> {
    if runtime
        .admin_key_request_poll_in_progress
        .swap(true, Ordering::AcqRel)
    {
        return Ok(AgentAdminKeyRequestUpdate {
            inbox: runtime.admin_key_request_inbox()?,
            error: None,
        });
    }
    let _guard = AdminKeyRequestPollGuard(&runtime.admin_key_request_poll_in_progress);
    fetch_and_apply_admin_inbox(app, runtime).await
}

async fn fetch_and_apply_admin_inbox(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
) -> Result<AgentAdminKeyRequestUpdate, String> {
    let Some(session) = active_admin_session(runtime)? else {
        runtime.clear_admin_key_request_inbox()?;
        let update = AgentAdminKeyRequestUpdate {
            inbox: AgentAdminKeyRequestInbox::default(),
            error: None,
        };
        emit_admin_update(app, &update);
        return Ok(update);
    };
    let Some(token) = session.agent_access_token.as_ref() else {
        return emit_admin_poll_error(
            app,
            runtime,
            "管理员 Agent 审批凭据缺失，请重新登录".to_string(),
        );
    };
    let inbox =
        match fetch_agent_admin_key_request_inbox(&session.proxy_web_url, token.value.as_str())
            .await
        {
            Ok(inbox) => inbox,
            Err(error)
                if matches!(
                    error.status,
                    Some(reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN)
                ) =>
            {
                runtime.clear_admin_key_request_inbox()?;
                runtime.permission_sync_notify.notify_one();
                let update = AgentAdminKeyRequestUpdate {
                    inbox: AgentAdminKeyRequestInbox::default(),
                    error: Some(error.message.clone()),
                };
                emit_admin_update(app, &update);
                return Err(error.message);
            }
            Err(error) => {
                return emit_admin_poll_error(app, runtime, error.message);
            }
        };
    let current = active_admin_session(runtime)?;
    if !current.is_some_and(|current| {
        current.account.username == session.account.username
            && current.proxy_web_url == session.proxy_web_url
    }) {
        runtime.clear_admin_key_request_inbox()?;
        let update = AgentAdminKeyRequestUpdate {
            inbox: AgentAdminKeyRequestInbox::default(),
            error: None,
        };
        emit_admin_update(app, &update);
        return Ok(update);
    }
    let (update, new_ids) = runtime.replace_admin_key_request_inbox(inbox)?;
    emit_admin_update(app, &update);
    notify_new_admin_requests(app, new_ids.len());
    Ok(update)
}

async fn finish_decision(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
    request_id: &str,
    result: Result<(), crate::auth::AgentAdminHttpError>,
    log_message: &str,
) -> Result<AgentAdminKeyRequestInbox, String> {
    match result {
        Ok(()) => {
            let update = runtime.remove_admin_key_request(request_id)?;
            emit_admin_update(app, &update);
            runtime.admin_key_request_poll_notify.notify_one();
            info!(request_id, "{log_message}");
            Ok(update.inbox)
        }
        Err(error) if error.is_conflict() => {
            match fetch_and_apply_admin_inbox(app, runtime).await {
                Ok(_) => Err("该申请已由其他管理员处理，列表已刷新".to_string()),
                Err(refresh_error) => Err(format!(
                    "该申请已由其他管理员处理；自动刷新失败：{refresh_error}"
                )),
            }
        }
        Err(error) => {
            if matches!(
                error.status,
                Some(reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN)
            ) {
                runtime.clear_admin_key_request_inbox()?;
                emit_admin_update(
                    app,
                    &AgentAdminKeyRequestUpdate {
                        inbox: AgentAdminKeyRequestInbox::default(),
                        error: Some(error.message.clone()),
                    },
                );
                runtime.permission_sync_notify.notify_one();
            }
            Err(error.message)
        }
    }
}

fn validate_approval(
    request: &AgentAdminKeyRequestApproval,
    runtime: &AgentRuntime,
) -> Result<(), String> {
    validate_request_id(&request.request_id)?;
    if request.expires_at <= current_timestamp() {
        return Err("密钥有效期必须晚于当前时间".to_string());
    }
    if request.proxy_address_ids.is_empty()
        || request.proxy_address_ids.len() > MAX_APPROVAL_PROXY_ADDRESSES
    {
        return Err("请至少选择一个启用的 Proxy 地址".to_string());
    }
    let selected = request.proxy_address_ids.iter().collect::<HashSet<_>>();
    if selected.len() != request.proxy_address_ids.len() {
        return Err("Proxy 地址选择不能重复".to_string());
    }
    let enabled = runtime
        .admin_key_request_inbox()?
        .proxy_addresses
        .into_iter()
        .filter(|address| address.enabled)
        .map(|address| address.proxy_address_id)
        .collect::<HashSet<_>>();
    if !request
        .proxy_address_ids
        .iter()
        .all(|address_id| enabled.contains(address_id))
    {
        return Err("选择中包含已停用或不存在的 Proxy 地址，请刷新后重试".to_string());
    }
    Ok(())
}

fn active_admin_session(
    runtime: &AgentRuntime,
) -> Result<Option<crate::runtime::AuthenticatedAgentSession>, String> {
    Ok(runtime.authenticated_session()?.filter(|session| {
        session.account.role == "admin" && session.account_status == AgentAuthAccountStatus::Active
    }))
}

fn require_active_admin_session(
    runtime: &AgentRuntime,
) -> Result<crate::runtime::AuthenticatedAgentSession, String> {
    active_admin_session(runtime)?.ok_or_else(|| "当前账号没有管理员审批权限".to_string())
}

fn validate_request_id(request_id: &str) -> Result<(), String> {
    if request_id.is_empty()
        || request_id.len() > 256
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("密钥申请编号无效".to_string());
    }
    Ok(())
}

fn normalize_rejection_reason(reason: Option<String>) -> Result<Option<String>, String> {
    let Some(reason) = reason else {
        return Ok(None);
    };
    let reason = reason.trim();
    if reason.is_empty() {
        return Ok(None);
    }
    if reason.chars().count() > 500 {
        return Err("拒绝理由不能超过 500 个字符".to_string());
    }
    if reason
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err("拒绝理由包含不允许的控制字符".to_string());
    }
    Ok(Some(reason.to_string()))
}

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn emit_admin_poll_error(
    app: &tauri::AppHandle,
    runtime: &AgentRuntime,
    message: String,
) -> Result<AgentAdminKeyRequestUpdate, String> {
    let update = runtime.admin_key_request_error_update(message.clone())?;
    emit_admin_update(app, &update);
    Err(message)
}

fn emit_admin_update(app: &tauri::AppHandle, update: &AgentAdminKeyRequestUpdate) {
    let _ = app.emit("agent-admin-key-requests-updated", update);
}

fn notify_new_admin_requests(app: &tauri::AppHandle, count: usize) {
    if count == 0 {
        return;
    }
    if let Err(error) = app
        .notification()
        .builder()
        .title("PPAASS 密钥申请")
        .body(format!("收到 {count} 个新的待审批密钥申请"))
        .show()
    {
        warn!(%error, "显示管理员密钥申请系统通知失败");
    }
}

struct AdminKeyRequestPollGuard<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for AdminKeyRequestPollGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
