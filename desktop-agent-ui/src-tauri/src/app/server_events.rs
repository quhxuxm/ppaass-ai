use super::*;

const MIN_RECONNECT_SECONDS: u64 = 1;
const MAX_RECONNECT_SECONDS: u64 = 60;

pub(crate) fn start_agent_server_events(app: tauri::AppHandle, runtime: Arc<AgentRuntime>) {
    tauri::async_runtime::spawn(async move {
        let mut reconnect_seconds = MIN_RECONNECT_SECONDS;
        loop {
            let Some(session) = runtime.authenticated_session().ok().flatten() else {
                runtime.server_event_notify.notified().await;
                reconnect_seconds = MIN_RECONNECT_SECONDS;
                continue;
            };
            let Some(token) = session.agent_access_token.as_ref() else {
                runtime
                    .logs
                    .push("SSE 通知凭据缺失，请重新登录以恢复实时同步".to_string());
                runtime.server_event_notify.notified().await;
                continue;
            };
            let mut stream = match AgentServerEventStream::connect(
                &session.proxy_registry_url,
                token.value.as_str(),
            )
            .await
            {
                Ok(stream) => {
                    info!(username = %session.account.username, "Agent SSE 事件流已连接");
                    reconnect_seconds = MIN_RECONNECT_SECONDS;
                    stream
                }
                Err(error) => {
                    warn!(%error, "Agent SSE 事件流连接失败，将退避重连");
                    runtime.logs.push(error);
                    wait_before_reconnect(&runtime, reconnect_seconds).await;
                    reconnect_seconds = next_reconnect_delay(reconnect_seconds);
                    continue;
                }
            };

            loop {
                let event = tokio::select! {
                    _ = runtime.server_event_notify.notified() => break,
                    event = stream.next_event() => event,
                };
                match event {
                    Ok(Some(event)) => {
                        handle_server_event(&app, &runtime, event).await;
                    }
                    Ok(None) => {
                        info!("Agent SSE 事件流已结束，将重新连接");
                        break;
                    }
                    Err(error) => {
                        warn!(%error, "Agent SSE 事件流中断，将重新连接");
                        runtime.logs.push(error);
                        break;
                    }
                }
            }
            wait_before_reconnect(&runtime, reconnect_seconds).await;
            reconnect_seconds = next_reconnect_delay(reconnect_seconds);
        }
    });
}

async fn handle_server_event(
    app: &tauri::AppHandle,
    runtime: &Arc<AgentRuntime>,
    event: AgentServerEventKind,
) {
    match event {
        AgentServerEventKind::Sync
        | AgentServerEventKind::ProfileChanged
        | AgentServerEventKind::ProfilesChanged
        | AgentServerEventKind::KeyRequestChanged => {
            sync_agent_permissions_once(app, runtime).await;
            refresh_admin_requests(app, runtime).await;
        }
        AgentServerEventKind::AdminKeyRequestsChanged => {
            refresh_admin_requests(app, runtime).await;
        }
    }
}

async fn refresh_admin_requests(app: &tauri::AppHandle, runtime: &Arc<AgentRuntime>) {
    if let Err(error) = refresh_agent_admin_key_requests_once(app, runtime).await {
        warn!("{error}");
        runtime.logs.push(error);
    }
}

async fn wait_before_reconnect(runtime: &AgentRuntime, seconds: u64) {
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_secs(seconds)) => {}
        _ = runtime.server_event_notify.notified() => {}
    }
}

pub fn next_reconnect_delay(current_seconds: u64) -> u64 {
    current_seconds.saturating_mul(2).min(MAX_RECONNECT_SECONDS)
}
