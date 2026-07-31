use std::{
    sync::{Weak, atomic::Ordering},
    time::Duration,
};

use futures::StreamExt;
use proxy_control_protocol::AUTHORIZATION_EVENTS_PATH;
use reqwest::header;
use tracing::{debug, warn};

use super::client::RemoteControlPlane;

const MAX_SSE_BUFFER_BYTES: usize = 64 * 1024;

pub(super) fn spawn_authorization_event_listener(control: Weak<RemoteControlPlane>) {
    tokio::spawn(async move {
        let mut retry_delay = Duration::from_secs(1);
        loop {
            let Some(control_plane) = control.upgrade() else {
                return;
            };
            match consume_event_stream(&control_plane).await {
                Ok(()) => retry_delay = Duration::from_secs(1),
                Err(error) => {
                    warn!(%error, ?retry_delay, "Registry 授权事件流中断，将重新连接");
                }
            }
            drop(control_plane);
            tokio::time::sleep(retry_delay).await;
            retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
        }
    });
}

async fn consume_event_stream(control: &RemoteControlPlane) -> crate::error::Result<()> {
    let mut request = control
        .client
        .get(control.endpoint(AUTHORIZATION_EVENTS_PATH)?)
        .header(header::AUTHORIZATION, control.bearer_value());
    let last_event_id = control.last_event_id.load(Ordering::Acquire);
    if last_event_id != 0 {
        request = request.header("Last-Event-ID", last_event_id.to_string());
    }
    let response = request.send().await.map_err(|error| {
        crate::error::ProxyError::ControlPlane(format!("连接 Registry 授权事件流失败：{error}"))
    })?;
    if !response.status().is_success() {
        return Err(crate::error::ProxyError::ControlPlane(format!(
            "Registry 授权事件流返回 HTTP {}",
            response.status()
        )));
    }
    let mut chunks = response.bytes_stream();
    let mut buffer = Vec::new();
    let mut event_name = String::new();
    let mut event_id = None;
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|error| {
            crate::error::ProxyError::ControlPlane(format!("读取 Registry 授权事件失败：{error}"))
        })?;
        buffer.extend_from_slice(&chunk);
        while let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = buffer.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = std::str::from_utf8(&line).map_err(|_| {
                crate::error::ProxyError::ControlPlane(
                    "Registry 授权事件不是有效 UTF-8".to_string(),
                )
            })?;
            if line.is_empty() {
                if matches!(
                    event_name.as_str(),
                    "authorization_changed" | "authorization_reset"
                ) {
                    control.clear_authorization_cache().await;
                }
                if let Some(event_id) = event_id.take() {
                    control.last_event_id.fetch_max(event_id, Ordering::Release);
                }
                event_name.clear();
            } else if let Some(value) = line.strip_prefix("event:") {
                event_name = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("id:") {
                event_id = value.trim().parse::<u64>().ok();
            }
        }
        if buffer.len() > MAX_SSE_BUFFER_BYTES {
            return Err(crate::error::ProxyError::ControlPlane(
                "Registry 授权事件超过缓冲区上限".to_string(),
            ));
        }
    }
    debug!("Registry 主动结束授权事件流");
    Ok(())
}
