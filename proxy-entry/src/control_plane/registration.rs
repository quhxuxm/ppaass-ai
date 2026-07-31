use std::{sync::Weak, time::Duration};

use proxy_control_protocol::{
    CONTROL_PROTOCOL_VERSION, ENTRY_REGISTRATION_PATH, EntryRegistrationRequest,
    EntryRegistrationResponse,
};
use reqwest::{StatusCode, header};
use tracing::{info, warn};

use super::client::{RemoteControlPlane, control_status_error};
use crate::error::{ProxyError, Result};

const ENTRY_REGISTRATION_INTERVAL: Duration = Duration::from_secs(30);
const ENTRY_REGISTRATION_RETRY_INITIAL: Duration = Duration::from_secs(1);
const ENTRY_REGISTRATION_RETRY_MAX: Duration = Duration::from_secs(30);

pub(super) fn spawn_entry_registration(control: Weak<RemoteControlPlane>) {
    tokio::spawn(async move {
        let mut retry_delay = ENTRY_REGISTRATION_RETRY_INITIAL;
        loop {
            let Some(control_plane) = control.upgrade() else {
                return;
            };
            let (delay, succeeded) = match register_entry(&control_plane).await {
                Ok(response) => {
                    match control_plane.refresh_authorizations().await {
                        Ok(revision) => info!(
                            entry_id = %control_plane.entry_id,
                            revision,
                            "Proxy Entry 已刷新 Registry 授权快照"
                        ),
                        Err(error) => warn!(
                            %error,
                            entry_id = %control_plane.entry_id,
                            "Proxy Entry 注册成功，但刷新授权快照失败；继续使用最后成功快照"
                        ),
                    }
                    info!(
                        entry_id = %control_plane.entry_id,
                        registry_instance_id = response.registry_instance_id,
                        protocol_version = response.protocol_version,
                        received_at = response.received_at,
                        "Proxy Entry 已向 Registry 注册"
                    );
                    (ENTRY_REGISTRATION_INTERVAL, true)
                }
                Err(error) => {
                    warn!(
                        %error,
                        entry_id = %control_plane.entry_id,
                        ?retry_delay,
                        "Proxy Entry 注册失败，将在后台重试"
                    );
                    (retry_delay, false)
                }
            };
            drop(control_plane);
            tokio::time::sleep(delay).await;
            retry_delay = if succeeded {
                ENTRY_REGISTRATION_RETRY_INITIAL
            } else {
                (retry_delay * 2).min(ENTRY_REGISTRATION_RETRY_MAX)
            };
        }
    });
}

async fn register_entry(control: &RemoteControlPlane) -> Result<EntryRegistrationResponse> {
    let response = control
        .client
        .post(control.endpoint(ENTRY_REGISTRATION_PATH)?)
        .header(header::AUTHORIZATION, control.bearer_value())
        .json(&EntryRegistrationRequest {
            entry_id: control.entry_id.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: CONTROL_PROTOCOL_VERSION,
            advertised_address: control.advertised_address.to_string(),
        })
        .send()
        .await
        .map_err(|error| {
            ProxyError::ControlPlane(format!("向 Registry 注册 Entry 失败：{error}"))
        })?;
    if response.status() != StatusCode::OK {
        return Err(control_status_error("注册 Proxy Entry", response.status()));
    }
    let registration = response
        .json::<EntryRegistrationResponse>()
        .await
        .map_err(|error| {
            ProxyError::ControlPlane(format!("Registry Entry 注册响应无效：{error}"))
        })?;
    if registration.protocol_version != CONTROL_PROTOCOL_VERSION {
        return Err(ProxyError::ControlPlane(format!(
            "Registry 控制协议版本不兼容：Entry={}，Registry={}",
            CONTROL_PROTOCOL_VERSION, registration.protocol_version
        )));
    }
    Ok(registration)
}
