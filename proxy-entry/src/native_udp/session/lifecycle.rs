use super::*;

pub(in crate::native_udp) async fn revalidate_authorization(
    context: &SessionContext,
) -> Result<()> {
    validate_session_authorization(
        &context.user_manager,
        &context.username,
        &context.authenticated_public_key_pem,
        context.authenticated_key_version,
    )
    .await
}

pub(in crate::native_udp) async fn wait_until_expired(expires_at: Option<i64>) {
    let Some(expires_at) = expires_at else {
        std::future::pending::<()>().await;
        return;
    };
    let Some(delay) = duration_until_expiry(expires_at, SystemTime::now()) else {
        std::future::pending::<()>().await;
        return;
    };
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

pub fn duration_until_expiry(expires_at: i64, now: SystemTime) -> Option<Duration> {
    if expires_at < 0 {
        return Some(Duration::ZERO);
    }
    let expires_at = u64::try_from(expires_at).ok()?;
    let deadline = UNIX_EPOCH.checked_add(Duration::from_secs(expires_at))?;
    Some(deadline.duration_since(now).unwrap_or_default())
}

pub fn session_expired_at(expires_at: Option<i64>, now: SystemTime) -> bool {
    let Some(expires_at) = expires_at else {
        return false;
    };
    let Ok(expires_at) = u64::try_from(expires_at) else {
        return true;
    };
    UNIX_EPOCH
        .checked_add(Duration::from_secs(expires_at))
        .is_some_and(|deadline| now >= deadline)
}

fn ensure_session_not_expired(context: &SessionContext) -> Result<()> {
    if session_expired_at(context.expires_at, SystemTime::now()) {
        return Err(ProxyError::Authentication(
            "Native UDP session expired".to_string(),
        ));
    }
    Ok(())
}

pub(in crate::native_udp) async fn send_session_message(
    context: &SessionContext,
    codec: &mut UdpSessionCodec,
    message: &UdpSessionMessage,
) -> Result<()> {
    ensure_session_not_expired(context)?;
    let datagrams = codec
        .encode_message(message)
        .map_err(|error| ProxyError::Connection(error.to_string()))?;
    for datagram in datagrams {
        ensure_session_not_expired(context)?;
        let sent = context.socket.send_to(&datagram, context.peer).await?;
        if sent != datagram.len() {
            return Err(ProxyError::Connection(format!(
                "partial native UDP send: {sent}/{}",
                datagram.len()
            )));
        }
    }
    Ok(())
}

pub(in crate::native_udp) fn udp_idle_timeout(config: &ProxyConfig) -> Duration {
    Duration::from_secs(config.udp_relay_idle_timeout_secs.max(1))
}

pub(in crate::native_udp) fn connect_response(
    flow_id: u64,
    error: Option<String>,
) -> UdpSessionMessage {
    UdpSessionMessage::ConnectResponse {
        flow_id,
        success: error.is_none(),
        error,
    }
}
