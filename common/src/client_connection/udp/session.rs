use super::*;

pub(super) async fn connect_udp_socket<C>(config: &C) -> io::Result<UdpSocket>
where
    C: ClientConnectionConfig,
{
    let remote_name = config.remote_addr();
    let timeout = config.timeout_duration();
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&remote_name).await?.collect();
    let bind_addr = config.bind_addr();
    let mut last_error = None;

    for remote in resolved {
        if bind_addr.is_some_and(|bind| bind.is_ipv4() != remote.is_ipv4()) {
            continue;
        }
        match connect_udp_socket_to(config, remote, bind_addr, timeout).await {
            Ok(socket) => return Ok(socket),
            Err(error) => {
                warn!("建立原生 UDP Proxy socket 失败：{error}");
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "远端 Proxy 没有可用的 UDP 端点",
        )
    }))
}

pub(super) async fn connect_udp_socket_to<C>(
    config: &C,
    remote: SocketAddr,
    configured_bind: Option<SocketAddr>,
    timeout: Duration,
) -> io::Result<UdpSocket>
where
    C: ClientConnectionConfig,
{
    let socket = Socket::new(
        Domain::for_address(remote),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if let Some(size) = config.udp_socket_buffer_size() {
        if let Err(error) = socket.set_recv_buffer_size(size) {
            debug!("设置原生 UDP Proxy SO_RCVBUF 失败：{error}");
        }
        if let Err(error) = socket.set_send_buffer_size(size) {
            debug!("设置原生 UDP Proxy SO_SNDBUF 失败：{error}");
        }
    }

    // Android VpnService.protect() must happen before bind/connect, otherwise
    // the proxy socket can be routed recursively back into the TUN.
    config.protect_udp_socket(&socket, remote)?;
    bind_socket_to_interface(&socket, config.bind_interface().as_ref(), remote)?;
    let bind = configured_bind.unwrap_or_else(|| {
        SocketAddr::new(
            if remote.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        )
    });
    socket.bind(&SockAddr::from(bind))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;
    tokio::time::timeout(timeout, socket.connect(remote))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "连接原生 UDP proxy 超时"))??;
    Ok(socket)
}

pub(super) async fn authenticate_udp_session<C>(
    socket: &UdpSocket,
    config: &C,
    timeout: Duration,
) -> io::Result<([u8; 16], UdpSessionCodec)>
where
    C: ClientConnectionConfig,
{
    let session_id = random_bytes();
    let client_nonce = random_bytes();
    let username = config.username();
    let timestamp = crate::current_timestamp();
    let private_key_pem = config
        .private_key_pem()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let rsa = RsaKeyPair::from_private_key_pem(&private_key_pem)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let proxy_identity_public_key_pem = config.proxy_identity_public_key_pem().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "未配置可信的 Proxy 传输身份公钥",
        )
    })?;
    let proxy_identity_public_key = RsaKeyPair::from_public_key_pem(&proxy_identity_public_key_pem)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Proxy 传输身份公钥格式无效"))?;
    let digest = udp_auth_proof_digest(&session_id, &username, timestamp, &client_nonce);
    let proof = rsa
        .sign_pss_sha256(&digest)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let auth = UdpAuthInit {
        username,
        timestamp,
        client_nonce,
        proof,
    };
    let request = encode_auth_init(session_id, &auth).map_err(udp_protocol_error)?;
    let deadline = Instant::now() + timeout;
    let mut retry_delay = AUTH_INITIAL_RETRY;
    let mut buffer = vec![0_u8; UDP_MAX_DATAGRAM_SIZE + 1];

    loop {
        socket.send(&request).await?;
        let attempt_deadline = (Instant::now() + retry_delay).min(deadline);
        loop {
            let remaining = attempt_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let received = tokio::time::timeout(remaining, socket.recv(&mut buffer)).await;
            let Ok(Ok(size)) = received else { break };
            if size > UDP_MAX_DATAGRAM_SIZE {
                continue;
            }
            let auth_ok = match decode_auth_ok(&buffer[..size]) {
                Ok((header, auth_ok)) if header.session_id == session_id => auth_ok,
                Ok(_) | Err(_) => continue,
            };
            let proxy_signature_transcript = udp_auth_ok_signature_transcript(
                &session_id,
                &digest,
                &auth_ok.encrypted_session_secret,
            )
            .map_err(udp_protocol_error)?;
            verify_pss_sha256(
                &proxy_identity_public_key,
                &proxy_signature_transcript,
                &auth_ok.proxy_signature,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Proxy 原生 UDP 传输身份验证失败",
                )
            })?;
            let secret_bytes = match rsa
                .decrypt_oaep_sha256_labelled(UDP_OAEP_LABEL, &auth_ok.encrypted_session_secret)
            {
                Ok(secret) => secret,
                Err(_) => continue,
            };
            let secret = match decode_session_secret(&secret_bytes) {
                Ok(secret) => secret,
                Err(_) => continue,
            };
            if secret
                .validate_handshake_context(&session_id, &client_nonce)
                .is_err()
            {
                continue;
            }
            let codec = UdpSessionCodec::new(
                UdpSessionRole::Agent,
                session_id,
                secret.master_key,
                client_nonce,
                secret.server_nonce,
            )
            .map_err(udp_protocol_error)?;
            return Ok((session_id, codec));
        }

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "原生 UDP 认证响应超时",
            ));
        }
        retry_delay = (retry_delay * 2).min(CONTROL_MAX_RETRY);
    }
}
