use super::*;

pub(super) async fn connect_udp_addr(
    dst: SocketAddr,
    interface: &str,
    source: BoundSource,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(dst), Type::DGRAM, Some(Protocol::UDP))?;
    // UDP 同样绑定到指定网卡，确保 DNS/UDP 目标也走预期出口。
    bind_socket_to_interface(&socket, interface, source.interface_index, dst)?;
    // 绑定候选源地址后再 connect，便于后续收发只面对单个对端。
    socket.bind(&SockAddr::from(source.addr))?;
    socket.set_nonblocking(true)?;

    let socket = UdpSocket::from_std(socket.into())?;
    socket.connect(dst).await?;
    tune_egress_udp_socket(&socket, "绑定出站 UDP 连接");
    Ok(socket)
}

pub(super) async fn connect_udp_default(target_addr: &str) -> io::Result<UdpSocket> {
    let mut last_error = None;
    let mut resolved = false;
    for dst in tokio::net::lookup_host(target_addr).await? {
        resolved = true;
        // 默认 UDP 路径仍按目标地址族选择通配绑定地址。
        let bind_addr = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        match UdpSocket::bind(bind_addr).await {
            Ok(socket) => match socket.connect(dst).await {
                Ok(()) => {
                    tune_egress_udp_socket(&socket, "默认出站 UDP 连接");
                    return Ok(socket);
                }
                Err(err) => last_error = Some(err),
            },
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        if resolved {
            io::Error::other("所有目标地址连接失败")
        } else {
            io::Error::new(io::ErrorKind::NotFound, "未解析到目标地址")
        }
    }))
}

pub(super) async fn connect_udp_default_resolved(
    destinations: &[SocketAddr],
) -> io::Result<UdpSocket> {
    let mut last_error = None;
    for &dst in destinations {
        match connect_udp_default_addr(dst).await {
            Ok(socket) => return Ok(socket),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| io::Error::other("所有目标地址连接失败")))
}

pub(super) async fn connect_udp_default_addr(dst: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(dst).await?;
    tune_egress_udp_socket(&socket, "已解析出站 UDP 连接");
    Ok(socket)
}

pub fn split_domain_target(target_addr: &str) -> io::Result<(&str, u16)> {
    // Address::Domain 的 host 历史上允许保存裸 IPv6，因此必须从最后一个冒号拆端口；
    // 例如 `::ffff:127.0.0.1:8787` 应解析成 `::ffff:127.0.0.1` + `8787`。
    let (raw_host, port) = target_addr.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("目标地址缺少端口：{target_addr:?}"),
        )
    })?;
    let host = if let Some(host) = raw_host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        // bracket 形式只接受数字 IP，不能把任意 `[domain]` 当成合法主机名。
        if host.parse::<IpAddr>().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("目标括号地址格式无效：{target_addr:?}"),
            ));
        }
        host
    } else {
        if raw_host.is_empty()
            || raw_host.contains(['[', ']'])
            || (raw_host.contains(':') && raw_host.parse::<IpAddr>().is_err())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("目标域名地址格式无效：{target_addr:?}"),
            ));
        }
        raw_host
    };
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("目标域名地址格式无效：{target_addr:?}"),
        ));
    }
    let port = port.parse::<u16>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("目标地址端口无效 {target_addr:?}：{err}"),
        )
    })?;
    Ok((host, port))
}

pub(super) fn tune_egress_udp_socket(socket: &UdpSocket, context: &str) {
    // QUIC/video traffic is bursty. Keep target-facing buffers large enough
    // that a short scheduler pause does not turn into avoidable packet loss.
    // These options are best-effort and work through socket2 on Unix and Windows.
    let sock_ref = SockRef::from(socket);
    if let Err(err) = sock_ref.set_recv_buffer_size(PROXY_EGRESS_UDP_BUFFER_SIZE) {
        tracing::warn!("设置 {context} 接收缓冲失败，将继续使用系统默认值: {err}");
    }
    if let Err(err) = sock_ref.set_send_buffer_size(PROXY_EGRESS_UDP_BUFFER_SIZE) {
        tracing::warn!("设置 {context} 发送缓冲失败，将继续使用系统默认值: {err}");
    }
}

pub(super) fn connect_context_error(
    interface: &str,
    source: SocketAddr,
    dst: SocketAddr,
    err: io::Error,
) -> io::Error {
    io::Error::new(
        err.kind(),
        format!("出站设备 {interface} 使用源地址 {source} 连接 {dst} 失败：{err}"),
    )
}
