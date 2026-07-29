use super::*;

pub(super) async fn handle_connect(
    mut req: Request<Incoming>,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
    client: HttpProxyClientLease,
) -> std::result::Result<Response<AgentBody>, hyper::Error> {
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(443);

    if host.is_empty() {
        return Ok(text_response(
            StatusCode::BAD_REQUEST,
            "Missing CONNECT host",
        ));
    }

    let address = Address::Domain {
        host: host.clone(),
        port,
    };
    let target = format!("{host}:{port}");
    let use_direct = direct_checker.is_direct(&address);

    if use_direct {
        let target_stream = match connect_direct_tcp(&target).await {
            Ok(stream) => stream,
            Err(err) => {
                debug!("Android HTTP CONNECT direct failed {target}: {err}");
                return Ok(text_response(
                    StatusCode::BAD_GATEWAY,
                    "Failed to connect to target",
                ));
            }
        };

        let tunnel_client = client.clone_lease();
        tokio::spawn(async move {
            let cancel = tunnel_client.cancel_token();
            tokio::select! {
                upgraded = hyper::upgrade::on(&mut req) => match upgraded {
                Ok(upgraded) => {
                    tokio::select! {
                        result = tunnel_direct(upgraded, target_stream, &target) => {
                            if let Err(err) = result {
                                error!("Android HTTP CONNECT direct tunnel error: {err}");
                            }
                        }
                        _ = cancel.cancelled() => {
                            debug!("Android HTTP CONNECT direct tunnel cancelled {target}");
                        }
                    }
                }
                Err(err) => error!("Android HTTP CONNECT upgrade failed: {err}"),
                },
                _ = cancel.cancelled() => {
                    debug!("Android HTTP CONNECT direct upgrade cancelled {target}");
                }
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(empty())
            .unwrap());
    }

    let connected_stream = match sessions
        .as_ref()
        .connect_to_target(address, TransportProtocol::Tcp)
        .await
    {
        Ok(stream) => stream,
        Err(err) => {
            debug!("Android HTTP CONNECT proxy stream failed {target}: {err}");
            return Ok(text_response(
                StatusCode::BAD_GATEWAY,
                "Failed to connect to proxy",
            ));
        }
    };

    let tunnel_client = client.clone_lease();
    tokio::spawn(async move {
        let cancel = tunnel_client.cancel_token();
        tokio::select! {
            upgraded = hyper::upgrade::on(&mut req) => match upgraded {
            Ok(upgraded) => {
                tokio::select! {
                    result = tunnel(upgraded, connected_stream, target.clone()) => {
                        if let Err(err) = result {
                            error!("Android HTTP CONNECT proxy tunnel error: {err}");
                        }
                    }
                    _ = cancel.cancelled() => {
                        debug!("Android HTTP CONNECT proxy tunnel cancelled {target}");
                    }
                }
            }
            Err(err) => error!("Android HTTP CONNECT upgrade failed: {err}"),
            },
            _ = cancel.cancelled() => {
                debug!("Android HTTP CONNECT proxy upgrade cancelled {target}");
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty())
        .unwrap())
}

pub(super) async fn handle_regular_request(
    mut req: Request<Incoming>,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
    _client: HttpProxyClientLease,
) -> std::result::Result<Response<AgentBody>, hyper::Error> {
    let uri = req.uri().clone();
    let (host, port) = extract_host_port(&req, &uri);
    if host.is_empty() {
        return Ok(text_response(StatusCode::BAD_REQUEST, "Missing host"));
    }

    let address = Address::Domain {
        host: host.clone(),
        port,
    };
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    if let Ok(new_uri) = Uri::from_str(path) {
        *req.uri_mut() = new_uri;
    }

    if direct_checker.is_direct(&address) {
        let target = address_to_string(&address);
        let target_stream = match connect_direct_tcp(&target).await {
            Ok(stream) => stream,
            Err(err) => {
                debug!("Android HTTP direct request failed {target}: {err}");
                return Ok(text_response(
                    StatusCode::BAD_GATEWAY,
                    "Failed to connect to target",
                ));
            }
        };

        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(target_stream)).await?;
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                error!("Android HTTP direct client connection failed");
                debug!(error = ?err, "Android HTTP direct client connection failure details");
            }
        });

        let response = sender.send_request(req).await?;
        let (parts, body) = response.into_parts();
        return Ok(Response::from_parts(parts, boxed(body)));
    }

    let connected_stream = match sessions
        .as_ref()
        .connect_to_target(address, TransportProtocol::Tcp)
        .await
    {
        Ok(stream) => stream,
        Err(err) => {
            debug!("Android HTTP proxy request stream failed {host}:{port}: {err}");
            return Ok(text_response(
                StatusCode::BAD_GATEWAY,
                "Failed to connect to proxy",
            ));
        }
    };

    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(connected_stream)).await?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            error!("Android HTTP proxy client connection failed");
            debug!(error = ?err, "Android HTTP proxy client connection failure details");
        }
    });

    let response = sender.send_request(req).await?;
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, boxed(body)))
}

pub(super) async fn tunnel(
    upgraded: Upgraded,
    mut connected_stream: AndroidYamuxTargetStream,
    target: String,
) -> Result<()> {
    let mut client_io = TokioIo::new(upgraded);
    match relay_tcp_bidirectional(
        &mut client_io,
        &mut connected_stream,
        TcpRelayOptions::http_proxy(&target),
    )
    .await
    {
        Ok(stats) => debug!(
            "Android HTTP CONNECT proxy tunnel closed {target}: up={} down={}",
            stats.client_to_remote, stats.remote_to_client
        ),
        Err(err) => debug!("Android HTTP CONNECT proxy tunnel ended {target}: {err}"),
    }
    Ok(())
}

pub(super) async fn tunnel_direct(
    upgraded: Upgraded,
    mut target_stream: TcpStream,
    target: &str,
) -> Result<()> {
    let mut client_io = TokioIo::new(upgraded);
    match relay_tcp_bidirectional(
        &mut client_io,
        &mut target_stream,
        TcpRelayOptions::http_proxy(target),
    )
    .await
    {
        Ok(stats) => debug!(
            "Android HTTP CONNECT direct tunnel closed {target}: up={} down={}",
            stats.client_to_remote, stats.remote_to_client
        ),
        Err(err) => debug!("Android HTTP CONNECT direct tunnel ended {target}: {err}"),
    }
    Ok(())
}
