use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use common::{DEFAULT_TCP_LISTEN_BACKLOG, bind_tcp_listener_with_backlog, spawn_guarded};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use protocol::{Address, TransportProtocol};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::android_log;
use crate::config::AndroidAgentConfig;
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AndroidAgentError, Result};
use crate::http_proxy_body::{AgentBody, boxed, empty, text_response};
use crate::http_proxy_clients::{
    HttpProxyClientLease, is_http_proxy_client_blocked, register_http_proxy_client,
};
use crate::http_proxy_io::connect_direct_tcp;
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};
use crate::yamux_session::{AndroidYamuxSessionManager, AndroidYamuxTargetStream};

pub async fn run_android_http_proxy(
    config: AndroidAgentConfig,
    listen_port: u16,
    shutdown: CancellationToken,
) -> Result<()> {
    config.validate()?;

    let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, listen_port));
    let listener = bind_tcp_listener_with_backlog(bind_addr, DEFAULT_TCP_LISTEN_BACKLOG)?;
    let config = Arc::new(config);
    let direct_checker = Arc::new(DirectAccessChecker::new(&config.direct_access));
    let tcp_sessions = AndroidYamuxSessionManager::new_tcp_direct(config, shutdown.clone());

    info!("Android HTTP proxy listening on {bind_addr}");
    android_log::info(format!("Android HTTP proxy listening on {bind_addr}"));

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                if is_http_proxy_client_blocked(peer_addr.ip()) {
                    debug!("Android HTTP proxy rejected blocked client {peer_addr}");
                    continue;
                }
                if let Err(err) = stream.set_nodelay(true) {
                    debug!("Android HTTP proxy failed to set TCP_NODELAY for {peer_addr}: {err}");
                }
                let sessions = tcp_sessions.clone();
                let checker = direct_checker.clone();
                let client = register_http_proxy_client(peer_addr);
                spawn_guarded("android http proxy client", async move {
                    if let Err(err) = handle_http_connection(stream, sessions, checker, client).await {
                        debug!("Android HTTP proxy client {peer_addr} ended: {err}");
                    }
                });
            }
        }
    }

    info!("Android HTTP proxy stopped");
    android_log::info("Android HTTP proxy stopped");
    Ok(())
}

fn extract_host_port(req: &Request<Incoming>, uri: &Uri) -> (String, u16) {
    if let Some(host_header) = req.headers().get(hyper::header::HOST)
        && let Ok(host_header) = host_header.to_str()
    {
        if host_header.starts_with('[')
            && let Some(bracket_end) = host_header.find(']')
        {
            let host = host_header[1..bracket_end].to_string();
            let port = if host_header.len() > bracket_end + 2
                && host_header.as_bytes()[bracket_end + 1] == b':'
            {
                host_header[bracket_end + 2..].parse().unwrap_or(80)
            } else {
                uri.port_u16().unwrap_or(80)
            };
            return (host, port);
        }

        if let Some(colon_pos) = host_header.rfind(':')
            && let Ok(port) = host_header[colon_pos + 1..].parse::<u16>()
        {
            return (host_header[..colon_pos].to_string(), port);
        }

        return (host_header.to_string(), uri.port_u16().unwrap_or(80));
    }

    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(80);
    (host, port)
}

async fn handle_http_connection(
    stream: TcpStream,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
    client: HttpProxyClientLease,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let sessions_clone = sessions.clone();
    let checker_clone = direct_checker.clone();
    let request_client = client.clone_lease();
    let service = service_fn(move |req| {
        let sessions = sessions_clone.clone();
        let checker = checker_clone.clone();
        let client = request_client.clone_lease();
        async move { handle_http_request(req, sessions, checker, client).await }
    });

    let conn = http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades();

    let cancel = client.cancel_token();
    tokio::select! {
        result = conn => {
            if let Err(err) = result {
                error!("Android HTTP proxy connection error: {err}");
                return Err(AndroidAgentError::Connection(format!(
                    "HTTP proxy connection error: {err}"
                )));
            }
        }
        _ = cancel.cancelled() => {
            debug!("Android HTTP proxy client connection cancelled");
        }
    }

    Ok(())
}

async fn handle_http_request(
    req: Request<Incoming>,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
    client: HttpProxyClientLease,
) -> std::result::Result<Response<AgentBody>, hyper::Error> {
    debug!("Android HTTP proxy request: {} {}", req.method(), req.uri());

    if req.method() == Method::CONNECT {
        handle_connect(req, sessions, direct_checker, client).await
    } else {
        handle_regular_request(req, sessions, direct_checker, client).await
    }
}

async fn handle_connect(
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

    if direct_checker.is_direct(&address) {
        let target_stream = match connect_direct_tcp(&target).await {
            Ok(stream) => stream,
            Err(err) => {
                error!("Android HTTP CONNECT direct failed {target}: {err}");
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
            error!("Android HTTP CONNECT proxy stream failed {target}: {err}");
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

async fn handle_regular_request(
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
                error!("Android HTTP direct request failed {target}: {err}");
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
                error!("Android HTTP direct client connection failed: {err:?}");
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
            error!("Android HTTP proxy request stream failed {host}:{port}: {err}");
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
            error!("Android HTTP proxy client connection failed: {err:?}");
        }
    });

    let response = sender.send_request(req).await?;
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, boxed(body)))
}

async fn tunnel(
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

async fn tunnel_direct(
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
