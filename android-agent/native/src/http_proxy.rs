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

use crate::config::AndroidAgentConfig;
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AndroidAgentError, Result};
use crate::http_proxy_body::{AgentBody, boxed, empty, text_response};
use crate::http_proxy_clients::{
    HttpProxyClientLease, is_http_proxy_client_blocked, register_http_proxy_client,
};
use crate::http_proxy_io::connect_direct_tcp;
use crate::packet_capture::{self, CapturedTcpStream, ProxyIngressProtocol};
use crate::socks5_proxy::handle_socks5_connection;
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

    info!(
        "Android HTTP / SOCKS5 proxy listening on {bind_addr}; tcp_transport=direct-framed-tcp (transport_mode only applies to UDP)"
    );

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
                spawn_guarded("android explicit proxy client", async move {
                    if let Err(err) = handle_proxy_connection(stream, peer_addr, sessions, checker).await {
                        debug!("Android explicit proxy client {peer_addr} ended: {err}");
                    }
                });
            }
        }
    }

    info!("Android HTTP / SOCKS5 proxy stopped");
    Ok(())
}

async fn handle_proxy_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    let mut buffer = [0u8; 1];
    if stream.peek(&mut buffer).await? == 0 {
        debug!("Android explicit proxy client {peer_addr} closed before protocol detection");
        return Ok(());
    }
    match detect_proxy_protocol(buffer[0]) {
        Some(protocol @ ProxyIngressProtocol::Socks5) => {
            let stream = packet_capture::capture_tcp_stream(stream, protocol);
            let client = register_http_proxy_client(peer_addr);
            handle_socks5_connection(stream, sessions, direct_checker, client).await
        }
        Some(protocol @ ProxyIngressProtocol::Http) => {
            let stream = packet_capture::capture_tcp_stream(stream, protocol);
            let client = register_http_proxy_client(peer_addr);
            handle_http_connection(stream, sessions, direct_checker, client).await
        }
        None => {
            debug!(
                "Android explicit proxy unknown protocol first byte from {peer_addr}: 0x{:02x}",
                buffer[0]
            );
            Ok(())
        }
    }
}

#[doc(hidden)]
pub fn detect_proxy_protocol(first_byte: u8) -> Option<ProxyIngressProtocol> {
    match first_byte {
        0x05 => Some(ProxyIngressProtocol::Socks5),
        b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T' => Some(ProxyIngressProtocol::Http),
        _ => None,
    }
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
    stream: CapturedTcpStream,
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
    debug!(
        method = %req.method(),
        host = %request_log_host(req.uri()),
        "Android HTTP proxy request"
    );

    if req.method() == Method::CONNECT {
        handle_connect(req, sessions, direct_checker, client).await
    } else {
        handle_regular_request(req, sessions, direct_checker, client).await
    }
}

#[doc(hidden)]
pub fn request_log_host(uri: &Uri) -> &str {
    uri.host().unwrap_or("<unknown>")
}

mod tunnel;
use tunnel::*;
