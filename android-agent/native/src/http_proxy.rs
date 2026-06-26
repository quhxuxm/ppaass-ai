use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use common::{
    DEFAULT_TCP_LISTEN_BACKLOG, TCP_RELAY_COPY_BUFFER_SIZE, bind_tcp_listener_with_backlog,
    spawn_guarded,
};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use protocol::{Address, TransportProtocol};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::android_log;
use crate::config::{ANDROID_SOCKET_BUFFER_SIZE, AndroidAgentConfig};
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AndroidAgentError, Result};
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
    let tcp_sessions =
        AndroidYamuxSessionManager::new(config, shutdown.clone(), "tcp_yamux_sessions");

    info!("Android HTTP proxy listening on {bind_addr}");
    android_log::info(format!("Android HTTP proxy listening on {bind_addr}"));

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                if let Err(err) = stream.set_nodelay(true) {
                    debug!("Android HTTP proxy failed to set TCP_NODELAY for {peer_addr}: {err}");
                }
                let sessions = tcp_sessions.clone();
                let checker = direct_checker.clone();
                spawn_guarded("android http proxy client", async move {
                    if let Err(err) = handle_http_connection(stream, sessions, checker).await {
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
) -> Result<()> {
    let io = TokioIo::new(stream);
    let sessions_clone = sessions.clone();
    let checker_clone = direct_checker.clone();
    let service = service_fn(move |req| {
        let sessions = sessions_clone.clone();
        let checker = checker_clone.clone();
        async move { handle_http_request(req, sessions, checker).await }
    });

    let conn = http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades();

    if let Err(err) = conn.await {
        error!("Android HTTP proxy connection error: {err}");
        return Err(AndroidAgentError::Connection(format!(
            "HTTP proxy connection error: {err}"
        )));
    }

    Ok(())
}

async fn handle_http_request(
    req: Request<Incoming>,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
) -> std::result::Result<Response<AgentBody>, hyper::Error> {
    debug!("Android HTTP proxy request: {} {}", req.method(), req.uri());

    if req.method() == Method::CONNECT {
        handle_connect(req, sessions, direct_checker).await
    } else {
        handle_regular_request(req, sessions, direct_checker).await
    }
}

async fn handle_connect(
    mut req: Request<Incoming>,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
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

        tokio::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    if let Err(err) = tunnel_direct(upgraded, target_stream, &target).await {
                        error!("Android HTTP CONNECT direct tunnel error: {err}");
                    }
                }
                Err(err) => error!("Android HTTP CONNECT upgrade failed: {err}"),
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

    tokio::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                if let Err(err) = tunnel(upgraded, connected_stream, target).await {
                    error!("Android HTTP CONNECT proxy tunnel error: {err}");
                }
            }
            Err(err) => error!("Android HTTP CONNECT upgrade failed: {err}"),
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
    match tokio::io::copy_bidirectional_with_sizes(
        &mut client_io,
        &mut connected_stream,
        TCP_RELAY_COPY_BUFFER_SIZE,
        TCP_RELAY_COPY_BUFFER_SIZE,
    )
    .await
    {
        Ok((client_to_proxy, proxy_to_client)) => debug!(
            "Android HTTP CONNECT proxy tunnel closed {target}: up={client_to_proxy} down={proxy_to_client}"
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
    match tokio::io::copy_bidirectional_with_sizes(
        &mut client_io,
        &mut target_stream,
        TCP_RELAY_COPY_BUFFER_SIZE,
        TCP_RELAY_COPY_BUFFER_SIZE,
    )
    .await
    {
        Ok((client_to_target, target_to_client)) => debug!(
            "Android HTTP CONNECT direct tunnel closed {target}: up={client_to_target} down={target_to_client}"
        ),
        Err(err) => debug!("Android HTTP CONNECT direct tunnel ended {target}: {err}"),
    }
    Ok(())
}

async fn connect_direct_tcp(target: &str) -> std::io::Result<TcpStream> {
    let mut last_error = None;
    for address in tokio::net::lookup_host(target).await? {
        match connect_direct_socket(address).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no target address resolved")
    }))
}

async fn connect_direct_socket(target: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    protect_socket(&socket)?;
    tune_socket(&socket);
    socket.set_nonblocking(true)?;

    let socket = TcpSocket::from_std_stream(socket.into());
    socket.connect(target).await
}

fn protect_socket(socket: &Socket) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        crate::socket_protector::protect_fd(socket.as_raw_fd())
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        Ok(())
    }
}

fn tune_socket(socket: &Socket) {
    let _ = socket.set_tcp_nodelay(true);
    let _ = socket.set_recv_buffer_size(ANDROID_SOCKET_BUFFER_SIZE);
    let _ = socket.set_send_buffer_size(ANDROID_SOCKET_BUFFER_SIZE);
}

type AgentBody = BoxBody<Bytes, hyper::Error>;

fn boxed<B>(body: B) -> AgentBody
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    BoxBody::new(body)
}

fn empty() -> AgentBody {
    boxed(Full::new(Bytes::new()).map_err(|err| match err {}))
}

fn text_response(status: StatusCode, text: &'static str) -> Response<AgentBody> {
    Response::builder()
        .status(status)
        .body(boxed(
            Full::new(Bytes::from_static(text.as_bytes())).map_err(|err| match err {}),
        ))
        .unwrap()
}
