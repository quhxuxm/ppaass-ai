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
use crate::socks5_proxy::handle_socks5_connection;
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};
use crate::yamux_session::{AndroidYamuxSessionManager, AndroidYamuxTargetStream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyProtocol {
    Socks5,
    Http,
}

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

    info!("Android HTTP / SOCKS5 proxy listening on {bind_addr}");
    android_log::info(format!(
        "Android HTTP / SOCKS5 proxy listening on {bind_addr}"
    ));

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
    android_log::info("Android HTTP / SOCKS5 proxy stopped");
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
        Some(ProxyProtocol::Socks5) => {
            let client = register_http_proxy_client(peer_addr);
            handle_socks5_connection(stream, sessions, direct_checker, client).await
        }
        Some(ProxyProtocol::Http) => {
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

fn detect_proxy_protocol(first_byte: u8) -> Option<ProxyProtocol> {
    match first_byte {
        0x05 => Some(ProxyProtocol::Socks5),
        b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T' => Some(ProxyProtocol::Http),
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
    let use_direct = direct_checker.is_direct(&address);

    if use_direct {
        let target_stream = match connect_direct_tcp(&target).await {
            Ok(stream) => stream,
            Err(err) => {
                error!("Android HTTP CONNECT direct failed {target}: {err}");
                android_log::warn(format!(
                    "Android HTTP CONNECT direct failed {target}: {err}"
                ));
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
            android_log::warn(format!(
                "Android HTTP CONNECT proxy stream failed {target}: {err}"
            ));
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
                            android_log::warn(format!(
                                "Android HTTP CONNECT proxy tunnel error {target}: {err}"
                            ));
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
        Err(err) => {
            debug!("Android HTTP CONNECT proxy tunnel ended {target}: {err}");
            android_log::warn(format!(
                "Android HTTP CONNECT proxy tunnel ended {target}: {err}"
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use common::YamuxConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};

    use crate::config::{AndroidAgentConfig, AndroidTunConfig};
    use crate::direct_access::{DirectAccessConfig, DirectAccessMode};

    #[test]
    fn proxy_protocol_detection_rejects_non_proxy_probe_bytes() {
        assert_eq!(detect_proxy_protocol(0x05), Some(ProxyProtocol::Socks5));
        assert_eq!(detect_proxy_protocol(b'G'), Some(ProxyProtocol::Http));
        assert_eq!(detect_proxy_protocol(b'C'), Some(ProxyProtocol::Http));
        assert_eq!(detect_proxy_protocol(0), None);
        assert_eq!(detect_proxy_protocol(b'\n'), None);
        assert_eq!(detect_proxy_protocol(b'X'), None);
    }

    #[tokio::test]
    async fn socks5_proxy_connects_to_direct_tcp_target() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
        });

        let port_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = port_probe.local_addr().unwrap().port();
        drop(port_probe);

        let shutdown = CancellationToken::new();
        let config = AndroidAgentConfig {
            proxy_addrs: vec!["127.0.0.1:9".to_string()],
            username: "test".to_string(),
            private_key_pem: "test".to_string(),
            transport_mode: common::TransportMode::Quic,
            quic_connection_pool_size: 4,
            async_runtime_stack_size_mb: 4,
            runtime_threads: 1,
            connect_timeout_secs: 1,
            http_proxy_max_concurrent_connects: 16,
            compression_mode: "none".to_string(),
            yamux: YamuxConfig::default(),
            direct_access: DirectAccessConfig {
                mode: DirectAccessMode::DirectAll,
                rules: Vec::new(),
            },
            tun: AndroidTunConfig::default(),
        };

        let proxy_shutdown = shutdown.clone();
        let proxy_task = tokio::spawn(async move {
            run_android_http_proxy(config, proxy_port, proxy_shutdown).await
        });

        let mut client = None;
        for _ in 0..20 {
            match TcpStream::connect(("127.0.0.1", proxy_port)).await {
                Ok(stream) => {
                    client = Some(stream);
                    break;
                }
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
        let mut client = client.expect("SOCKS5 proxy listener should accept connections");

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x05, 0x00]);

        let echo_port = echo_addr.port();
        client
            .write_all(&[
                0x05,
                0x01,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                (echo_port >> 8) as u8,
                echo_port as u8,
            ])
            .await
            .unwrap();
        let mut connect_reply = [0u8; 10];
        client.read_exact(&mut connect_reply).await.unwrap();
        assert_eq!(&connect_reply[..2], &[0x05, 0x00]);

        let clients = crate::http_proxy_clients::http_proxy_clients_json();
        assert!(
            clients.contains("\"127.0.0.1\""),
            "SOCKS5 client should be visible in proxy client list: {clients}"
        );

        let payload = b"ppaass-socks5-smoke";
        client.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);

        drop(client);
        shutdown.cancel();
        timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("proxy task should stop")
            .unwrap()
            .unwrap();
        echo_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_proxy_still_supports_regular_http_and_connect() {
        let port_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = port_probe.local_addr().unwrap().port();
        drop(port_probe);

        let shutdown = CancellationToken::new();
        let proxy_shutdown = shutdown.clone();
        let proxy_task = tokio::spawn(async move {
            run_android_http_proxy(test_config(), proxy_port, proxy_shutdown).await
        });

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            assert!(request.starts_with("GET /plain?x=1 HTTP/1.1"), "{request}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
        });

        let mut http_client = connect_to_proxy(proxy_port).await;
        http_client
            .write_all(
                format!(
                    "GET http://{}/plain?x=1 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    origin_addr, origin_addr
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        http_client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.ends_with("OK"), "{response}");
        origin_task.await.unwrap();

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
        });

        let mut connect_client = connect_to_proxy(proxy_port).await;
        connect_client
            .write_all(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo_addr, echo_addr
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let connect_response = read_http_head(&mut connect_client).await;
        assert!(
            connect_response.starts_with("HTTP/1.1 200 OK"),
            "{connect_response}"
        );
        let payload = b"ppaass-http-connect-smoke";
        connect_client.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        connect_client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        drop(connect_client);
        echo_task.await.unwrap();

        shutdown.cancel();
        timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("proxy task should stop")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn http_and_socks5_share_one_port_concurrently() {
        let port_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = port_probe.local_addr().unwrap().port();
        drop(port_probe);

        let shutdown = CancellationToken::new();
        let proxy_shutdown = shutdown.clone();
        let proxy_task = tokio::spawn(async move {
            run_android_http_proxy(test_config(), proxy_port, proxy_shutdown).await
        });

        let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_addr = slow_listener.local_addr().unwrap();
        let (slow_started_tx, slow_started_rx) = oneshot::channel();
        let slow_task = tokio::spawn(async move {
            let (mut stream, _) = slow_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            assert!(request.starts_with("GET /slow HTTP/1.1"), "{request}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n")
                .await
                .unwrap();
            slow_started_tx.send(()).ok();
            stream.write_all(b"slow").await.unwrap();
            sleep(Duration::from_millis(250)).await;
            stream.write_all(b"-socks-body").await.unwrap();
        });

        let mut socks_client = socks5_connect_to_ipv4(proxy_port, slow_addr).await;
        socks_client
            .write_all(b"GET /slow HTTP/1.1\r\nHost: slow.local\r\n\r\n")
            .await
            .unwrap();
        let socks_response = read_http_head(&mut socks_client).await;
        assert!(
            socks_response.starts_with("HTTP/1.1 200 OK"),
            "{socks_response}"
        );
        slow_started_rx
            .await
            .expect("SOCKS5 target should start a long response");

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            assert!(
                request.starts_with("GET /http-while-socks HTTP/1.1"),
                "{request}"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nHTTP-OK",
                )
                .await
                .unwrap();
        });

        let mut http_client = connect_to_proxy(proxy_port).await;
        http_client
            .write_all(
                format!(
                    "GET http://{}/http-while-socks HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    origin_addr, origin_addr
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut http_response = String::new();
        http_client
            .read_to_string(&mut http_response)
            .await
            .unwrap();
        assert!(
            http_response.starts_with("HTTP/1.1 200 OK"),
            "{http_response}"
        );
        assert!(http_response.ends_with("HTTP-OK"), "{http_response}");
        origin_task.await.unwrap();

        let mut socks_body = vec![0u8; 15];
        socks_client.read_exact(&mut socks_body).await.unwrap();
        assert_eq!(socks_body, b"slow-socks-body");
        drop(socks_client);
        slow_task.await.unwrap();

        shutdown.cancel();
        timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("proxy task should stop")
            .unwrap()
            .unwrap();
    }

    fn test_config() -> AndroidAgentConfig {
        AndroidAgentConfig {
            proxy_addrs: vec!["127.0.0.1:9".to_string()],
            username: "test".to_string(),
            private_key_pem: "test".to_string(),
            transport_mode: common::TransportMode::Quic,
            quic_connection_pool_size: 4,
            async_runtime_stack_size_mb: 4,
            runtime_threads: 1,
            connect_timeout_secs: 1,
            http_proxy_max_concurrent_connects: 16,
            compression_mode: "none".to_string(),
            yamux: YamuxConfig::default(),
            direct_access: DirectAccessConfig {
                mode: DirectAccessMode::DirectAll,
                rules: Vec::new(),
            },
            tun: AndroidTunConfig::default(),
        }
    }

    async fn connect_to_proxy(proxy_port: u16) -> TcpStream {
        for _ in 0..20 {
            match TcpStream::connect(("127.0.0.1", proxy_port)).await {
                Ok(stream) => return stream,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
        panic!("proxy listener should accept connections");
    }

    async fn socks5_connect_to_ipv4(proxy_port: u16, target: SocketAddr) -> TcpStream {
        let mut client = connect_to_proxy(proxy_port).await;
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x05, 0x00]);

        let ip = match target.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("test helper only supports IPv4"),
        };
        let port = target.port();
        client
            .write_all(&[
                0x05,
                0x01,
                0x00,
                0x01,
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                (port >> 8) as u8,
                port as u8,
            ])
            .await
            .unwrap();
        let mut connect_reply = [0u8; 10];
        client.read_exact(&mut connect_reply).await.unwrap();
        assert_eq!(&connect_reply[..2], &[0x05, 0x00]);
        client
    }

    async fn read_http_head(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            stream.read_exact(&mut buf).await.unwrap();
            bytes.push(buf[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }
}
