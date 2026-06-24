//! 本地 HTTP 代理入口。
//!
//! HTTP CONNECT 会升级成裸 TCP 隧道，普通 HTTP 请求则通过 hyper client 转发。
//! 两条路径都会先由 `DirectAccessChecker` 判定是否直连；否则通过 `ConnectionPool`
//! 取得 agent->proxy 的目标流。

use crate::connection_pool::{ConnectedStream, ConnectionPool};
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AgentError, Result};
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};
use crate::telemetry;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use protocol::Address;
use protocol::TransportProtocol;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, instrument};

/// 从 HTTP 请求中提取主机和端口，正确处理 IPv6 地址
fn extract_host_port(req: &Request<Incoming>, uri: &Uri) -> (String, u16) {
    // 首先尝试从 Host 头获取
    if let Some(host_header) = req.headers().get(hyper::header::HOST)
        && let Ok(host_header) = host_header.to_str()
    {
        // 处理 IPv6 地址: [::1]:8080
        if host_header.starts_with('[') {
            // IPv6 格式
            if let Some(bracket_end) = host_header.find(']') {
                let host = host_header[1..bracket_end].to_string();
                let port = if host_header.len() > bracket_end + 2
                    && host_header.as_bytes()[bracket_end + 1] == b':'
                {
                    host_header[bracket_end + 2..].parse().unwrap_or(80)
                } else {
                    80
                };
                return (host, port);
            }
        }

        // 常规 host:port 格式
        if let Some(colon_pos) = host_header.rfind(':') {
            // 检查冒号后是否有端口号
            if let Ok(port) = host_header[colon_pos + 1..].parse::<u16>() {
                return (host_header[..colon_pos].to_string(), port);
            }
        }

        // 头部中没有端口
        return (host_header.to_string(), uri.port_u16().unwrap_or(80));
    }

    // 回退到 URI
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(80);
    (host, port)
}

#[instrument(skip(stream, pool, direct_checker))]
pub async fn handle_http_connection(
    stream: TcpStream,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    debug!("处理 HTTP 连接: {stream:?}");
    let io = TokioIo::new(stream);
    let pool_clone = pool.clone();
    let checker_clone = direct_checker.clone();

    // 每个 HTTP 请求都共享连接池和直连规则，service_fn 只做轻量克隆。
    let service = service_fn(move |req| {
        let pool = pool_clone.clone();
        let checker = checker_clone.clone();
        async move { handle_http_request(req, pool, checker).await }
    });

    let conn = http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades();

    if let Err(e) = conn.await {
        error!("HTTP 连接服务出错: {}", e);
        return Err(AgentError::HyperError(e));
    }

    Ok(())
}

async fn handle_http_request(
    req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    debug!("HTTP 请求: {} {}", req.method(), req.uri());

    if req.method() == Method::CONNECT {
        // CONNECT 需要升级为原始双向字节流，常用于 HTTPS。
        handle_connect(req, pool, direct_checker).await
    } else {
        // 普通 HTTP 请求走 hyper client handshake 转发。
        handle_regular_request(req, pool, direct_checker).await
    }
}

async fn handle_connect(
    mut req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(443);

    debug!("CONNECT 请求到 {}:{}", host, port);

    let address = Address::Domain {
        host: host.clone(),
        port,
    };

    let target = format!("{host}:{port}");

    if direct_checker.is_direct(&address) {
        // === 直连路径: 直接连接目标 ===
        debug!("CONNECT 使用直连连接到 {}", target);

        let target_for_spawn = target.clone();
        let relay_buffer_size = pool.tcp_relay_buffer_size();
        tokio::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    debug!("HTTP CONNECT 升级成功（直连） {}:{}", host, port);
                    if let Err(e) =
                        tunnel_direct(upgraded, &target_for_spawn, relay_buffer_size).await
                    {
                        error!("直连隧道错误: {}", e);
                    }
                }
                Err(e) => {
                    error!("HTTP CONNECT 升级失败: {}", e);
                }
            }
        });

        // 先回复 200，随后升级任务接管底层 TCP 流。
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(empty())
            .unwrap())
    } else {
        // === 代理路径: 通过代理隧道连接 ===
        // 必须先向 proxy 完成目标 Connect，再给客户端 200。
        // 这样目标不可达时客户端能收到明确的 BAD_GATEWAY，而不是拿到半开的隧道。
        let connected_stream = match pool
            .as_ref()
            .get_connected_stream(address, TransportProtocol::Tcp)
            .await
        {
            Ok(stream) => {
                debug!("从连接池获取已连接流, stream_id: {}", stream.stream_id());
                stream
            }
            Err(e) => {
                error!("从连接池获取流失败: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(boxed(
                        Full::new(Bytes::from("Failed to connect to proxy"))
                            .map_err(|e| match e {}),
                    ))
                    .unwrap());
            }
        };

        // proxy 连接已建立后再升级客户端连接，避免给客户端过早成功响应。
        let relay_buffer_size = pool.tcp_relay_buffer_size();
        tokio::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    debug!("HTTP CONNECT 升级成功 {}:{}", host, port);
                    if let Err(e) =
                        tunnel(upgraded, connected_stream, target, relay_buffer_size).await
                    {
                        error!("隧道错误: {}", e);
                    }
                }
                Err(e) => {
                    error!("HTTP CONNECT 升级失败: {}", e);
                }
            }
        });

        // CONNECT 成功响应本身没有 body，数据随后走 upgraded stream。
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(empty())
            .unwrap())
    }
}

async fn tunnel(
    upgraded: Upgraded,
    connected_stream: ConnectedStream,
    target: String,
    relay_buffer_size: usize,
) -> std::result::Result<(), AgentError> {
    // HTTP CONNECT 隧道与 TUN/SOCKS 共用统一 TCP relay，避免代理路径的
    // DataPacket flush/半关闭语义在不同入口出现分叉。
    //
    // legacy framed stream 的写端是 SinkWriter<DataPacketSink>。对这类流使用
    // copy_bidirectional 时，小块 TLS/HTTP2 数据可能停留在 framed writer 缓冲里，
    // 浏览器体验会表现成 CONNECT 已建立但后续读写偶发顿住；因此 framed 路径
    // 使用逐写 flush。Yamux 子流是裸字节流，仍保留标准 copy 以维持吞吐。
    let proxy_is_framed = connected_stream.is_framed();
    let mut client_io = TokioIo::new(upgraded);
    let mut proxy_io = connected_stream.into_async_io();

    match relay_tcp_bidirectional(
        &mut client_io,
        &mut proxy_io,
        relay_buffer_size,
        if proxy_is_framed {
            TcpRelayOptions::framed_proxy(&target)
        } else {
            TcpRelayOptions::standard(&target)
        },
    )
    .await
    {
        Ok(stats) => {
            debug!(
                "CONNECT 隧道关闭: {} 字节 客户端->代理, {} 字节 代理->客户端, buffer={} bytes",
                stats.client_to_remote, stats.remote_to_client, relay_buffer_size
            );
            telemetry::emit_traffic(
                "HTTP CONNECT",
                target,
                stats.client_to_remote,
                stats.remote_to_client,
            );
        }
        Err(e) => {
            // 客户端关闭连接时出现的连接错误是预期的
            debug!("CONNECT 隧道结束: {}", e);
        }
    }

    Ok(())
}

/// 直连隧道: 不通过代理直接连接目标
async fn tunnel_direct(
    upgraded: Upgraded,
    target: &str,
    relay_buffer_size: usize,
) -> std::result::Result<(), AgentError> {
    // 直连 CONNECT 跳过 proxy，直接把 upgraded client 和目标 TCP 流相连。
    let mut client_io = TokioIo::new(upgraded);
    let mut target_stream = TcpStream::connect(target).await?;

    match relay_tcp_bidirectional(
        &mut client_io,
        &mut target_stream,
        relay_buffer_size,
        TcpRelayOptions::standard(target),
    )
    .await
    {
        Ok(stats) => {
            debug!(
                "直连 CONNECT 隧道关闭: {} 字节 客户端->目标, {} 字节 目标->客户端, buffer={} bytes",
                stats.client_to_remote, stats.remote_to_client, relay_buffer_size
            );
            telemetry::emit_traffic(
                "HTTP CONNECT (direct)",
                target,
                stats.client_to_remote,
                stats.remote_to_client,
            );
        }
        Err(e) => {
            debug!("直连 CONNECT 隧道结束: {}", e);
        }
    }

    Ok(())
}

async fn handle_regular_request(
    mut req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let uri = req.uri();

    // 从 Host 头或 URI 中提取主机和端口
    let (host, port) = extract_host_port(&req, uri);

    debug!("HTTP 请求到 {}:{}", host, port);

    if host.is_empty() {
        // HTTP/1.1 请求缺少 Host 无法确定目标。
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(boxed(
                Full::new(Bytes::from("Missing host")).map_err(|e| match e {}),
            ))
            .unwrap());
    }

    let address = Address::Domain {
        host: host.clone(),
        port,
    };

    // 将 URI 修正为目标服务器的相对路径（origin-form）
    // 代理收到的请求可能是 absolute-form，发给 origin server 时应转成 path/query。
    let path = req
        .uri()
        .path_and_query()
        .map(|pq: &hyper::http::uri::PathAndQuery| pq.as_str())
        .unwrap_or("/");

    if let Ok(new_uri) = Uri::from_str(path) {
        *req.uri_mut() = new_uri;
    }

    if direct_checker.is_direct(&address) {
        // === 直连路径: 直接连接目标 ===
        let target = address_to_string(&address);
        debug!("HTTP 请求使用直连连接到 {}", target);

        let target_stream = match TcpStream::connect(&target).await {
            Ok(s) => s,
            Err(e) => {
                error!("直连到 {} 失败: {}", target, e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(boxed(
                        Full::new(Bytes::from("Failed to connect to target"))
                            .map_err(|e| match e {}),
                    ))
                    .unwrap());
            }
        };

        // 直接与目标进行握手
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(target_stream)).await?;

        // hyper connection future 驱动读写状态机，必须放到后台持续运行。
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                error!("直连连接失败: {:?}", err);
            }
        });

        let response = sender.send_request(req).await?;
        let (parts, body) = response.into_parts();
        let body = boxed(body);

        Ok(Response::from_parts(parts, body))
    } else {
        // === 代理路径: 通过代理隧道连接 ===
        let connected_stream = match pool
            .as_ref()
            .get_connected_stream(address, TransportProtocol::Tcp)
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                error!("从连接池获取流失败: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(boxed(
                        Full::new(Bytes::from("Failed to connect to proxy"))
                            .map_err(|e| match e {}),
                    ))
                    .unwrap());
            }
        };

        // 转换为异步 IO
        let proxy_io = connected_stream.into_async_io();

        // 通过代理隧道与目标进行握手
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(proxy_io)).await?;

        // 代理路径也需要后台驱动 hyper client connection。
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                error!("连接失败: {:?}", err);
            }
        });

        // 发送请求
        let response = sender.send_request(req).await?;

        // 将响应体转换为 BoxBody 类型
        let (parts, body) = response.into_parts();
        let body = boxed(body);

        Ok(Response::from_parts(parts, body))
    }
}

// 未知体的辅助类型
type AgentBody = BoxBody<Bytes, hyper::Error>;

fn boxed<B>(body: B) -> AgentBody
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    // 统一响应 body 类型，便于不同分支返回同一个 Response 类型。
    BoxBody::new(body)
}

fn empty() -> AgentBody {
    // CONNECT 成功响应使用空 body。
    boxed(Full::new(Bytes::new()).map_err(|e| match e {}))
}
