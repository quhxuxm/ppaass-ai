//! 本地 HTTP 代理入口。
//!
//! HTTP CONNECT 会升级成裸 TCP 隧道，普通 HTTP 请求则通过 hyper client 转发。
//! 两条路径都会先由 `DirectAccessChecker` 判定是否直连；否则通过 proxy session
//! manager 取得 agent->proxy 的目标流。

use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AgentError, Result};
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};
use crate::telemetry;
use crate::yamux_session::{YamuxSessionManager, YamuxTargetStream};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use protocol::{Address, TransportProtocol};
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

#[instrument(skip(stream, sessions, direct_checker))]
pub async fn handle_http_connection(
    stream: TcpStream,
    sessions: Arc<YamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
) -> Result<()> {
    debug!("处理 HTTP 连接: {stream:?}");
    let io = TokioIo::new(stream);
    let sessions_clone = sessions.clone();
    let checker_clone = direct_checker.clone();

    // 每个 HTTP 请求都共享 proxy session 管理器和直连规则，service_fn 只做轻量克隆。
    let service = service_fn(move |req| {
        let sessions = sessions_clone.clone();
        let checker = checker_clone.clone();
        async move { handle_http_request(req, sessions, checker).await }
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
    sessions: Arc<YamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    debug!("HTTP 请求: {} {}", req.method(), req.uri());

    if req.method() == Method::CONNECT {
        // CONNECT 需要升级为原始双向字节流，常用于 HTTPS。
        handle_connect(req, sessions, direct_checker).await
    } else {
        // 普通 HTTP 请求走 hyper client handshake 转发。
        handle_regular_request(req, sessions, direct_checker).await
    }
}

async fn handle_connect(
    mut req: Request<Incoming>,
    sessions: Arc<YamuxSessionManager>,
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

        // CONNECT 的 200 只应该表示“隧道已经可用”。
        // 如果先回复 200 再异步连接目标，浏览器会立刻把 TLS ClientHello 写进本地隧道；
        // 一旦后续远端连接失败或建立过慢，这个已经成功的 CONNECT 会表现成异常 TCP/TLS
        // 连接，而不是一次可重试的代理建连失败。视频分片场景下这会让播放器状态机很难判断
        // 当前分片到底是网络失败、解析失败还是响应中断。
        let target_stream = match TcpStream::connect(&target).await {
            Ok(stream) => stream,
            Err(err) => {
                error!("HTTP CONNECT 直连到 {} 失败: {}", target, err);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(boxed(
                        Full::new(Bytes::from("Failed to connect to target"))
                            .map_err(|e| match e {}),
                    ))
                    .unwrap());
            }
        };
        if let Err(err) = target_stream.set_nodelay(true) {
            debug!("HTTP CONNECT 直连目标 TCP_NODELAY 设置失败，继续使用默认行为：{err}");
        }

        tokio::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    debug!("HTTP CONNECT 升级成功（直连） {}:{}", host, port);
                    if let Err(e) = tunnel_direct(upgraded, target_stream, &target).await {
                        error!("直连隧道错误: {}", e);
                    }
                }
                Err(e) => {
                    error!("HTTP CONNECT 升级失败: {}", e);
                }
            }
        });

        // 目标连接成功后再回复 200，随后升级任务接管底层 TCP 流。
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(empty())
            .unwrap())
    } else {
        // === 代理路径: 通过代理隧道连接 ===
        // 代理路径同样必须先确认远端 proxy/目标通道可用，再向浏览器返回 CONNECT 200。
        // 浏览器把 200 视为“之后就是透明 TCP 字节流”；如果此时 proxy stream 还没建立，
        // TLS/HTTP2 的开头字节会先堆在本地 upgraded 连接里，后续失败只能体现为隧道
        // 被动断开。对媒体分片来说，这类“看似建连成功、随后字节流异常”的失败很容易
        // 表现成分片大小接近正常但播放器无法解析或缓冲状态卡住。
        let connected_stream = match sessions
            .as_ref()
            .connect_to_target(address, TransportProtocol::Tcp)
            .await
        {
            Ok(stream) => {
                debug!(
                    "通过 proxy session manager 获取目标流, stream_id: {}",
                    stream.stream_id()
                );
                stream
            }
            Err(e) => {
                error!("HTTP CONNECT 获取 proxy 流失败: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(boxed(
                        Full::new(Bytes::from("Failed to connect to proxy"))
                            .map_err(|e| match e {}),
                    ))
                    .unwrap());
            }
        };

        tokio::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    debug!("HTTP CONNECT 升级成功 {}:{}", host, port);
                    // 代理路径必须把 Domain 原样交给 proxy 端解析。
                    // agent 端本地解析会改变出口 DNS 语义：目标 IP 由本机网络决定，
                    // 不再由 proxy 所在地域、proxy DNS 缓存和远端分流策略决定。对
                    // CDN/HLS 这类强地域相关流量尤其容易选错节点，因此这里只负责
                    // 透传域名，不做任何 agent 侧 DNS fallback。
                    if let Err(e) = tunnel(upgraded, connected_stream, target).await {
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
    connected_stream: YamuxTargetStream,
    target: String,
) -> std::result::Result<(), AgentError> {
    // HTTP CONNECT、SOCKS、TUN 的 TCP 字节流统一走 copy_bidirectional。
    // direct framed TCP 和 Yamux 都先通过 YamuxTargetStream 转成 AsyncRead/AsyncWrite，
    // 调用点不再按底层传输分支切换不同 relay 语义。
    let mut client_io = TokioIo::new(upgraded);
    let mut proxy_io = connected_stream.into_async_io();

    match relay_tcp_bidirectional(
        &mut client_io,
        &mut proxy_io,
        TcpRelayOptions::standard(&target),
    )
    .await
    {
        Ok(stats) => {
            debug!(
                "CONNECT 隧道关闭: {} 字节 客户端->代理, {} 字节 代理->客户端",
                stats.client_to_remote, stats.remote_to_client
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
    mut target_stream: TcpStream,
    target: &str,
) -> std::result::Result<(), AgentError> {
    // 直连 CONNECT 跳过 proxy，直接把 upgraded client 和目标 TCP 流相连。
    let mut client_io = TokioIo::new(upgraded);

    match relay_tcp_bidirectional(
        &mut client_io,
        &mut target_stream,
        TcpRelayOptions::standard(target),
    )
    .await
    {
        Ok(stats) => {
            debug!(
                "直连 CONNECT 隧道关闭: {} 字节 客户端->目标, {} 字节 目标->客户端",
                stats.client_to_remote, stats.remote_to_client
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
    sessions: Arc<YamuxSessionManager>,
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
    // 每个普通 HTTP proxy 请求都会创建一条独立的目标连接。
    // 显式关闭上游 keep-alive，避免 per-request 子流被误当成可复用连接。
    req.headers_mut()
        .insert(hyper::header::CONNECTION, HeaderValue::from_static("close"));

    if direct_checker.is_direct(&address) {
        // === 直连路径: 直接连接目标 ===
        let target = address_to_string(&address);
        debug!("HTTP 请求使用直连连接到 {}", target);

        let target_stream = match TcpStream::connect(&target).await {
            Ok(s) => {
                if let Err(err) = s.set_nodelay(true) {
                    debug!("HTTP 普通请求直连目标 TCP_NODELAY 设置失败，继续使用默认行为：{err}");
                }
                s
            }
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

        let (sender_guard_tx, sender_guard_rx) = tokio::sync::oneshot::channel();

        // hyper connection future 驱动读写状态机，必须放到后台持续运行。
        // sender 需要至少活到 response body 被驱动完成；否则慢速响应在远端链路上
        // 可能被提前收尾，表现成 Content-Length 和实际 body 不一致。
        tokio::spawn(async move {
            tokio::pin!(conn);
            let mut sender_guard = None;
            tokio::select! {
                guard = sender_guard_rx => {
                    sender_guard = guard.ok();
                    if let Err(err) = (&mut conn).await {
                        error!("直连连接失败: {:?}", err);
                    }
                }
                result = &mut conn => {
                    if let Err(err) = result {
                        error!("直连连接失败: {:?}", err);
                    }
                }
            }
            drop(sender_guard);
        });

        let response = sender.send_request(req).await?;
        let _ = sender_guard_tx.send(sender);
        let (parts, body) = response.into_parts();
        let body = boxed(body);

        Ok(Response::from_parts(parts, body))
    } else {
        // === 代理路径: 通过代理隧道连接 ===
        // 普通 HTTP 代理同样不能在 agent 端解析域名。这里把 Domain 目标透传给
        // proxy，使 DNS、CDN 节点选择和远端策略都发生在真正出口侧。
        let connected_stream = match sessions
            .as_ref()
            .connect_to_target(address, TransportProtocol::Tcp)
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                error!("通过 proxy session manager 获取目标流失败: {}", e);
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

        let (sender_guard_tx, sender_guard_rx) = tokio::sync::oneshot::channel();

        // 代理路径也需要后台驱动 hyper client connection。
        // 和直连路径一样保留 sender，直到 response body 对应的连接自然结束。
        tokio::spawn(async move {
            tokio::pin!(conn);
            let mut sender_guard = None;
            tokio::select! {
                guard = sender_guard_rx => {
                    sender_guard = guard.ok();
                    if let Err(err) = (&mut conn).await {
                        error!("连接失败: {:?}", err);
                    }
                }
                result = &mut conn => {
                    if let Err(err) = result {
                        error!("连接失败: {:?}", err);
                    }
                }
            }
            drop(sender_guard);
        });

        // 发送请求
        let response = sender.send_request(req).await?;
        let _ = sender_guard_tx.send(sender);

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
