use super::*;
use crate::direct_access::address_to_string;
use hyper::header::HeaderValue;
use std::str::FromStr;

pub(super) async fn handle_regular_request(
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

        let target_stream = match common::connect_tcp_happy_eyeballs(&target, |_, _| Ok(())).await {
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
