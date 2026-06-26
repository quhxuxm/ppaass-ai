use anyhow::Result;
use bytes::Bytes;
use common::{DEFAULT_TCP_LISTEN_BACKLOG, bind_tcp_listener_with_backlog};
use futures::stream;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{error, info, trace};

const DEFAULT_LARGE_RESPONSE_SIZE_BYTES: u64 = 1024 * 1024;
const MAX_LARGE_RESPONSE_SIZE_BYTES: u64 = 256 * 1024 * 1024;

/// 响应多个测试端点的模拟 HTTP 目标服务器
pub struct MockHttpServer {
    port: u16,
}

impl MockHttpServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let listener = bind_tcp_listener_with_backlog(addr, DEFAULT_TCP_LISTEN_BACKLOG)?;
        info!("模拟 HTTP 服务器正在监听 {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, service_fn(handle_http_request))
                            .await
                        {
                            error!("服务连接时出错：{}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("接受连接失败：{}", e);
                }
            }
        }
    }
}

/// 模拟 TCP 回显服务器，会回显收到的所有数据
pub struct MockTcpServer {
    port: u16,
}

impl MockTcpServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let listener = bind_tcp_listener_with_backlog(addr, DEFAULT_TCP_LISTEN_BACKLOG)?;
        info!("模拟 TCP 回显服务器正在监听 {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("来自 {} 的 TCP 回显连接", addr);
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_echo(stream).await {
                            error!("TCP 回显错误：{}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("接受 TCP 连接失败：{}", e);
                }
            }
        }
    }
}

/// 模拟 UDP 回显服务器
pub struct MockUdpServer {
    port: u16,
}

impl MockUdpServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let socket = UdpSocket::bind(addr).await?;
        let socket = Arc::new(socket);
        info!("模拟 UDP 回显服务器正在监听 {}", addr);

        let mut buf = [0u8; 8192];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, client_addr)) => {
                    let socket_clone = socket.clone();
                    let data = buf[..n].to_vec();
                    trace!(
                        "收到来自 {} 的 UDP 数据：\n{}",
                        client_addr,
                        pretty_hex::pretty_hex(&data)
                    );
                    tokio::spawn(async move {
                        if let Err(e) = socket_clone.send_to(&data, client_addr).await {
                            error!("向 {} 发送 UDP 回显失败：{}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("接收 UDP 失败：{}", e);
                }
            }
        }
    }
}

async fn handle_http_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let path = req.uri().path();
    info!("HTTP 请求：{} {}", req.method(), path);

    let response = match path {
        "/health" => Response::builder()
            .status(StatusCode::OK)
            .body(full_body("OK"))?,
        "/echo" => {
            // 回显请求体
            let body = req.collect().await?.to_bytes();
            Response::builder()
                .status(StatusCode::OK)
                .body(BoxBody::new(Full::new(body).map_err(|e| match e {})))?
        }
        "/large" => {
            // 返回用于吞吐测试的大响应，并支持 Range 分片下载。
            handle_large_response(&req)?
        }
        "/fluctuating-large" => {
            // 按小块和短暂停顿流式返回，用于模拟目标网络波动。
            handle_fluctuating_large_response(&req)?
        }
        "/json" => {
            let json_data = r#"{"status":"success","message":"Mock target response"}"#;
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(full_body(json_data))?
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body("Not Found"))?,
    };

    Ok(response)
}

fn handle_large_response(
    req: &Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let size = large_response_size(req.uri().query());
    let range = match parse_range_header(
        req.headers()
            .get(RANGE)
            .and_then(|value| value.to_str().ok()),
        size,
    ) {
        Ok(range) => range,
        Err(()) => {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_RANGE, format!("bytes */{size}"))
                .body(full_body("Range Not Satisfiable"))?);
        }
    };

    if let Some((start, end)) = range {
        let body = large_file_body(start, end - start + 1);
        return Ok(Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(ACCEPT_RANGES, "bytes")
            .header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"))
            .header(CONTENT_LENGTH, body.len().to_string())
            .body(full_body(body))?);
    }

    let body = large_file_body(0, size);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(full_body(body))?)
}

fn handle_fluctuating_large_response(
    req: &Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let size = large_response_size(req.uri().query());
    let range = match parse_range_header(
        req.headers()
            .get(RANGE)
            .and_then(|value| value.to_str().ok()),
        size,
    ) {
        Ok(range) => range,
        Err(()) => {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_RANGE, format!("bytes */{size}"))
                .body(full_body("Range Not Satisfiable"))?);
        }
    };

    let (status, start, end) = if let Some((start, end)) = range {
        (StatusCode::PARTIAL_CONTENT, start, end)
    } else {
        (StatusCode::OK, 0, size - 1)
    };
    let body_len = end - start + 1;
    let mut builder = Response::builder()
        .status(status)
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, body_len.to_string());
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }

    Ok(builder.body(fluctuating_large_body(start, body_len))?)
}

fn large_response_size(query: Option<&str>) -> u64 {
    query
        .and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == "size").then_some(value)
            })
        })
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LARGE_RESPONSE_SIZE_BYTES)
        .clamp(1, MAX_LARGE_RESPONSE_SIZE_BYTES)
}

fn parse_range_header(
    range: Option<&str>,
    size: u64,
) -> std::result::Result<Option<(u64, u64)>, ()> {
    let Some(range) = range else {
        return Ok(None);
    };
    let range = range.trim().strip_prefix("bytes=").ok_or(())?;
    if range.contains(',') {
        return Err(());
    }
    let (start, end) = range.split_once('-').ok_or(())?;

    if start.is_empty() {
        let suffix_len = end.parse::<u64>().map_err(|_| ())?;
        if suffix_len == 0 {
            return Err(());
        }
        let start = size.saturating_sub(suffix_len);
        return Ok(Some((start, size - 1)));
    }

    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= size {
        return Err(());
    }

    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if end < start {
        return Err(());
    }

    Ok(Some((start, end)))
}

fn large_file_body(start: u64, len: u64) -> Vec<u8> {
    (0..len)
        .map(|offset| large_file_byte_at(start + offset))
        .collect()
}

fn fluctuating_large_body(start: u64, len: u64) -> BoxBody<Bytes, hyper::Error> {
    const PATTERN: [usize; 8] = [1, 7, 257, 1024, 4093, 8192, 17, 2048];
    const PAUSES_MS: [u64; 6] = [0, 2, 8, 1, 15, 3];

    let body_stream = stream::unfold(
        (0_u64, 0_usize, false),
        move |(written, pattern_idx, inserted_lull)| async move {
            if written >= len {
                return None;
            }

            let mut inserted_lull = inserted_lull;
            if !inserted_lull && written >= len / 2 {
                tokio::time::sleep(Duration::from_millis(180)).await;
                inserted_lull = true;
            }

            let chunk_len = PATTERN[pattern_idx % PATTERN.len()].min((len - written) as usize);
            let chunk = large_file_body(start + written, chunk_len as u64);
            let next_pattern_idx = pattern_idx + 1;
            let pause = PAUSES_MS[next_pattern_idx % PAUSES_MS.len()];
            if pause > 0 {
                tokio::time::sleep(Duration::from_millis(pause)).await;
            }

            Some((
                Ok::<_, Infallible>(Frame::data(Bytes::from(chunk))),
                (written + chunk_len as u64, next_pattern_idx, inserted_lull),
            ))
        },
    );

    BoxBody::new(StreamBody::new(body_stream).map_err(|err| match err {}))
}

pub(crate) fn large_file_byte_at(offset: u64) -> u8 {
    b'A' + (offset % 26) as u8
}

fn full_body<T: Into<Bytes>>(body: T) -> BoxBody<Bytes, hyper::Error> {
    BoxBody::new(Full::new(body.into()).map_err(|e| match e {}))
}

async fn handle_tcp_echo(mut stream: TcpStream) -> Result<()> {
    let mut buffer = vec![0u8; 8192];

    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            // 连接已关闭
            break;
        }

        // 回显数据
        stream.write_all(&buffer[..n]).await?;
        stream.flush().await?;
    }

    Ok(())
}

/// 运行模拟服务器
pub async fn run_mock_servers(http_port: u16, tcp_port: u16, udp_port: u16) -> Result<()> {
    let http_server = MockHttpServer::new(http_port);
    let tcp_server = MockTcpServer::new(tcp_port);
    let udp_server = MockUdpServer::new(udp_port);

    tokio::select! {
        res = http_server.run() => {
            error!("HTTP 服务器已停止：{:?}", res);
            res
        }
        res = tcp_server.run() => {
            error!("TCP 服务器已停止：{:?}", res);
            res
        }
        res = udp_server.run() => {
            error!("UDP 服务器已停止：{:?}", res);
            res
        }
        _ = tokio::signal::ctrl_c() => {
            info!("收到关闭信号");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_http_server() {
        // 这是一个基础测试，用于确保服务器可以实例化
        let server = MockHttpServer::new(19090);
        assert_eq!(server.port, 19090);
    }

    #[tokio::test]
    async fn test_mock_tcp_server() {
        let server = MockTcpServer::new(19091);
        assert_eq!(server.port, 19091);
    }

    #[tokio::test]
    async fn test_mock_udp_server() {
        let server = MockUdpServer::new(19092);
        assert_eq!(server.port, 19092);
    }

    #[test]
    fn test_range_header_parsing() {
        assert_eq!(
            parse_range_header(Some("bytes=10-19"), 100).unwrap(),
            Some((10, 19))
        );
        assert_eq!(
            parse_range_header(Some("bytes=90-200"), 100).unwrap(),
            Some((90, 99))
        );
        assert_eq!(
            parse_range_header(Some("bytes=-10"), 100).unwrap(),
            Some((90, 99))
        );
        assert!(parse_range_header(Some("bytes=100-101"), 100).is_err());
    }
}
