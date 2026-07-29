use anyhow::Result;
use bytes::Bytes;
use common::{DEFAULT_TCP_LISTEN_BACKLOG, bind_tcp_listener_with_backlog};
use futures::stream;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{error, info, trace};

const DEFAULT_LARGE_RESPONSE_SIZE_BYTES: u64 = 1024 * 1024;
const MAX_LARGE_RESPONSE_SIZE_BYTES: u64 = 256 * 1024 * 1024;

mod responses;
mod servers;

pub(crate) use responses::large_file_byte_at;
use responses::*;
pub use servers::{MockH2Server, MockHttpServer, MockTcpServer, MockUdpServer, run_mock_servers};

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
