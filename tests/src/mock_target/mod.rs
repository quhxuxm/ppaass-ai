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
pub use responses::parse_range_header;
use responses::{handle_http_request, handle_tcp_echo};
pub use servers::{MockH2Server, MockHttpServer, MockTcpServer, MockUdpServer, run_mock_servers};
