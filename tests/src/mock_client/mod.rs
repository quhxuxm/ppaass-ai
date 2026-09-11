use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{HeaderMap, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

mod http;
mod socks5;
mod tcp;

pub use http::MockHttpClient;
pub(crate) use http::read_connect_response;
pub use socks5::MockSocks5Client;
pub use tcp::{MockTcpClient, connect_to_agent_with_retry};
