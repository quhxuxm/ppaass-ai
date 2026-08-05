//! legacy TCP/UDP 数据中继。
//!
//! agent 与 proxy 之间传的是 `DataPacket`，目标服务器侧通常是裸 TCP/UDP。
//! 本模块的核心工作就是把 packet-based 的 agent 连接适配成 `AsyncRead/AsyncWrite`，
//! 再与目标 socket 做双向搬运。

use super::*;
use crate::config::{PERMISSION_PROXY_CONNECT_TCP, PERMISSION_PROXY_CONNECT_UDP};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::sync::watch;

mod copy_io;
mod server;
mod tcp;

pub use copy_io::RelayCopyIo;
pub use tcp::{TcpRelayTimeouts, can_ignore_tcp_shutdown_error, relay_tcp_with_half_close};
