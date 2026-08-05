//! 桌面端 TCP 隧道中继的统一实现。
//!
//! TUN、HTTP CONNECT、SOCKS CONNECT/BIND 最终都是“本地客户端流 <-> 远端流”的
//! 双向字节中继。这里刻意只保留 Tokio `copy_bidirectional` 这一套
//! 字节流搬运逻辑，避免 TUN、HTTP、SOCKS 在半关闭/flush 行为上出现分叉。
//!
//! `TcpRelayOptions` 仍保留不同入口的构造函数，方便日志和调用点表达语义；真正
//! 的 relay 不再根据入口切换实现。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use common::TCP_RELAY_COPY_BUFFER_SIZE;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

/// 一次双向 TCP relay 的字节统计。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRelayStats {
    pub client_to_remote: u64,
    pub remote_to_client: u64,
}

struct RelayCopyIo<'a, S> {
    inner: &'a mut S,
    label: &'a str,
}

impl<'a, S> RelayCopyIo<'a, S> {
    fn new(inner: &'a mut S, label: &'a str) -> Self {
        Self { inner, label }
    }
}

impl<S> AsyncRead for RelayCopyIo<'_, S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for RelayCopyIo<'_, S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) if can_ignore_tcp_shutdown_error(&error) => {
                // 统一使用 copy_bidirectional 后，shutdown 错误必须保持“半关闭尾部
                // 容错”语义：BrokenPipe/Reset/NotConnected 通常只是对端已经先关了
                // 写半边，不应该让另一个方向尚未排空的响应被取消。
                debug!("TCP relay 忽略 {} shutdown 错误：{}", this.label, error);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// 中继结束策略。
#[derive(Debug, Clone, Copy)]
pub struct TcpRelayOptions<'a> {
    /// 日志标签，用于定位具体目标。
    pub label: &'a str,
}

impl<'a> TcpRelayOptions<'a> {
    pub fn standard(label: &'a str) -> Self {
        Self { label }
    }

    pub fn tun(label: &'a str) -> Self {
        Self { label }
    }
}

/// 统一 TCP 隧道 relay。
///
/// `client` 表示本地应用/浏览器侧；`remote` 表示直连目标或 proxy stream。
/// 返回值顺序固定为 client->remote、remote->client，方便各入口记录 telemetry。
pub async fn relay_tcp_bidirectional<C, R>(
    client: &mut C,
    remote: &mut R,
    options: TcpRelayOptions<'_>,
) -> io::Result<TcpRelayStats>
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    // 所有 TCP 入口都走同一个 copy_bidirectional。不要在这里按
    // TUN/HTTP/SOCKS/framed proxy 分叉，否则后续排查卡顿时会再次出现“某个入口
    // 修好了、另一个入口还保留旧半关闭语义”的问题。
    let mut client_io = RelayCopyIo::new(client, options.label);
    let mut remote_io = RelayCopyIo::new(remote, options.label);
    let (client_to_remote, remote_to_client) = tokio::io::copy_bidirectional_with_sizes(
        &mut client_io,
        &mut remote_io,
        TCP_RELAY_COPY_BUFFER_SIZE,
        TCP_RELAY_COPY_BUFFER_SIZE,
    )
    .await?;

    Ok(TcpRelayStats {
        client_to_remote,
        remote_to_client,
    })
}

fn can_ignore_tcp_shutdown_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}
