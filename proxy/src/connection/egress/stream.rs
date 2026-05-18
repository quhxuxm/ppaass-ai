use super::route_guard::TargetRouteGuard;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub struct EgressTcpStream {
    stream: TcpStream,
    // 持有 route guard 到 TCP 流结束，Drop 时自动释放临时旁路路由。
    _route_guard: Option<TargetRouteGuard>,
}

impl EgressTcpStream {
    pub(super) fn new(stream: TcpStream, route_guard: Option<TargetRouteGuard>) -> Self {
        Self {
            stream,
            _route_guard: route_guard,
        }
    }
}

impl AsyncRead for EgressTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 读写能力全部委托给底层 TcpStream，包装层只负责路由生命周期。
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for EgressTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 写入目标 TCP 流。
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 保持 AsyncWrite 语义完整。
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // TCP 中继结束时关闭目标写半边。
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
