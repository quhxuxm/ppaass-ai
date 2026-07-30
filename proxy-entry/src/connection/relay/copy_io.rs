use super::*;

pub(super) struct RelayCopyIo<'a, S> {
    inner: &'a mut S,
    label: &'static str,
    activity_tx: watch::Sender<()>,
    read_bytes: Arc<AtomicU64>,
    read_eof: Arc<std::sync::atomic::AtomicBool>,
}

impl<'a, S> RelayCopyIo<'a, S> {
    pub(super) fn new(
        inner: &'a mut S,
        label: &'static str,
        activity_tx: watch::Sender<()>,
        read_bytes: Arc<AtomicU64>,
        read_eof: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            inner,
            label,
            activity_tx,
            read_bytes,
            read_eof,
        }
    }

    fn mark_activity(&self) {
        // watch 只用作轻量“有活动”信号，不承载数据；发送失败说明 watchdog 已经退出。
        let _ = self.activity_tx.send(());
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
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut *this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len().saturating_sub(filled_before);
            if read > 0 {
                this.read_bytes.fetch_add(read as u64, Ordering::AcqRel);
                this.mark_activity();
            } else {
                this.read_eof
                    .store(true, std::sync::atomic::Ordering::Release);
                this.mark_activity();
            }
        }
        result
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
        let result = Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result
            && *written > 0
        {
            this.mark_activity();
        }
        result
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
                // copy_bidirectional 的半关闭语义是正确的，但真实网络里 shutdown
                // 可能遇到对端已关闭写半边的 BrokenPipe/Reset。这里把这类错误视为
                // “半关闭已经没有必要继续”，避免请求方向的小错误取消响应方向排空。
                debug!(
                    "TCP relay 忽略 {label} shutdown 错误：{error}",
                    label = this.label
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}
